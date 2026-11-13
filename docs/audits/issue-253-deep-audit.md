# Deep audit: Issue #253 — bind add-factor existing-factor authorization to new-factor material

**Status:** Analysis only — no implementation  
**Audited against:** `uaf/7-ensure-lookup-post-insert-reconcile` (PR #237 head, SHA `0f955ed`) and cross-checked with `origin/main`, PR #254 / Paolo review, and issue #253 body  
**Related stack:** PRs #232–#237, #250–#254  
**Date:** 2026-09-15

---

## Executive summary

**Verdict: approve-with-changes**

The threat is real on the UAF stack whenever the new factor is a passkey registration: `registration_state_hash` / `ChallengeContext::AddFactor { new_factor_type }` binds **pre-authenticator ceremony state** (or the raw OIDC JWT for OIDC-new), not the credential that `finish_passkey_registration` actually accepts. An orchestrated client / same-origin relay that splits “victim signs existing factor” from “attacker completes `create()`” can add an attacker passkey while the existing-factor proof still verifies.

The proposed fix — existing factor covers `existing_factor_challenge || SHA256(new_factor_material)` inside today’s single `POST /v1/add-factor`, with new-factor validation moved earlier so the digest is known — is the right shape. It matches Paolo’s #254 review intent, avoids a multi-endpoint pending-registration redesign, and fits both Turnkey (`metadata.challenge`) and OIDC session-keypair signing.

Do **not** implement the proposal verbatim. Before coding, fix or explicitly decide:

1. **Threat-model wording** — pure network MITM is overstated; WebAuthn RP/origin binding already stops classic TLS MITM from completing `create()` for the real RP. The realistic adversary is ceremony-splitting malware, a malicious/compromised app build, XSS/same-origin relay, or a phishing client that obtains the minted pair.
2. **Rollout bridge** — shape auto-detect that still accepts legacy 32-byte `metadata.challenge` **keeps the attack open** for anyone who sends the old shape. Bridge without a hard sunset is not a security control.
3. **Token / nonce burn semantics** — “defer both `use_challenge_token` calls” is incomplete: OIDC nonce consumption inside `OidcTokenVerifier::verify_token` can still burn on paths that later fail binding; new-factor ceremony tokens and existing-factor approval tokens have different griefing profiles and should not share one blanket deferral rule.
4. **Encoding contract** — `credential_id || SEC1-pubkey` needs a locked client/server byte contract (raw cred id, uncompressed `0x04||x||y`, hash domain separation). Without it, “binding mismatch” will be indistinguishable from client bugs during rollout.
5. **Asymmetry risk** — passkey-existing verification is **inline** in `add_factor.rs`; OIDC-existing goes through `AuthHandler::verify`. Binding that lands in only one arm re-opens the gap on the other.

**Severity of leaving #253 unfixed when Passkey-new ships:** High (P1) for backup recovery control-plane integrity under compromised/orchestrating clients.  
**Severity on current `main` alone:** lower — production `main` only mints OIDC-new (JWT already bound into context); authenticator-swap becomes live when the UAF passkey-registration path merges.

---

## Code inspected (grounding)

| Area | Location |
|---|---|
| Challenge mint + `registration_state_hash` | `src/routes/add_factor_challenge.rs` (`handler`, `registration_state_hash`) |
| Add-factor handler (existing + new + burns + persist) | `src/routes/add_factor.rs` (`handler`, Steps 1 / 2 / 2A / 3) |
| OIDC / registration auth | `src/auth.rs` (`AuthHandler::verify`, `validate_factor_registration`, `validate_oidc_authentication`, `validate_passkey_registration`) |
| Turnkey stamp + SEC1 encoding | `src/turnkey_activity.rs` (`verify_turnkey_activity_webauthn_stamp`) |
| Challenge context types | `src/challenge_manager.rs` (`ChallengeContext::AddFactor`, `NewFactorType`) |
| Raw ECDSA verify | `src/verify_signature.rs` (`verify_signature`) |
| Single-use token burn | `src/redis_cache.rs` (`use_challenge_token`) |
| Error codes | `types/src/error.rs` (`PasskeyRegistrationMismatch`, `OidcTokenMismatch`, `InvalidChallenge`) |
| Ceremony-swap test (false confidence) | `tests/add_factor_challenge_binding.rs` (`test_add_factor_rejects_swapped_passkey_registration_token`) |
| Happy paths (no passkey↔passkey) | `tests/add_factor_happy_paths.rs` |
| Turnkey test helper | `tests/common/mod.rs` (`create_turnkey_activity_and_hash`, `sign_keypair_challenge`) |
| Production contrast | `origin/main` `add_factor_challenge.rs` — OIDC-new only |

---

## 1. Threat model — validate / refute

### Claimed attack

Issue #253 diagrams a relay/MITM that:

1. Obtains the minted challenge pair from `POST /v1/add-factor/challenge`
2. Completes `navigator.credentials.create()` on an attacker device with the new-factor WebAuthn options
3. Has the victim sign only the existing-factor side (raw challenge / Turnkey activity)
4. Submits attacker credential + victim existing-factor proof to `POST /v1/add-factor`

### What the code actually binds today (#237)

**Mint** (`add_factor_challenge.rs`):

- Passkey-new: serializes `PasskeyRegistration` into the new-factor JWE payload; hex-SHA256 of those bytes becomes `NewFactorType::PasskeyRegistration { registration_hash }`, embedded in the existing-factor token’s `ChallengeContext::AddFactor`.
- OIDC-new: embeds the **raw JWT string** in `NewFactorType::OidcAccount { oidc_token }` before the existing factor signs anything.

**Complete** (`add_factor.rs`):

- Passkey-existing: after stamp + activity checks, compares  
  `STANDARD.encode(trusted_challenge) == turnkey_activity.metadata.challenge`  
  (`handler` ~lines 165–171). No bytes from `new_factor_authorization` enter that comparison.
- OIDC-existing: `AuthHandler::verify` → `validate_oidc_authentication` → `verify_signature(public_key, signature, challenge_token_payload)` over the **raw 32-byte challenge only** (`auth.rs` ~520).
- Passkey-new cross-check: recomputes `registration_state_hash` on the new-factor token payload and compares to context (`add_factor.rs` ~250–280) — still ceremony state, not resulting cred.
- Then `validate_factor_registration` → `finish_passkey_registration` (`auth.rs` ~315–350).

### Verdict on the attack

| Adversary | Mitigated by current binding? | Notes |
|---|---|---|
| Swap a **different** registration ceremony token after existing factor signed | **Yes** | Covered by `registration_hash` / `PasskeyRegistrationMismatch`; tested in `test_add_factor_rejects_swapped_passkey_registration_token` |
| Same ceremony, **different authenticator** / attacker `create()` result | **No** | Hash is identical for any authenticator that finishes that state |
| Passkey-existing → **OIDC-new** identity swap after mint | **Yes (already)** | JWT is in encrypted context at mint; Step 2 enforces `OidcTokenMismatch` |
| Pure passive TLS MITM with no malicious client | **Mostly N/A / overstated** | WebAuthn `create()` is origin/RP-bound; a network MITM cannot normally drive `credentials.create()` for the real RP on a clean victim browser |
| Ceremony-splitting malicious app / compromised client / XSS relay | **No — gap is real** | This is the adversary the fix actually addresses |
| Fully compromised honest-looking client that lies about local digest | **Out of scope (agreed)** | Needs app integrity / attestation; protocol binding cannot save a client that asks the user to sign attacker material |

**Refinement for the issue text:** replace “relay/MITM” as the primary story with **ceremony-splitting client**. Keep network relay only insofar as it *is* the client (malicious app, injected JS, desktop orchestrator).

`registration_state_hash` is still worth keeping as defense-in-depth against **token swap**; it does **not** substitute for material binding.

---

## 2. Proposed binding — `challenge || SHA256(material)`

### Mechanics (sound)

Reconstruct digest on the server from **post-validation** material inside one `AddFactorRequest`:

- Passkey: `SHA256(credential_id_bytes || sec1_uncompressed_pubkey)`
- OIDC: `SHA256(raw_jwt_utf8_bytes)`
- Existing signs / embeds: `trusted_challenge_32 || material_digest_32` → 64 bytes

Hash-then-concat is preferable to raw `challenge || pubkey || …` because:

- Turnkey `metadata.challenge` stays a short, fixed decoded length (enables shape detection)
- Variable-length cred ids do not change the signed envelope size
- OIDC JWTs are large; hashing avoids stuffing multi-KB into Turnkey metadata

SEC1 reuse from `verify_turnkey_activity_webauthn_stamp` (`turnkey_activity.rs` ~89–99: `0x04 || x || y`) is the right canonical pubkey encoding **if and only if** clients implement the identical COSE→SEC1 path on the **verified** registration result (or an equivalently specified extraction from the attestation). Server must compute the digest from `finish_passkey_registration`’s `Passkey` (`cred_id` + `get_public_key()`), never from untrusted client-supplied parallel fields.

### Edge cases / gaps in the proposal

| Topic | Risk | Recommendation |
|---|---|---|
| Cred id length | Concatenation before hash is fine if pubkey is always exactly 65 bytes **last**; still document “raw cred id bytes then SEC1” explicitly | Publish a one-page byte contract; optional length-prefix (`u16be cred_len ‖ cred ‖ sec1`) for clarity / future key types |
| Domain separation | `SHA256(jwt)` and `SHA256(cred‖pk)` live in the same 32-byte slot; context usually prevents cross-type confusion, but uniform binding without a tag is weaker than it looks | Prefer `SHA256(domain ‖ material)` with `domain ∈ { "uaf-pk-v1", "uaf-oidc-v1" }` (or include `NewFactorType` discriminant) |
| OIDC JWT bytes | Must be exact wire string used in `Authorization` / context equality; Apple `aud` wrappers must not be hashed in a different form than submitted | Hash the same `&str` used for `OidcTokenMismatch` / `verify_token` |
| Fixed 64-byte Turnkey claim | **Not a hard Turnkey API constraint** found in-repo; it is a **design convenience** for shape detection and bounded metadata | Document as “our convention,” not “Turnkey requires 64” |
| Old 32 vs new 64 ambiguity | Length-based branching is unambiguous **if** you decode STANDARD base64 and switch on byte length; string-compare of base64 (today’s `STANDARD.encode(trusted) != backup_service_challenge`) must become decode-then-compare | Change comparison to decoded bytes; reject lengths other than 32 or 64 (during bridge) / only 64 (after sunset) |
| Client footgun | Today helpers copy API `existingFactorChallenge` **string** into Turnkey metadata (`create_turnkey_activity_and_hash`). New form requires decode → concat digest → re-encode — **not** string concatenation of base64 | Call this out in client contract; update `test-utils` / `tests/common` in the same PR as server |
| `verify_signature` empty check | `verify_signature` rejects empty payload; 64-byte payload is fine (`verify_signature.rs` ~25–27) | No change needed |
| Uniform binding for OIDC-new | Cryptographically redundant with context JWT bind; still OK for one code path | When retrofitting Passkey-existing, Passkey→OIDC clients must also change what they put in `metadata.challenge` — product impact beyond Passkey-new |

### Collision / shape notes

- Decoded **32 vs 64** cannot collide by length.
- Accepting **both** during bridge means the security property is the **minimum** of the two accepted forms (see §5).
- Hex `registration_hash` (ceremony) vs raw 32-byte `material_digest` are different layers; do not conflate them in APIs or metrics.

---

## 3. Handler reorder (`add_factor.rs`) — races, burns, griefing

### Today’s order (problem)

1. Existing-factor auth (**burns** existing token at 1A.6 or inside `AuthHandler::verify` Step 5)
2. Context bind (`registration_hash` / OIDC token equality)
3. `validate_factor_registration` (**burns** new token; may consume OIDC nonce)
4. Lookup + metadata persist

So an invalid new-factor submission spends a valid existing-factor approval — real UX griefing / DoS-against-self under the confused-deputy model. Confirmed in code paths above.

### Proposed order (mostly right)

1. Decrypt / extract both tokens (and keep context bind)
2. Validate new factor **before** existing-factor material bind check
3. Verify existing factor against `challenge ‖ digest`
4. Commit burns
5. Persist (unchanged; #237 lookup/heal logic stays)

Validating registration before existing-factor **identity** proof is OK: `finish_passkey_registration` does not need `backup_id`. You still must not persist until existing-factor auth succeeds.

### Findings on burns / races

**H1 — Do not blindly “defer both burns.”**  
Prefer:

- **New-factor challenge token:** burn immediately after successful registration validation (ceremony should be single-use; reduces double-finish races).
- **Existing-factor challenge token:** defer burn until material binding + existing-factor crypto checks pass (fixes the griefing issue the proposal cares about).
- **OIDC nonces:** today `validate_oidc_authentication` / registration call `verify_token(..., consume=true)` **before** `verify_signature` (`auth.rs` ~515–520). A binding mismatch after nonce consume forces a full re-login. For the binding change, **verify the signature over `challenge‖digest` before consuming the nonce** (or make nonce consume explicit and ordered after binding success). Same-session reuse logic (`reuse_same_oidc_session` in `add_factor.rs` ~303–334) must be preserved carefully under reorder.

**H2 — `AuthHandler` API must split “authenticate” from “consume.”**  
`verify` and `validate_factor_registration` always `use_challenge_token` at the end. Reorder + deferred existing burn needs a flag or split methods; otherwise OIDC-existing cannot participate without burning early. This is a real refactor cost the issue understates.

**H3 — Concurrent double-submit of the same pair.**  
Two in-flight `POST /add-factor` with the same tokens can both pass extract + `finish_passkey_registration` before either NX-burn. Redis `use_challenge_token` (`NX`) serializes the burn; one wins, one gets `AlreadyUsed`. Persist races are already handled by #234–#237 lookup/heal — orthogonal but means binding work must not weaken burn-before-persist: **burns (at least existing + new tokens) must succeed before lookup insert**.

**H4 — Partial failure / orphaned device passkeys.**  
If the user completes `create()` locally, then existing-factor binding fails, the device may still hold a passkey never written to backup. Paolo’s “prompt passkey last” client sequencing reduces this; server reorder does not create it, but deferred existing burn makes retries easier (good). Document client UX: only create once binding inputs are ready; surface `ExistingFactorMaterialBindingMismatch` distinctly.

**H5 — Griefing after deferral without binding (legacy bridge).**  
If legacy 32-byte form is still accepted, an attacker holding a victim existing-factor signature over the bare challenge can retry many new-factor materials without a new victim signature. Material binding removes that; the bridge reintroduces it for legacy shape.

---

## 4. Architectural coupling

### Current smells (confirmed)

- `add_factor.rs` calls `super::add_factor_challenge::registration_state_hash` — route-to-route coupling (`add_factor.rs` ~274).
- Passkey-existing auth is a long inline branch; OIDC-existing uses `AuthHandler::verify` — two sources of truth for “existing main factor proved ownership.”
- `NewFactorType::PasskeyRegistration { registration_hash }` naming still sounds like credential binding; it is ceremony-state binding (`challenge_manager.rs` ~252–259).

### On `factor_binding.rs`

A small module owning:

- `registration_state_hash` (move)
- `new_factor_material_digest(...)`
- maybe `existing_factor_signed_payload(challenge, digest) -> [u8; 64]`

is proportionate — not over-engineered — **if** both existing-factor arms call it. Putting helpers only next to the OIDC path would be the failure mode.

### Turnkey vs OIDC asymmetry

| Concern | Passkey-existing | OIDC-existing |
|---|---|---|
| Where binding is checked | `metadata.challenge` string vs decoded trusted bytes in `add_factor.rs` | `verify_signature` trusted payload in `validate_oidc_authentication` |
| Stamp / ID token | Stamp verifies over full activity JSON (so changing `metadata.challenge` is what the user “signed” via Turnkey) | Session key signs exact byte slice |
| Bridge | Length of decoded challenge field | Try-both verify (new payload, then old) if ever needed — **not needed** if OIDC-existing never ships unbound |

**Do not** force a shared trait in the first implementation PR (proposal is right). **Do** add a single shared helper and a checklist/test matrix so both arms stay in lockstep.

### Over-engineering to avoid

- New endpoints / pending-registration resources — unnecessary given `AddFactorRequest` already carries both authorizations.
- Unifying Turnkey stamp verification with OIDC into one abstraction in the same PR.
- Removing `registration_hash` in the first landing — keep as defense-in-depth (agreed).

---

## 5. Rollout bridges

| Option | Security | Ops | Recommendation |
|---|---|---|---|
| Hard cutover (min app version) | Strongest if enforced server-side | Needs version signal + release train sync | Prefer if app can gate |
| Shape auto-detect 32 vs 64 | **Attack remains for anyone sending 32** | Easy mixed fleet | Acceptable **only** with dated sunset + metrics on legacy share → 0 |
| Indefinite bridge | Gap never closes | Quiet failure | Reject |
| Try-both (OIDC) | Same caveat as shape bridge | Slightly more CPU | Irrelevant if OIDC-existing ships bound from day one |

**Critical:** the issue correctly states the caveat; treat it as a **High** product risk, not a footnote. Any PR that enables legacy 32-byte acceptance should include:

- metric `add_factor_existing_challenge_shape{shape=legacy|bound}`
- alert on legacy use after sunset
- server flag to force-reject legacy independently of code deploy

Also: today’s comparison is base64 **string** equality. Shape detection must **decode** with the same alphabet the client uses (`STANDARD` today). Reject unknown lengths loudly (`InvalidChallenge` or dedicated malformed-shape code).

---

## 6. Sequencing — ship OIDC-existing+binding now, retrofit Passkey-existing later?

### Code reality

- **`main`:** Passkey-existing → OIDC-new only; JWT bound at mint; **no** passkey-registration new-factor path → authenticator-swap not live in production yet.
- **`#237` stack:** OIDC-existing + Passkey-new already implemented **without** material binding. Merging this stack without #253 opens:
  - OIDC-existing → Passkey-new (Paolo’s explicit concern)
  - Passkey-existing → Passkey-new
  - Passkey-existing → OIDC-new remains identity-safe via JWT context, but would still need a payload change if Passkey-existing binding is applied uniformly later

### Tradeoffs

| Strategy | Pros | Cons |
|---|---|---|
| **A. Bind OIDC-existing now; defer Passkey-existing retrofit** | Unblocks “OIDC without prior passkey”; zero legacy OIDC clients | Knowingly ships Passkey-new (if merged) with Passkey-existing still unbound; contradicts Paolo’s “don’t leave this open” if Passkey-new is enabled |
| **B. Hold both until binding lands for both arms** | Consistent security story | Blocks OIDC-existing on Passkey client retrofit schedule |
| **C. Bind both arms in one server PR; feature-flag Passkey-new until clients ready** | Server complete; product controls exposure | Larger PR; Passkey clients still need a release for Passkey↔Passkey |

**Audit recommendation:** Prefer **C** technically: implement binding helpers for both arms on top of #237, enforce bound payload unconditionally for OIDC-existing, and either (i) hard-cut or short-bridge Passkey-existing, or (ii) **do not enable Passkey-new in production clients** until Passkey-existing bound shape is required. Strategy A is only acceptable if Passkey-new remains client-disabled while Passkey-existing stays legacy — a product gate, not a server illusion of safety.

---

## 7. Missing tests / false confidence

Current suite proves the **wrong** property for #253:

| Existing test | What it proves | What it does **not** prove |
|---|---|---|
| `test_add_factor_rejects_swapped_passkey_registration_token` | Ceremony **token** swap → `passkey_registration_mismatch` | Same ceremony, different authenticator / digest |
| `add_factor_happy_paths.rs` | OIDC↔passkey and OIDC↔OIDC | **No** passkey-existing → passkey-new happy path (issue is correct) |
| `add_factor_challenge_binding.rs` matrix | Replay, kind mismatch, swapped tokens | Material binding |
| Turnkey helpers | Embed bare `existingFactorChallenge` string | Bound 64-byte form |

### Required tests for an implementation PR

1. **Authenticator-swap / digest-mismatch (negative):** finish registration for cred A; existing factor signs digest(B); expect `ExistingFactorMaterialBindingMismatch` (new code), not `passkey_registration_mismatch`.
2. **Passkey ↔ passkey happy path** with bound payload.
3. **OIDC-existing → passkey-new** signs `challenge‖digest` (not bare challenge).
4. **Legacy shape:** if bridge enabled — accept 32-byte and assert metric; if sunset — reject 32-byte.
5. **Burn ordering:** invalid new factor must **not** consume existing-factor token; binding failure must not consume existing token; successful path consumes both; OIDC nonce not consumed on binding failure.
6. **Domain / encoding vectors:** fixed test vectors for SEC1 digest computation shared with client doc.
7. Update `create_turnkey_activity_and_hash` / `sign_keypair_challenge` for concat scheme — otherwise the suite can go green on an incomplete server check.

Until (1) exists, green CI is **false confidence** relative to #253.

---

## 8. Deep refactor suggestions (where the proposal is wrong, incomplete, or heavy)

### Verdict on proposal pieces

| Piece | Assessment |
|---|---|
| Late commitment in one `/add-factor` | **Keep** — best fit |
| `challenge ‖ SHA256(material)` | **Keep** with domain separation |
| Reorder new-factor validation earlier | **Keep** |
| Defer **both** token burns | **Change** — asymmetric burn policy (§3) |
| `factor_binding.rs` | **Keep** (small) |
| Keep `registration_hash` | **Keep** |
| Shape auto-detect bridge | **Conditional** — only with hard sunset |
| Sequencing A (OIDC now, Passkey later) | **Product call** — unsafe if Passkey-new is user-reachable |

### Alternative designs (tradeoffs)

**Alt 1 — Proposal + fixes (recommended)**  
Single request, shared digest helper, split consume APIs, domain-separated hash, burn policy per token kind, dual-arm binding, short legacy bridge or hard cut.

- Pros: minimal protocol change; matches Paolo + Codex direction  
- Cons: client signing change; AuthHandler API churn  

**Alt 2 — Pending registration JWE (multi-step)**  
`create` → server validates → encrypted pending token containing cred commitment → existing factor signs commitment → finalize.

- Pros: types make illegal states harder  
- Cons: more endpoints/TTL/abuse surface; unnecessary given Alt 1  

**Alt 3 — Bind full attestation Object hash**  
Stronger binding to the exact authenticator response.

- Pros: harder to substitute fields  
- Cons: `attestation: none` common; client/server canonicalization hell; worse UX debugging  

**Alt 4 — Only bind passkey-new; leave OIDC-new on context bind**  
Conditional digest.

- Pros: slightly less client work for OIDC-new  
- Cons: two code paths; proposal’s uniformity argument wins for maintainability  

### Suggested implementation sketch (not this PR)

1. Add `src/factor_binding.rs` (or `add_factor_binding.rs`) with domain-separated digests + payload builder.
2. Extend `AuthHandler::verify` / `validate_oidc_authentication` with `trusted_payload: &[u8]` (or `material_digest: Option<[u8;32]>`) and `consume_challenge: bool`; fix nonce order vs signature.
3. In passkey-existing branch: decode `metadata.challenge`, verify length policy, compare to `challenge ‖ digest` (and optionally legacy).
4. Reorder `handler` in `add_factor.rs`; keep context checks; persist unchanged.
5. New `ErrorCode::ExistingFactorMaterialBindingMismatch` + metrics.
6. Tests from §7; client contract doc linked from rustdoc on the helper.

---

## Findings ranked by severity

### Critical

_None that invalidate the core design._ The gap itself is **High** if Passkey-new is exposed without a fix; the proposal is directionally correct.

### High

1. **Authenticator-swap gap is real on UAF Passkey-new paths** — `registration_state_hash` does not close it (`add_factor_challenge.rs`, `add_factor.rs` Step 2, `auth.rs` `validate_passkey_registration`).
2. **Legacy 32-byte acceptance during bridge preserves the attack** for any client (or attacker) still using bare challenge in Turnkey metadata / OIDC signature.
3. **Dual-path existing-factor auth** — binding must land in both inline Turnkey branch and `AuthHandler::verify`, or one arm stays vulnerable.
4. **OIDC nonce / challenge consume ordering** — binding failures (and today’s signature failures) can burn OIDC nonce before the user-visible check finishes; deferral story must include nonce semantics.

### Medium

5. **Threat-model overclaim (network MITM)** — refine to ceremony-splitting / malicious client; avoids wrong mitigations.
6. **“Defer both burns” is too coarse** — prefer burn new-factor token after successful registration; defer existing-factor token only.
7. **Missing domain separation** in material digest.
8. **Encoding contract underspecified** (cred id bytes, SEC1, JWT string, base64 decode/re-encode for Turnkey) — rollout will look like intermittent `ExistingFactorMaterialBindingMismatch`.
9. **False confidence in current tests** — ceremony-swap tests pass while P1 remains open; no passkey↔passkey happy path.
10. **Sequencing option A** is only safe if Passkey-new is not client-reachable while Passkey-existing remains unbound.

### Low

11. Route-to-route `registration_state_hash` import — move with the new helper module.
12. `NewFactorType::PasskeyRegistration` naming implies credential bind — rename in a follow-up (`CeremonyStateHash` vs material digest).
13. Double JWE decrypt (extract then `verify` / validate) — wasteful, not a security break.
14. Serde-JSON hashing of registration state — pre-existing brittleness; less urgent once material bind is primary.

### Nit

15. Document that “fixed 64 bytes for Turnkey” is our convention, not an upstream hard limit discovered in this repo.
16. Compare decoded challenge bytes, not base64 strings, when implementing shape checks.
17. Dedicated error code + metrics — agree with proposal.

---

## Recommended design alternatives (summary)

1. **Ship Alt 1 (proposal + §3/§5/§8 fixes)** on top of #237.  
2. **Reject** indefinite shape bridges and multi-endpoint pending-registration unless product explicitly needs mid-flow server validation UX.  
3. **Gate Passkey-new** on either Passkey-existing binding enforcement or an explicit accepted risk by Paolo/product.

---

## Explicit questions for Paolo / product

1. **Sequencing:** Is it acceptable to merge OIDC-existing **with** material binding while Passkey-existing still accepts bare 32-byte challenges — **if and only if** Passkey-new remains disabled in production apps? Or must both arms enforce binding before any Passkey-new exposure?
2. **Passkey-existing rollout:** Hard min-app-version cutover vs shape bridge? If bridge, what is the **calendar sunset** and who owns killing legacy?
3. **Uniformity:** When Passkey-existing gains binding, must Passkey→OIDC (already identity-safe) also switch to `challenge‖SHA256(jwt)`, or may that path stay on 32-byte until a later cleanup?
4. **Threat acceptance:** Confirm residual risk of fully compromised clients is accepted without device-attestation requirements in this iteration.
5. **Client contract ownership:** Who publishes the byte-level signing doc (SEC1, cred id, domain tags) that app teams implement against — and should server expose a test-only digest helper / published test vectors?
6. **Error / UX:** Should binding failure prompt “create passkey again” or “re-approve existing factor,” given burn-policy choices above?
7. **Metrics / abort:** What legacy usage threshold forces killing the 32-byte branch even if some app versions remain in the wild?

---

## Appendix A — attack vs current checks (cheat sheet)

```
Mint:     existing_ctx embeds registration_state_hash(ceremony_json)   // NOT cred
Victim:   signs Turnkey(activity.metadata.challenge = b64(challenge_32))
Attacker: create() → cred_A on same ceremony
Server:   hash(ceremony) matches ✓
          finish_passkey_registration(cred_A) ✓
          metadata.challenge == b64(challenge_32) ✓   // never saw cred_A
Result:   attacker factor added
```

With #253 binding (intended):

```
Victim client: digest = H(cred_V ‖ pk_V); challenge_field = b64(chal ‖ digest)
Attacker swap: server finishes cred_A; expects chal ‖ H(cred_A ‖ pk_A)
Verify: mismatch → ExistingFactorMaterialBindingMismatch
```

## Appendix B — primary code references

- `registration_state_hash` — `src/routes/add_factor_challenge.rs`
- Existing passkey challenge compare — `src/routes/add_factor.rs` (`handler`, Step 1A.5–1A.6)
- OIDC existing verify + burn — `src/auth.rs` (`verify`, `validate_oidc_authentication`)
- New factor registration — `src/auth.rs` (`validate_factor_registration`, `validate_passkey_registration`)
- SEC1 encoding precedent — `src/turnkey_activity.rs` (`verify_turnkey_activity_webauthn_stamp`)
- Context types — `src/challenge_manager.rs` (`NewFactorType`, `ChallengeContext::AddFactor`)
- Ceremony-swap test — `tests/add_factor_challenge_binding.rs`

---

*End of audit. No production behavior changes accompany this document.*
