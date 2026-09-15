//! Verifies `types::PasskeyCreationChallenge` (the local mirror embedded in
//! `NewFactorChallenge`, kept local because `webauthn-rs-proto` doesn't derive `JsonSchema`)
//! stays wire-compatible with the real `webauthn-rs` `CreationChallengeResponse` produced by
//! `start_resident_passkey_registration`. If a future `webauthn-rs` upgrade adds, renames, or
//! retypes a field, this test breaks instead of the mirror silently serving a stale or lossy
//! shape to clients.

use backup_service::environment::Environment;
use backup_service::webauthn::start_resident_passkey_registration;
use types::PasskeyCreationChallenge;

#[test]
fn passkey_creation_challenge_mirrors_real_webauthn_response() {
    let environment = Environment::development(None);
    let (real_challenge, _registration) =
        start_resident_passkey_registration(&environment.webauthn_config(), "name", "display name")
            .expect("registration ceremony should start");

    let real_json = serde_json::to_value(&real_challenge).expect("serialize real response");

    let mirrored: PasskeyCreationChallenge = serde_json::from_value(real_json.clone())
        .unwrap_or_else(|err| {
            panic!(
                "types::PasskeyCreationChallenge no longer parses webauthn-rs's real \
                 CreationChallengeResponse shape (crate upgrade drift?): {err}"
            )
        });

    let mirrored_json = serde_json::to_value(&mirrored).expect("serialize mirrored response");
    assert_eq!(
        mirrored_json, real_json,
        "types::PasskeyCreationChallenge round-trips to a different JSON shape than the real \
         webauthn-rs response — the mirror has drifted (e.g. a field it doesn't model is now \
         populated, or a type differs)"
    );
}
