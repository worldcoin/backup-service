//! `POST /v1/add-factor` binds the existing factor's authorization to the new passkey's public
//! key as a 65-byte SEC1 P-256 point, so the binding is only defined for ES256 credentials. The
//! add-factor registration options therefore advertise ES256 only (webauthn-rs's default list is
//! `[ES256, RS256]`), but `webauthn-rs` verifies an RS256 registration without complaint — so the
//! server itself must still turn one away when a client submits it anyway, with
//! `unsupported_passkey_algorithm`, and without consuming either challenge.
//!
//! The mock authenticator only ever mints ES256 credentials, so the RS256 registration response
//! is assembled by hand here (`none` attestation). Feeding the same builder a P-256 key is the
//! control: it proves the hand-built response passes every `WebAuthn` check, so the rejection is
//! about the algorithm and nothing else.

mod common;

use crate::common::{
    add_factor_payload_for_passkey_new, create_test_backup_with_oidc_account, generate_keypair,
    get_add_factor_challenges_generic, get_test_redis_cache_manager, oidc_nonce_from_jwt,
    parse_response_body, send_post_request_with_environment, sign_keypair_challenge,
    verify_s3_metadata_exists, TestBackupWithOidcAccount,
};
use axum::http::StatusCode;
use backup_service::environment::Environment;
use backup_service_test_utils::{
    get_mock_passkey_client, make_credential_from_passkey_challenge, registered_passkey_material,
    MockOidcProvider, MockOidcServer,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::value::{Integer, Value as Cbor};
use josekit::jwk::Jwk;
use openidconnect::SubjectIdentifier;
use p256::elliptic_curve::Generate;
use p256::SecretKey;
use serde_json::json;
use serial_test::serial;
use sha2::{Digest, Sha256};
use types::OidcProvider;
use uuid::Uuid;

/// The origin the service's `WebAuthn` config trusts (`Environment::webauthn_config`).
const WEBAUTHN_ORIGIN: &str = "https://keys.world.app";

/// Label sent with every new-factor authorization here; it is part of the bound material.
const LABEL: &str = "Hand-built passkey";

/// `authenticatorData` flags: user present (`0x01`), user verified (`0x04` — the registration
/// policy is `UserVerificationPolicy::Required`) and attested credential data included (`0x40`).
/// The backup flags stay clear: BS without BE is rejected outright, and BE is optional because
/// the policy allows synchronised authenticators.
const FLAGS_UP_UV_AT: u8 = 0x01 | 0x04 | 0x40;

// COSE key labels and values (RFC 9052 / RFC 9053), as `webauthn-rs` reads them.
const COSE_KTY: i64 = 1;
const COSE_ALG: i64 = 3;
const COSE_KTY_EC2: i64 = 2;
const COSE_KTY_RSA: i64 = 3;
const COSE_ALG_ES256: i64 = -7;
const COSE_ALG_RS256: i64 = -257;
const COSE_EC2_CRV: i64 = -1;
const COSE_EC2_X: i64 = -2;
const COSE_EC2_Y: i64 = -3;
const COSE_CRV_P256: i64 = 1;
const COSE_RSA_N: i64 = -1;
const COSE_RSA_E: i64 = -2;

fn cbor_int(value: i64) -> Cbor {
    Cbor::Integer(Integer::from(value))
}

fn cbor_encode(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

/// A freshly generated RSA-2048 public key as the COSE key an RS256 authenticator would attest.
/// `webauthn-rs` insists on `n` being exactly 256 bytes and `e` exactly 3 bytes.
fn rs256_cose_key() -> Cbor {
    let jwk = Jwk::generate_rsa_key(2048).expect("RSA-2048 key generation");
    let parameter = |name: &str| -> Vec<u8> {
        let encoded = jwk
            .parameter(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("RSA JWK has no `{name}` parameter"));
        URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("JWK parameters are unpadded base64url")
    };
    let n = parameter("n");
    let e = parameter("e");
    assert_eq!(n.len(), 256, "RSA-2048 modulus must be 256 bytes");
    assert_eq!(e, [0x01, 0x00, 0x01], "public exponent must be 65537");

    Cbor::Map(vec![
        (cbor_int(COSE_KTY), cbor_int(COSE_KTY_RSA)),
        (cbor_int(COSE_ALG), cbor_int(COSE_ALG_RS256)),
        (cbor_int(COSE_RSA_N), Cbor::Bytes(n)),
        (cbor_int(COSE_RSA_E), Cbor::Bytes(e)),
    ])
}

/// A P-256 public key (SEC1 uncompressed, `0x04 || x || y`) as the COSE key an ES256
/// authenticator would attest.
fn es256_cose_key(public_key_sec1: &[u8; 65]) -> Cbor {
    Cbor::Map(vec![
        (cbor_int(COSE_KTY), cbor_int(COSE_KTY_EC2)),
        (cbor_int(COSE_ALG), cbor_int(COSE_ALG_ES256)),
        (cbor_int(COSE_EC2_CRV), cbor_int(COSE_CRV_P256)),
        (
            cbor_int(COSE_EC2_X),
            Cbor::Bytes(public_key_sec1[1..33].to_vec()),
        ),
        (
            cbor_int(COSE_EC2_Y),
            Cbor::Bytes(public_key_sec1[33..].to_vec()),
        ),
    ])
}

/// A registration response assembled without an authenticator.
struct HandBuiltRegistration {
    /// Raw credential id bytes, as carried in the attested credential data.
    credential_id: Vec<u8>,
    /// The `RegisterPublicKeyCredential` JSON to send as `newFactorAuthorization.credential`.
    credential: serde_json::Value,
}

/// Builds a `none`-attestation registration response for `cose_public_key` against the
/// `newFactorChallenge` (a `CredentialCreationOptions`) the service issued. It satisfies every
/// check in the `webauthn-rs` registration ceremony that does not depend on the key: client data
/// type, challenge, origin, RP id hash, UP/UV flags and a parseable attested-credential-data block.
fn build_none_attestation_registration(
    new_factor_challenge: &serde_json::Value,
    cose_public_key: &Cbor,
) -> HandBuiltRegistration {
    let options = &new_factor_challenge["publicKey"];
    let challenge = options["challenge"]
        .as_str()
        .expect("publicKey.challenge is a base64url string");
    let rp_id = options["rp"]["id"].as_str().expect("publicKey.rp.id");

    let client_data_json = serde_json::to_vec(&json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": WEBAUTHN_ORIGIN,
        "crossOrigin": false,
    }))
    .expect("client data JSON");

    let credential_id: [u8; 16] = rand::random();

    // authenticatorData = rpIdHash (32) || flags (1) || signCount (4, BE)
    //   || attestedCredentialData, where
    // attestedCredentialData = AAGUID (16) || credentialIdLength (2, BE) || credentialId
    //   || credentialPublicKey (COSE key, CBOR)
    let mut authenticator_data = Vec::new();
    authenticator_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    authenticator_data.push(FLAGS_UP_UV_AT);
    authenticator_data.extend_from_slice(&0u32.to_be_bytes());
    authenticator_data.extend_from_slice(&[0u8; 16]);
    authenticator_data.extend_from_slice(
        &u16::try_from(credential_id.len())
            .expect("credential id length fits in u16")
            .to_be_bytes(),
    );
    authenticator_data.extend_from_slice(&credential_id);
    authenticator_data.extend_from_slice(&cbor_encode(cose_public_key));

    // attestationObject = CBOR map {"fmt": "none", "attStmt": {}, "authData": authenticatorData}
    let attestation_object = cbor_encode(&Cbor::Map(vec![
        (
            Cbor::Text("fmt".to_string()),
            Cbor::Text("none".to_string()),
        ),
        (Cbor::Text("attStmt".to_string()), Cbor::Map(Vec::new())),
        (
            Cbor::Text("authData".to_string()),
            Cbor::Bytes(authenticator_data),
        ),
    ]));

    let credential_id_b64url = URL_SAFE_NO_PAD.encode(credential_id);
    HandBuiltRegistration {
        credential_id: credential_id.to_vec(),
        credential: json!({
            "id": credential_id_b64url,
            "rawId": credential_id_b64url,
            "type": "public-key",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data_json),
                "attestationObject": URL_SAFE_NO_PAD.encode(&attestation_object),
            },
        }),
    }
}

/// A backup owned by a fresh Google account.
struct OidcBackup {
    subject: String,
    backup_id: String,
    environment: Environment,
    oidc_server: MockOidcServer,
}

async fn create_oidc_backup() -> OidcBackup {
    let subject = format!("subject-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let TestBackupWithOidcAccount {
        environment,
        response,
        oidc_server,
        ..
    } = test;
    let backup_id = parse_response_body(response).await["backupId"]
        .as_str()
        .expect("backupId")
        .to_string();

    OidcBackup {
        subject,
        backup_id,
        environment,
        oidc_server,
    }
}

/// Add-factor challenges for registering a new passkey, authorized by an existing OIDC account.
async fn passkey_registration_challenges() -> serde_json::Value {
    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "PASSKEY_REGISTRATION",
            "platform": "IOS"
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;
    assert!(
        challenges["newFactorChallenge"]["publicKey"].is_object(),
        "unexpected challenge response: {challenges}"
    );
    challenges
}

/// One existing-factor session: a session keypair and a Google ID token whose nonce commits to
/// it, for the account that owns the backup.
struct ExistingOidcSession {
    public_key: String,
    secret_key: SecretKey,
    oidc_token: String,
}

impl ExistingOidcSession {
    fn new(oidc_server: &MockOidcServer, subject: &str) -> Self {
        let (public_key, secret_key) = generate_keypair();
        let oidc_token = oidc_server.generate_token(
            &MockOidcProvider::Google,
            Some(SubjectIdentifier::new(subject.to_string())),
            &public_key,
        );
        Self {
            public_key,
            secret_key,
            oidc_token,
        }
    }

    /// The `/v1/add-factor` body in which this session authorizes adding `credential`: it signs
    /// the binding payload over the credential's id, `public_key_sec1`, `LABEL` and the verbatim
    /// `clientDataJSON` / `attestationObject` bytes, with no Turnkey provider id and no encrypted
    /// backup key, matching the request fields exactly.
    fn add_factor_request(
        &self,
        challenges: &serde_json::Value,
        credential: &serde_json::Value,
        public_key_sec1: &[u8; 65],
    ) -> serde_json::Value {
        let payload = add_factor_payload_for_passkey_new(
            challenges,
            credential,
            public_key_sec1,
            LABEL,
            None,
            &json!(null),
        );
        let signature = sign_keypair_challenge(&self.secret_key, &payload);
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": self.oidc_token },
                "publicKey": self.public_key,
                "signature": signature,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": credential,
                "label": LABEL,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": null,
        })
    }
}

/// Whether both add-factor challenge tokens have been consumed.
async fn assert_challenge_tokens_used(challenges: &serde_json::Value, expected: bool) {
    let redis = get_test_redis_cache_manager().await;
    for token_field in ["existingFactorToken", "newFactorToken"] {
        let token = challenges[token_field].as_str().expect(token_field);
        assert_eq!(
            redis.is_challenge_token_used(token).await.expect("redis"),
            expected,
            "{token_field} consumed state"
        );
    }
}

/// The add-factor response and the stored metadata both list `factor_id` as a passkey factor for
/// `credential_id`.
async fn assert_passkey_factor_added(
    add_factor_response: &serde_json::Value,
    backup_id: &str,
    credential_id: &[u8],
) {
    let factor_id = add_factor_response["factorId"]
        .as_str()
        .expect("factorId in add-factor response");
    let expected_credential_id = URL_SAFE_NO_PAD.encode(credential_id);

    let exported = add_factor_response["backupMetadata"]["factors"]
        .as_array()
        .expect("backupMetadata.factors");
    assert!(
        exported.iter().any(|factor| factor["id"] == factor_id
            && factor["kind"]["kind"] == "PASSKEY"
            && factor["kind"]["credentialId"] == expected_credential_id
            && factor["kind"]["label"] == LABEL),
        "exported metadata lacks passkey factor {factor_id} for {expected_credential_id}: {add_factor_response}"
    );

    let metadata = verify_s3_metadata_exists(backup_id).await;
    let stored = metadata["factors"].as_array().expect("factors");
    assert!(
        stored
            .iter()
            .any(|factor| factor["id"] == factor_id && factor["kind"]["kind"] == "PASSKEY"),
        "stored metadata lacks passkey factor {factor_id}: {metadata}"
    );
}

/// A valid RS256 registration is rejected with `unsupported_passkey_algorithm`, and since nothing
/// was consumed the same tokens, ID token and session keypair then complete the ceremony with an
/// ES256 credential.
#[tokio::test]
#[serial]
async fn test_add_factor_rejects_rs256_passkey_registration_and_leaves_challenges_reusable() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges().await;
    let new_factor_challenge = &challenges["newFactorChallenge"];

    // The options only invite what completion accepts, so an authenticator honoring them never
    // produces the RS256 credential below; the server still has to reject one submitted anyway.
    let advertised_algorithms: Vec<i64> = new_factor_challenge["publicKey"]["pubKeyCredParams"]
        .as_array()
        .expect("publicKey.pubKeyCredParams")
        .iter()
        .map(|param| param["alg"].as_i64().expect("pubKeyCredParams[].alg"))
        .collect();
    assert_eq!(
        advertised_algorithms,
        vec![COSE_ALG_ES256],
        "add-factor registration options must advertise ES256 only"
    );

    let session = ExistingOidcSession::new(&backup.oidc_server, &backup.subject);

    // No 65-byte point exists for an RSA key, so no signed payload can be "right". Sign the
    // correctly shaped payload (challenge || 32-byte digest) over a zeroed point: the request is
    // well-formed up to the algorithm check, and a server that wrongly accepted the key could
    // still not get past the binding check with it.
    let rsa_registration =
        build_none_attestation_registration(new_factor_challenge, &rs256_cose_key());
    let metadata_before = verify_s3_metadata_exists(&backup.backup_id).await;
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        session.add_factor_request(&challenges, &rsa_registration.credential, &[0u8; 65]),
        Some(backup.environment),
    )
    .await;
    let status = response.status();
    let body = parse_response_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"]["code"], "unsupported_passkey_algorithm",
        "{body}"
    );

    // Rejected before anything was consumed or persisted: the stored metadata is identical to what
    // it was, and both tokens and the session's nonce are still fresh.
    assert_eq!(
        verify_s3_metadata_exists(&backup.backup_id).await,
        metadata_before,
        "an unsupported_passkey_algorithm rejection must leave the stored metadata untouched"
    );
    assert_challenge_tokens_used(&challenges, false).await;
    let nonce_used = get_test_redis_cache_manager()
        .await
        .is_oidc_nonce_used(
            &oidc_nonce_from_jwt(&session.oidc_token),
            &OidcProvider::Google,
        )
        .await
        .expect("redis");
    assert!(
        !nonce_used,
        "rejection must not burn the existing factor's OIDC nonce"
    );

    // The very same tokens, ID token and session keypair complete the same registration ceremony
    // with an ES256 credential from the mock authenticator.
    let mut passkey_client = get_mock_passkey_client();
    let credential = make_credential_from_passkey_challenge(
        &mut passkey_client,
        &json!({ "challenge": new_factor_challenge }),
    )
    .await;
    let (credential_id, public_key_sec1) = registered_passkey_material(&passkey_client);
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        session.add_factor_request(&challenges, &credential, &public_key_sec1),
        Some(backup.environment),
    )
    .await;
    let status = response.status();
    let body = parse_response_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_passkey_factor_added(&body, &backup.backup_id, &credential_id).await;
    assert_challenge_tokens_used(&challenges, true).await;
}

/// Control: the same hand-built `none`-attestation response carrying a P-256 (ES256) key is
/// accepted, so the RS256 rejection above is about the algorithm, not about the construction.
#[tokio::test]
#[serial]
async fn test_add_factor_accepts_hand_built_es256_passkey_registration() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges().await;

    let secret_key = SecretKey::generate();
    let public_key_sec1: [u8; 65] = secret_key
        .public_key()
        .to_sec1_bytes()
        .as_ref()
        .try_into()
        .expect("an uncompressed P-256 point is 65 bytes");
    let registration = build_none_attestation_registration(
        &challenges["newFactorChallenge"],
        &es256_cose_key(&public_key_sec1),
    );

    let session = ExistingOidcSession::new(&backup.oidc_server, &backup.subject);
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        session.add_factor_request(&challenges, &registration.credential, &public_key_sec1),
        Some(backup.environment),
    )
    .await;
    let status = response.status();
    let body = parse_response_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_passkey_factor_added(&body, &backup.backup_id, &registration.credential_id).await;
    assert_challenge_tokens_used(&challenges, true).await;
}
