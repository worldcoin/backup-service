//! Rollout bridge for the add-factor material binding (#253): until
//! `ADD_FACTOR_LEGACY_PASSKEY_PAYLOAD_SUNSET` has passed, `/add-factor` still accepts the legacy
//! existing=Passkey payload — the bare `existingFactorChallenge` in the Turnkey activity — next to
//! the bound one. It is open by default (unset or empty means no sunset), stays open on an
//! unparseable value (logged as an error), closes once the sunset has passed, and never applies to
//! existing=OIDC (which has no shipped clients to bridge).
//!
//! The variable is process-global, so every test here is `#[serial]` and clears it on exit.

mod common;

use crate::common::{
    add_factor_payload_for_oidc_new, create_test_backup, create_test_backup_with_oidc_account,
    create_turnkey_activity_and_hash, generate_keypair, get_add_factor_challenges_generic,
    get_test_redis_cache_manager, parse_response_body, send_post_request_with_environment,
    sign_keypair_challenge, verify_s3_metadata_exists, LegacyBridgeVar,
};
use axum::http::StatusCode;
use backup_service::environment::Environment;
use backup_service_test_utils::{
    get_mock_passkey_client, get_passkey_assertion, MockOidcProvider, MockOidcServer,
    MockPasskeyClient,
};
use chrono::{Duration, Utc};
use openidconnect::SubjectIdentifier;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

const TURNKEY_PROVIDER_ID: &str = "turnkey_provider_id";

fn future_sunset() -> String {
    (Utc::now() + Duration::days(1)).to_rfc3339()
}

fn past_sunset() -> String {
    (Utc::now() - Duration::days(1)).to_rfc3339()
}

/// A passkey-owned backup, a fresh Google account to add to it, and the add-factor challenges
/// minted for that combination.
struct PasskeyToOidc {
    passkey_client: MockPasskeyClient,
    backup_id: String,
    environment: Environment,
    _oidc_server: MockOidcServer,
    oidc_token: String,
    session_public_key: String,
    session_secret_key: p256::SecretKey,
    challenges: serde_json::Value,
}

impl PasskeyToOidc {
    async fn prepare() -> Self {
        let mut passkey_client = get_mock_passkey_client();
        let (_credential, create_response) =
            create_test_backup(&mut passkey_client, b"BACKUP DATA").await;
        assert_eq!(create_response.status(), StatusCode::OK);
        let backup_id = parse_response_body(create_response).await["backupId"]
            .as_str()
            .expect("backupId")
            .to_string();

        let oidc_server = MockOidcServer::new().await;
        let environment =
            Environment::development(Some(oidc_server.server.socket_address().port() as usize));
        let (session_public_key, session_secret_key) = generate_keypair();
        let oidc_token =
            oidc_server.generate_token(&MockOidcProvider::Google, None, &session_public_key);

        let challenges = get_add_factor_challenges_generic(
            json!({ "kind": "OIDC_ACCOUNT", "oidcToken": oidc_token }),
            Some("PASSKEY"),
        )
        .await;

        Self {
            passkey_client,
            backup_id,
            environment,
            _oidc_server: oidc_server,
            oidc_token,
            session_public_key,
            session_secret_key,
            challenges,
        }
    }

    /// The bare challenge — what shipped clients put in the Turnkey activity today.
    fn legacy_payload(&self) -> String {
        self.challenges["existingFactorChallenge"]
            .as_str()
            .expect("existingFactorChallenge")
            .to_string()
    }

    /// `existingFactorChallenge || SHA256(tag || material)` for exactly the request `body` sends.
    fn bound_payload(&self) -> String {
        add_factor_payload_for_oidc_new(
            &self.challenges,
            &self.oidc_token,
            Some(TURNKEY_PROVIDER_ID),
            &json!(null),
        )
    }

    /// Sends the add-factor request with the existing passkey stamping an activity that carries
    /// `metadata_challenge`, and returns `(status, body)`.
    async fn send(&mut self, metadata_challenge: &str) -> (StatusCode, serde_json::Value) {
        let (turnkey_activity, challenge_hash) =
            create_turnkey_activity_and_hash(metadata_challenge);
        let passkey_assertion =
            get_passkey_assertion(&mut self.passkey_client, &challenge_hash).await;
        let new_signature = sign_keypair_challenge(
            &self.session_secret_key,
            self.challenges["newFactorChallenge"]
                .as_str()
                .expect("newFactorChallenge"),
        );

        let response = send_post_request_with_environment(
            "/v1/add-factor",
            json!({
                "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
                "existingFactorChallengeToken": self.challenges["existingFactorToken"],
                "existingFactorTurnkeyActivity": turnkey_activity,
                "newFactorAuthorization": {
                    "kind": "OIDC_ACCOUNT",
                    "oidcToken": { "kind": "GOOGLE", "token": self.oidc_token },
                    "publicKey": self.session_public_key,
                    "signature": new_signature,
                },
                "newFactorChallengeToken": self.challenges["newFactorToken"],
                "turnkeyProviderId": TURNKEY_PROVIDER_ID,
                "encryptedBackupKey": null,
            }),
            Some(self.environment),
        )
        .await;
        let status = response.status();
        (status, parse_response_body(response).await)
    }

    async fn assert_oidc_factor_persisted(&self, expected: bool) {
        let metadata = verify_s3_metadata_exists(&self.backup_id).await;
        let has_oidc = metadata["factors"]
            .as_array()
            .expect("factors")
            .iter()
            .any(|factor| factor["kind"]["kind"] == "OIDC_ACCOUNT");
        assert_eq!(has_oidc, expected, "OIDC factor persisted: {metadata}");
    }

    async fn assert_challenge_tokens_used(&self, expected: bool) {
        let redis = get_test_redis_cache_manager().await;
        for field in ["existingFactorToken", "newFactorToken"] {
            let token = self.challenges[field].as_str().expect(field);
            assert_eq!(
                redis.is_challenge_token_used(token).await.expect("redis"),
                expected,
                "{field} consumed"
            );
        }
    }
}

fn assert_legacy_rejected(status: StatusCode, body: &serde_json::Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"]["code"], "existing_factor_material_binding_mismatch",
        "{body}"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("signed only the challenge"),
        "legacy shape should be named in the message: {body}"
    );
}

#[tokio::test]
#[serial]
async fn test_bridge_accepts_legacy_passkey_payload_while_sunset_is_ahead() {
    let _bridge = LegacyBridgeVar::set(&future_sunset());
    let mut flow = PasskeyToOidc::prepare().await;

    let (status, body) = flow.send(&flow.legacy_payload()).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    flow.assert_oidc_factor_persisted(true).await;
    flow.assert_challenge_tokens_used(true).await;
}

#[tokio::test]
#[serial]
async fn test_bridge_still_accepts_bound_payload() {
    let _bridge = LegacyBridgeVar::set(&future_sunset());
    let mut flow = PasskeyToOidc::prepare().await;

    let (status, body) = flow.send(&flow.bound_payload()).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    flow.assert_oidc_factor_persisted(true).await;
}

#[tokio::test]
#[serial]
async fn test_bridge_closed_after_sunset_rejects_legacy_payload_without_consuming_anything() {
    let _bridge = LegacyBridgeVar::set(&past_sunset());
    let mut flow = PasskeyToOidc::prepare().await;

    let (status, body) = flow.send(&flow.legacy_payload()).await;
    assert_legacy_rejected(status, &body);
    flow.assert_oidc_factor_persisted(false).await;
    flow.assert_challenge_tokens_used(false).await;

    // The rejection consumed nothing, so the very same tokens succeed with the bound payload.
    let (status, body) = flow.send(&flow.bound_payload()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    flow.assert_oidc_factor_persisted(true).await;
}

/// Production configuration lives outside this repository, so the server must keep shipped
/// clients working until a sunset is deliberately configured.
#[tokio::test]
#[serial]
async fn test_bridge_is_open_by_default() {
    let _bridge = LegacyBridgeVar::unset();
    let mut flow = PasskeyToOidc::prepare().await;

    let (status, body) = flow.send(&flow.legacy_payload()).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    flow.assert_oidc_factor_persisted(true).await;
    flow.assert_challenge_tokens_used(true).await;
}

/// What the deploy config carries until a sunset is agreed: the variable present but empty.
#[tokio::test]
#[serial]
async fn test_empty_sunset_means_no_sunset() {
    let _bridge = LegacyBridgeVar::set("");
    let mut flow = PasskeyToOidc::prepare().await;

    let (status, body) = flow.send(&flow.legacy_payload()).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    flow.assert_oidc_factor_persisted(true).await;
}

/// A typo in the sunset must not cut shipped clients off; it is logged and delays the cutover.
#[tokio::test]
#[serial]
async fn test_unparseable_sunset_keeps_the_bridge_open() {
    let _bridge = LegacyBridgeVar::set("next year, probably");
    let mut flow = PasskeyToOidc::prepare().await;

    let (status, body) = flow.send(&flow.legacy_payload()).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    flow.assert_oidc_factor_persisted(true).await;
}

/// existing=OIDC has no shipped clients, so the bridge never applies to it: the session keypair must
/// sign the bound payload even while the passkey bridge is open.
#[tokio::test]
#[serial]
async fn test_bridge_does_not_cover_oidc_existing_factor() {
    let _bridge = LegacyBridgeVar::set(&future_sunset());

    let subject = format!("existing-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let backup_id = parse_response_body(test.response).await["backupId"]
        .as_str()
        .expect("backupId")
        .to_string();

    // Fresh session for the existing account (its create-time nonce is already consumed) and a
    // different account as the new factor.
    let (existing_public_key, existing_secret_key) = generate_keypair();
    let existing_token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(subject)),
        &existing_public_key,
    );
    let (new_public_key, new_secret_key) = generate_keypair();
    let new_token = test.oidc_server.generate_token(
        &MockOidcProvider::Google,
        Some(SubjectIdentifier::new(format!("new-{}", Uuid::new_v4()))),
        &new_public_key,
    );
    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new_token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    // Legacy: the existing session signs only the bare challenge.
    let legacy_signature = sign_keypair_challenge(
        &existing_secret_key,
        challenges["existingFactorChallenge"]
            .as_str()
            .expect("existingFactorChallenge"),
    );
    let new_signature = sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"]
            .as_str()
            .expect("newFactorChallenge"),
    );
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": existing_token },
                "publicKey": existing_public_key,
                "signature": legacy_signature,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": new_token },
                "publicKey": new_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": TURNKEY_PROVIDER_ID,
            "encryptedBackupKey": null,
        }),
        Some(test.environment),
    )
    .await;
    let status = response.status();
    let body = parse_response_body(response).await;

    assert_legacy_rejected(status, &body);
    let metadata = verify_s3_metadata_exists(&backup_id).await;
    assert_eq!(
        metadata["factors"].as_array().expect("factors").len(),
        1,
        "no factor may be added: {metadata}"
    );
}
