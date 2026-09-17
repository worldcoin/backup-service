//! End-to-end coverage of the add-factor material binding.
//!
//! `POST /v1/add-factor` requires the existing factor to authorize
//! `existing_factor_challenge || SHA256(tag || new_factor_material)`, where the material is the
//! new credential (id, key and the verbatim registration response bytes) or ID token plus the
//! request's `label`, `turnkeyProviderId` and `encryptedBackupKey` exactly as sent. These tests
//! play the relay that rewrites a request after the user approved it and check the same three
//! things every time: the request is rejected with `existing_factor_material_binding_mismatch`,
//! nothing was persisted, and nothing was consumed — the very same challenge tokens and
//! existing-factor authorization still succeed once the body matches what was approved.

mod common;

use crate::common::{
    add_factor_payload_for_oidc_new, add_factor_payload_for_passkey_new, create_test_backup,
    create_test_backup_with_oidc_account, create_turnkey_activity_and_hash, generate_keypair,
    get_add_factor_challenges_generic, get_keypair_challenge, get_test_redis_cache_manager,
    make_sync_factor, oidc_nonce_from_jwt, parse_response_body, send_post_request_with_environment,
    send_post_request_with_multipart, sign_keypair_challenge, verify_s3_metadata_exists,
    webauthn_bytes, BackupAccount, LegacyBridgeVar,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::Response;
use backup_service::environment::Environment;
use backup_service_test_utils::{
    get_mock_passkey_client, get_passkey_assertion, make_credential_from_passkey_challenge,
    registered_passkey_material, MockOidcProvider, MockOidcServer, MockPasskeyClient,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openidconnect::SubjectIdentifier;
use p256::SecretKey;
use serde_json::{json, Value};
use serial_test::serial;
use std::ops::Range;
use types::OidcProvider;
use uuid::Uuid;

const BINDING_MISMATCH: &str = "existing_factor_material_binding_mismatch";
const ALREADY_USED: &str = "already_used";
const OIDC_TOKEN_MISMATCH: &str = "oidc_token_mismatch";

/// The label the user approved for the new passkey in the swap scenarios.
const APPROVED_LABEL: &str = "Victim's phone";
const TURNKEY_PROVIDER_ID: &str = "turnkey_provider_id";

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A backup whose only main factor is the passkey held by `client`.
struct PasskeyBackup {
    client: MockPasskeyClient,
    backup_id: String,
}

async fn create_passkey_backup() -> PasskeyBackup {
    let mut client = get_mock_passkey_client();
    let (_credential, response) = create_test_backup(&mut client, b"BACKUP DATA").await;
    assert_eq!(response.status(), StatusCode::OK);
    let backup_id = backup_id_from_create_response(response).await;
    PasskeyBackup { client, backup_id }
}

/// A backup whose only main factor is an OIDC account with `provider`, plus the mock issuer that
/// can mint further ID tokens for it.
struct OidcBackup {
    provider: MockOidcProvider,
    subject: String,
    backup_id: String,
    environment: Environment,
    oidc_server: MockOidcServer,
}

impl OidcBackup {
    /// An ID token from this backup's issuer for `subject` whose nonce commits to `public_key`.
    fn token_for(&self, subject: &str, public_key: &str) -> String {
        self.oidc_server.generate_token(
            &self.provider,
            Some(SubjectIdentifier::new(subject.to_string())),
            public_key,
        )
    }

    /// A fresh session keypair plus an ID token for `subject` from this backup's issuer.
    fn session_for(&self, subject: &str) -> OidcSession {
        let (public_key, secret_key) = generate_keypair();
        let token = self.token_for(subject, &public_key);
        OidcSession {
            public_key,
            secret_key,
            token,
        }
    }

    /// A fresh session keypair plus an ID token for this backup's own account.
    fn fresh_session(&self) -> OidcSession {
        self.session_for(&self.subject)
    }
}

/// A backup whose only main factor is a Google account.
async fn create_oidc_backup() -> OidcBackup {
    let subject = format!("binding-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let backup_id = backup_id_from_create_response(test.response).await;
    OidcBackup {
        provider: MockOidcProvider::Google,
        subject,
        backup_id,
        environment: test.environment,
        oidc_server: test.oidc_server,
    }
}

/// A backup whose only main factor is an Apple account: the same `/v1/create` flow as
/// `create_test_backup_with_oidc_account`, which hardcodes Google, with an Apple ID token sent
/// as `{kind: APPLE, token}` (no `aud`, so the default client id applies).
async fn create_apple_oidc_backup() -> OidcBackup {
    let subject = format!("binding-apple-{}", Uuid::new_v4());
    let oidc_server = MockOidcServer::new().await;
    let environment = Environment::development(Some(oidc_server.port()));

    let backup_account = BackupAccount::generate();
    let challenge_response = get_keypair_challenge().await;
    let (proof_token, proof_signature) = backup_account.proof(&challenge_response);
    let (public_key, secret_key) = generate_keypair();
    let token = oidc_server.generate_token(
        &MockOidcProvider::Apple,
        Some(SubjectIdentifier::new(subject.clone())),
        &public_key,
    );
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().expect("challenge"),
    );
    let (sync_factor, sync_challenge_token, _) = make_sync_factor().await;

    let response = send_post_request_with_multipart(
        "/v1/create",
        json!({
            "authorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "APPLE", "token": token },
                "publicKey": public_key,
                "signature": signature,
            },
            "challengeToken": challenge_response["token"],
            "initialEncryptionKey": { "kind": "PRF", "encryptedKey": "ENCRYPTED_KEY" },
            "initialSyncFactor": sync_factor,
            "initialSyncChallengeToken": sync_challenge_token,
            "turnkeyProviderId": TURNKEY_PROVIDER_ID,
            "manifestHash": "0101010101010101010101010101010101010101010101010101010101010101",
            "backupAccountId": backup_account.id,
            "backupAccountChallengeToken": proof_token,
            "backupAccountSignature": proof_signature,
        }),
        Bytes::from_static(b"BACKUP DATA"),
        Some(environment),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let backup_id = backup_id_from_create_response(response).await;
    OidcBackup {
        provider: MockOidcProvider::Apple,
        subject,
        backup_id,
        environment,
        oidc_server,
    }
}

async fn backup_id_from_create_response(response: Response) -> String {
    let body = parse_response_body(response).await;
    body["backupId"].as_str().expect("backupId").to_string()
}

/// An OIDC session: the ephemeral keypair and an ID token whose nonce commits to it.
struct OidcSession {
    public_key: String,
    secret_key: SecretKey,
    token: String,
}

impl OidcSession {
    /// A Google `OIDC_ACCOUNT` authorization whose session keypair signed `signed_payload_b64`
    /// (standard base64): the binding payload for an existing factor, the bare
    /// `newFactorChallenge` for a new one.
    fn authorization(&self, signed_payload_b64: &str) -> Value {
        self.authorization_with_oidc_token(
            &json!({ "kind": "GOOGLE", "token": self.token }),
            signed_payload_b64,
        )
    }

    /// Like [`Self::authorization`] with an explicit `oidcToken` object, for providers whose
    /// wire form has more than one shape (Apple with or without `aud`).
    fn authorization_with_oidc_token(&self, oidc_token: &Value, signed_payload_b64: &str) -> Value {
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
            "publicKey": self.public_key,
            "signature": sign_keypair_challenge(&self.secret_key, signed_payload_b64),
        })
    }
}

/// A Google account with a fresh subject being added as the new factor, with the mock issuer
/// the service must be pointed at for the request.
struct NewOidcAccount {
    environment: Environment,
    session: OidcSession,
    /// Dropping the guard stops the mock issuer, so it lives as long as the account.
    _server: MockOidcServer,
}

impl NewOidcAccount {
    async fn new() -> Self {
        let server = MockOidcServer::new().await;
        let environment = Environment::development(Some(server.port()));
        let (public_key, secret_key) = generate_keypair();
        let token = server.generate_token(
            &MockOidcProvider::Google,
            Some(SubjectIdentifier::new(format!(
                "new-account-{}",
                Uuid::new_v4()
            ))),
            &public_key,
        );
        Self {
            environment,
            session: OidcSession {
                public_key,
                secret_key,
                token,
            },
            _server: server,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------------------------

async fn passkey_registration_challenges(existing_factor_kind: &str) -> Value {
    get_add_factor_challenges_generic(
        json!({ "kind": "PASSKEY_REGISTRATION", "platform": "IOS" }),
        Some(existing_factor_kind),
    )
    .await
}

async fn oidc_challenges(new_oidc_token: &str, existing_factor_kind: &str) -> Value {
    get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new_oidc_token }),
        Some(existing_factor_kind),
    )
    .await
}

fn existing_factor_challenge(challenges: &Value) -> &str {
    challenges["existingFactorChallenge"]
        .as_str()
        .expect("existingFactorChallenge")
}

/// The new-factor challenge of an OIDC ceremony (a passkey ceremony carries creation options
/// here instead, see [`register_from_challenges`]).
fn new_factor_challenge(challenges: &Value) -> &str {
    challenges["newFactorChallenge"]
        .as_str()
        .expect("newFactorChallenge")
}

/// Registers a fresh credential on `client` from the ceremony in `challenges`.
async fn register_from_challenges(client: &mut MockPasskeyClient, challenges: &Value) -> Value {
    make_credential_from_passkey_challenge(
        client,
        &json!({ "challenge": challenges["newFactorChallenge"] }),
    )
    .await
}

/// Existing-passkey authorization: a Turnkey activity carrying `signed_payload_b64` as its
/// `metadata.challenge`, stamped by `client`. Returns `(authorization, activity)`.
async fn existing_passkey_authorization(
    client: &mut MockPasskeyClient,
    signed_payload_b64: &str,
) -> (Value, String) {
    let (activity, activity_hash) = create_turnkey_activity_and_hash(signed_payload_b64);
    let assertion = get_passkey_assertion(client, &activity_hash).await;
    (
        json!({ "kind": "PASSKEY", "credential": assertion }),
        activity,
    )
}

/// New-passkey authorization; `label: None` omits the field entirely.
fn new_passkey_authorization(credential: &Value, label: Option<&str>) -> Value {
    let mut authorization = json!({ "kind": "PASSKEY", "credential": credential });
    if let Some(label) = label {
        authorization["label"] = json!(label);
    }
    authorization
}

fn icloud_key(encrypted_key: &str) -> Value {
    json!({ "kind": "ICLOUD", "encryptedKey": encrypted_key })
}

fn turnkey_key(encrypted_key: &str) -> Value {
    json!({
        "kind": "TURNKEY",
        "encryptedKey": encrypted_key,
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID",
    })
}

/// A `/v1/add-factor` request body. Cloning and overriding one field is how each test produces
/// the tampered variant of an approved request.
#[derive(Clone)]
struct AddFactorBody<'a> {
    challenges: &'a Value,
    existing_authorization: Value,
    /// Only for an existing passkey.
    existing_turnkey_activity: Option<String>,
    new_authorization: Value,
    turnkey_provider_id: Option<&'a str>,
    /// `json!(null)` when the request carries no key.
    encrypted_backup_key: Value,
}

impl AddFactorBody<'_> {
    fn to_json(&self) -> Value {
        let mut body = json!({
            "existingFactorAuthorization": self.existing_authorization,
            "existingFactorChallengeToken": self.challenges["existingFactorToken"],
            "newFactorAuthorization": self.new_authorization,
            "newFactorChallengeToken": self.challenges["newFactorToken"],
            "encryptedBackupKey": self.encrypted_backup_key,
        });
        if let Some(activity) = &self.existing_turnkey_activity {
            body["existingFactorTurnkeyActivity"] = json!(activity);
        }
        if let Some(turnkey_provider_id) = self.turnkey_provider_id {
            body["turnkeyProviderId"] = json!(turnkey_provider_id);
        }
        body
    }
}

// ---------------------------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------------------------

async fn post_add_factor(
    body: &AddFactorBody<'_>,
    environment: Option<Environment>,
) -> (StatusCode, Value) {
    let response =
        send_post_request_with_environment("/v1/add-factor", body.to_json(), environment).await;
    let status = response.status();
    (status, parse_response_body(response).await)
}

/// Whether both challenge tokens of a ceremony have been consumed.
async fn assert_challenge_tokens_used(challenges: &Value, expected: bool) {
    let redis = get_test_redis_cache_manager().await;
    for name in ["existingFactorToken", "newFactorToken"] {
        let token = challenges[name].as_str().expect("challenge token");
        let used = redis.is_challenge_token_used(token).await.expect("redis");
        assert_eq!(used, expected, "{name} consumed state");
    }
}

/// Whether the nonce of a Google ID token has been consumed.
async fn assert_nonce_used(jwt: &str, expected: bool) {
    assert_nonce_used_for(jwt, &OidcProvider::Google, expected).await;
}

/// Whether the nonce of an ID token from `provider` has been consumed (nonces are tracked per
/// provider).
async fn assert_nonce_used_for(jwt: &str, provider: &OidcProvider, expected: bool) {
    let redis = get_test_redis_cache_manager().await;
    let nonce = oidc_nonce_from_jwt(jwt);
    let used = redis
        .is_oidc_nonce_used(&nonce, provider)
        .await
        .expect("redis");
    assert_eq!(used, expected, "{provider:?} nonce consumed state");
}

/// Posts `body` expecting a 400 with `expected_code`, and proves the rejection had no side
/// effects: the stored backup metadata is byte-for-byte unchanged and neither challenge token
/// was consumed. Returns the error body.
async fn assert_rejected_without_side_effects(
    body: &AddFactorBody<'_>,
    environment: Option<Environment>,
    backup_id: &str,
    expected_code: &str,
) -> Value {
    let metadata_before = verify_s3_metadata_exists(backup_id).await;

    let (status, error) = post_add_factor(body, environment).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unexpected status: {error}"
    );
    assert_eq!(error["error"]["code"], expected_code, "error body: {error}");
    assert_eq!(error["allowRetry"], false);

    assert_eq!(
        verify_s3_metadata_exists(backup_id).await,
        metadata_before,
        "rejected request changed the backup metadata"
    );
    assert_challenge_tokens_used(body.challenges, false).await;
    error
}

/// Posts `body` expecting a 200, and checks both challenge tokens are consumed afterwards.
/// Returns the response body.
async fn assert_accepted(body: &AddFactorBody<'_>, environment: Option<Environment>) -> Value {
    let (status, response) = post_add_factor(body, environment).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "approved request rejected: {response}"
    );
    assert!(response["factorId"].is_string(), "response: {response}");
    assert_challenge_tokens_used(body.challenges, true).await;
    response
}

/// The factor `response.factorId` names, as exported in `response.backupMetadata`.
fn exported_factor(response: &Value) -> &Value {
    let factor_id = response["factorId"].as_str().expect("factorId");
    factor_with_id(&response["backupMetadata"], factor_id)
}

/// The factor with id `factor_id` in `metadata.factors` (exported or stored form).
fn factor_with_id<'a>(metadata: &'a Value, factor_id: &str) -> &'a Value {
    metadata["factors"]
        .as_array()
        .expect("factors")
        .iter()
        .find(|factor| factor["id"] == factor_id)
        .unwrap_or_else(|| panic!("factor {factor_id} not in metadata: {metadata}"))
}

fn main_factor_count(metadata: &Value) -> usize {
    metadata["factors"].as_array().expect("factors").len()
}

/// The encryption keys of `kind` in `metadata.keys` (exported or stored form).
fn keys_of_kind<'a>(metadata: &'a Value, kind: &str) -> Vec<&'a Value> {
    metadata["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .filter(|key| key["kind"] == kind)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// 1 + 2. Authenticator swap within one registration ceremony
// ---------------------------------------------------------------------------------------------

/// Victim and attacker complete the SAME registration ceremony on different authenticators, so
/// the attacker's credential passes new-factor verification on its own; only the binding ties the
/// existing account's approval to the victim's key. Existing = OIDC account.
#[tokio::test]
#[serial]
async fn test_authenticator_swap_rejected_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;

    let mut victim = get_mock_passkey_client();
    let mut attacker = get_mock_passkey_client();
    let victim_credential = register_from_challenges(&mut victim, &challenges).await;
    let attacker_credential = register_from_challenges(&mut attacker, &challenges).await;
    let (victim_credential_id, victim_public_key) = registered_passkey_material(&victim);
    assert_ne!(
        registered_passkey_material(&attacker).0,
        victim_credential_id
    );

    // The existing account approves exactly the victim's credential.
    let session = backup.fresh_session();
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &victim_credential,
        &victim_public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&victim_credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let swapped = AddFactorBody {
        new_authorization: new_passkey_authorization(&attacker_credential, Some(APPROVED_LABEL)),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &swapped,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&session.token, false).await;

    // Same tokens, same existing-factor signature, the approved credential: accepted.
    let response = assert_accepted(&approved, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
    assert_eq!(
        exported_factor(&response)["kind"]["credentialId"],
        URL_SAFE_NO_PAD.encode(&victim_credential_id)
    );
    assert_eq!(
        main_factor_count(&verify_s3_metadata_exists(&backup.backup_id).await),
        2
    );
}

/// Same swap with an existing passkey, whose approval travels in a stamped Turnkey activity.
#[tokio::test]
#[serial]
async fn test_authenticator_swap_rejected_with_passkey_existing_factor() {
    let mut backup = create_passkey_backup().await;
    let challenges = passkey_registration_challenges("PASSKEY").await;

    let mut victim = get_mock_passkey_client();
    let mut attacker = get_mock_passkey_client();
    let victim_credential = register_from_challenges(&mut victim, &challenges).await;
    let attacker_credential = register_from_challenges(&mut attacker, &challenges).await;
    let (victim_credential_id, victim_public_key) = registered_passkey_material(&victim);
    assert_ne!(
        registered_passkey_material(&attacker).0,
        victim_credential_id
    );

    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &victim_credential,
        &victim_public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        new_authorization: new_passkey_authorization(&victim_credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let swapped = AddFactorBody {
        new_authorization: new_passkey_authorization(&attacker_credential, Some(APPROVED_LABEL)),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(&swapped, None, &backup.backup_id, BINDING_MISMATCH).await;

    let response = assert_accepted(&approved, None).await;
    assert_eq!(
        exported_factor(&response)["kind"]["credentialId"],
        URL_SAFE_NO_PAD.encode(&victim_credential_id)
    );
    assert_eq!(
        main_factor_count(&verify_s3_metadata_exists(&backup.backup_id).await),
        2
    );
}

// ---------------------------------------------------------------------------------------------
// 3. Field swaps: the credential is the approved one, another persisted field is not
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_encrypted_backup_key_swap_rejected_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (_, public_key) = registered_passkey_material(&new_passkey);

    let approved_key = icloud_key("approved-icloud-wrapped-key");
    let injected_key = icloud_key("injected-icloud-wrapped-key");
    let session = backup.fresh_session();
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &approved_key,
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: approved_key.clone(),
    };
    let swapped = AddFactorBody {
        encrypted_backup_key: injected_key,
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &swapped,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&session.token, false).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert!(keys_of_kind(&metadata, "ICLOUD").is_empty());

    assert_accepted(&approved, Some(backup.environment)).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert_eq!(keys_of_kind(&metadata, "ICLOUD"), vec![&approved_key]);
}

#[tokio::test]
#[serial]
async fn test_encrypted_backup_key_swap_rejected_with_passkey_existing_factor() {
    let mut backup = create_passkey_backup().await;
    let account = NewOidcAccount::new().await;
    let challenges = oidc_challenges(&account.session.token, "PASSKEY").await;

    let approved_key = turnkey_key("approved-turnkey-wrapped-key");
    let injected_key = turnkey_key("injected-turnkey-wrapped-key");
    let payload = add_factor_payload_for_oidc_new(
        &challenges,
        &account.session.token,
        Some(TURNKEY_PROVIDER_ID),
        &approved_key,
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        new_authorization: account
            .session
            .authorization(new_factor_challenge(&challenges)),
        turnkey_provider_id: Some(TURNKEY_PROVIDER_ID),
        encrypted_backup_key: approved_key.clone(),
    };
    let swapped = AddFactorBody {
        encrypted_backup_key: injected_key,
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &swapped,
        Some(account.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&account.session.token, false).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert!(keys_of_kind(&metadata, "TURNKEY").is_empty());

    assert_accepted(&approved, Some(account.environment)).await;
    assert_nonce_used(&account.session.token, true).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert_eq!(keys_of_kind(&metadata, "TURNKEY"), vec![&approved_key]);
}

#[tokio::test]
#[serial]
async fn test_turnkey_provider_id_swap_rejected_with_passkey_existing_factor() {
    let mut backup = create_passkey_backup().await;
    let account = NewOidcAccount::new().await;
    let challenges = oidc_challenges(&account.session.token, "PASSKEY").await;

    let payload = add_factor_payload_for_oidc_new(
        &challenges,
        &account.session.token,
        Some("tp-approved"),
        &json!(null),
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        new_authorization: account
            .session
            .authorization(new_factor_challenge(&challenges)),
        turnkey_provider_id: Some("tp-approved"),
        encrypted_backup_key: json!(null),
    };
    let swapped = AddFactorBody {
        turnkey_provider_id: Some("tp-injected"),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &swapped,
        Some(account.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&account.session.token, false).await;

    let response = assert_accepted(&approved, Some(account.environment)).await;
    assert_nonce_used(&account.session.token, true).await;
    let factor = exported_factor(&response);
    assert_eq!(factor["kind"]["kind"], "OIDC_ACCOUNT");
    assert_eq!(factor["kind"]["turnkeyProviderId"], "tp-approved");
}

/// `turnkeyProviderId` is optional for a passkey; the digest still commits to its absence.
#[tokio::test]
#[serial]
async fn test_turnkey_provider_id_injection_rejected_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (_, public_key) = registered_passkey_material(&new_passkey);

    let session = backup.fresh_session();
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let injected = AddFactorBody {
        turnkey_provider_id: Some("tp-injected"),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &injected,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&session.token, false).await;

    assert_accepted(&approved, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
}

/// `turnkeyProviderId` omitted and `turnkeyProviderId: ""` are different requests: the encoding
/// carries a presence byte for the field, so approving one does not authorize the other.
#[tokio::test]
#[serial]
async fn test_empty_turnkey_provider_id_differs_from_omitted_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (_, public_key) = registered_passkey_material(&new_passkey);

    // The existing account approves the request without a `turnkeyProviderId`.
    let session = backup.fresh_session();
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let emptied = AddFactorBody {
        turnkey_provider_id: Some(""),
        ..approved.clone()
    };
    assert_eq!(emptied.to_json()["turnkeyProviderId"], "");

    assert_rejected_without_side_effects(
        &emptied,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&session.token, false).await;

    assert_accepted(&approved, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
}

#[tokio::test]
#[serial]
async fn test_label_swap_rejected_with_passkey_existing_factor() {
    let mut backup = create_passkey_backup().await;
    let challenges = passkey_registration_challenges("PASSKEY").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (_, public_key) = registered_passkey_material(&new_passkey);

    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let swapped = AddFactorBody {
        new_authorization: new_passkey_authorization(&credential, Some("Attacker's device")),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(&swapped, None, &backup.backup_id, BINDING_MISMATCH).await;

    let response = assert_accepted(&approved, None).await;
    assert_eq!(exported_factor(&response)["kind"]["label"], APPROVED_LABEL);
}

#[tokio::test]
#[serial]
async fn test_label_swap_rejected_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (_, public_key) = registered_passkey_material(&new_passkey);

    let session = backup.fresh_session();
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let swapped = AddFactorBody {
        new_authorization: new_passkey_authorization(&credential, Some("Attacker's device")),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &swapped,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&session.token, false).await;

    let response = assert_accepted(&approved, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
    assert_eq!(exported_factor(&response)["kind"]["label"], APPROVED_LABEL);
}

/// Same-account metadata-only upgrade: one ID token + session keypair authorizes both sides and
/// the request only adds a Turnkey wrapped key. Swapping that key must fail like any other field.
#[tokio::test]
#[serial]
async fn test_encrypted_backup_key_swap_rejected_on_same_oidc_session_upgrade() {
    let backup = create_oidc_backup().await;
    let session = backup.fresh_session();
    let challenges = oidc_challenges(&session.token, "OIDC_ACCOUNT").await;

    let approved_key = turnkey_key("approved-turnkey-wrapped-key");
    let injected_key = turnkey_key("injected-turnkey-wrapped-key");
    let payload = add_factor_payload_for_oidc_new(
        &challenges,
        &session.token,
        Some(TURNKEY_PROVIDER_ID),
        &approved_key,
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: session.authorization(new_factor_challenge(&challenges)),
        turnkey_provider_id: Some(TURNKEY_PROVIDER_ID),
        encrypted_backup_key: approved_key.clone(),
    };
    let swapped = AddFactorBody {
        encrypted_backup_key: injected_key,
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &swapped,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&session.token, false).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert!(keys_of_kind(&metadata, "TURNKEY").is_empty());

    assert_accepted(&approved, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert_eq!(keys_of_kind(&metadata, "TURNKEY"), vec![&approved_key]);
    assert_eq!(main_factor_count(&metadata), 1, "no duplicate factor row");
}

// ---------------------------------------------------------------------------------------------
// 4. Legacy shape: the existing factor still signs only the bare challenge. For existing=Passkey
//    this is what the rollout bridge lets through while it is open (covered in
//    `add_factor_legacy_payload_bridge.rs`); here the bridge is closed, so both paths reject.
// ---------------------------------------------------------------------------------------------

/// The server names the legacy shape in its message; that is the only external signal that a
/// client is outdated rather than under attack.
fn assert_legacy_shape_named(error: &Value) {
    let message = error["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("signed only the challenge"),
        "legacy shape not called out: {error}"
    );
}

#[tokio::test]
#[serial]
async fn test_legacy_bare_challenge_rejected_with_passkey_existing_factor_once_bridge_closed() {
    let _bridge = LegacyBridgeVar::closed();
    let mut backup = create_passkey_backup().await;
    let account = NewOidcAccount::new().await;
    let challenges = oidc_challenges(&account.session.token, "PASSKEY").await;
    let key = turnkey_key("turnkey-wrapped-key");

    // An outdated client stamps an activity whose `metadata.challenge` is the bare challenge.
    let (legacy_authorization, legacy_activity) =
        existing_passkey_authorization(&mut backup.client, existing_factor_challenge(&challenges))
            .await;
    let legacy = AddFactorBody {
        challenges: &challenges,
        existing_authorization: legacy_authorization,
        existing_turnkey_activity: Some(legacy_activity),
        new_authorization: account
            .session
            .authorization(new_factor_challenge(&challenges)),
        turnkey_provider_id: Some(TURNKEY_PROVIDER_ID),
        encrypted_backup_key: key.clone(),
    };
    let error = assert_rejected_without_side_effects(
        &legacy,
        Some(account.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_legacy_shape_named(&error);
    assert_nonce_used(&account.session.token, false).await;

    // The same tokens succeed once the activity carries the bound payload.
    let payload = add_factor_payload_for_oidc_new(
        &challenges,
        &account.session.token,
        Some(TURNKEY_PROVIDER_ID),
        &key,
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let bound = AddFactorBody {
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        ..legacy.clone()
    };
    assert_accepted(&bound, Some(account.environment)).await;
    assert_nonce_used(&account.session.token, true).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert_eq!(keys_of_kind(&metadata, "TURNKEY"), vec![&key]);
}

#[tokio::test]
#[serial]
async fn test_legacy_bare_challenge_rejected_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (credential_id, public_key) = registered_passkey_material(&new_passkey);

    // An outdated client signs the bare challenge with the session keypair.
    let session = backup.fresh_session();
    let legacy = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(existing_factor_challenge(&challenges)),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let error = assert_rejected_without_side_effects(
        &legacy,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_legacy_shape_named(&error);
    assert_nonce_used(&session.token, false).await;

    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let bound = AddFactorBody {
        existing_authorization: session.authorization(&payload),
        ..legacy.clone()
    };
    let response = assert_accepted(&bound, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
    assert_eq!(
        exported_factor(&response)["kind"]["credentialId"],
        URL_SAFE_NO_PAD.encode(&credential_id)
    );
}

// ---------------------------------------------------------------------------------------------
// 5. Happy paths that exercise the bound fields
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_passkey_to_passkey_with_label_and_icloud_key_persists_both() {
    let mut backup = create_passkey_backup().await;
    let challenges = passkey_registration_challenges("PASSKEY").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (credential_id, public_key) = registered_passkey_material(&new_passkey);

    let key = icloud_key("icloud-wrapped-key");
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        "Work laptop",
        None,
        &key,
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let body = AddFactorBody {
        challenges: &challenges,
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        new_authorization: new_passkey_authorization(&credential, Some("Work laptop")),
        turnkey_provider_id: None,
        encrypted_backup_key: key.clone(),
    };

    let response = assert_accepted(&body, None).await;
    let exported = exported_factor(&response);
    assert_eq!(exported["kind"]["kind"], "PASSKEY");
    assert_eq!(exported["kind"]["label"], "Work laptop");
    assert_eq!(
        exported["kind"]["credentialId"],
        URL_SAFE_NO_PAD.encode(&credential_id)
    );
    assert_eq!(
        keys_of_kind(&response["backupMetadata"], "ICLOUD"),
        vec![&key]
    );

    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    let stored = factor_with_id(&metadata, response["factorId"].as_str().unwrap());
    assert_eq!(stored["kind"]["label"], "Work laptop");
    assert_eq!(keys_of_kind(&metadata, "ICLOUD"), vec![&key]);
    assert_eq!(main_factor_count(&metadata), 2);
}

#[tokio::test]
#[serial]
async fn test_oidc_to_passkey_with_turnkey_key_persists_key() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (_, public_key) = registered_passkey_material(&new_passkey);

    let key = turnkey_key("turnkey-wrapped-key");
    let session = backup.fresh_session();
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &key,
    );
    let body = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: key.clone(),
    };

    let response = assert_accepted(&body, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
    assert_eq!(
        keys_of_kind(&response["backupMetadata"], "TURNKEY"),
        vec![&key]
    );
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert_eq!(keys_of_kind(&metadata, "TURNKEY"), vec![&key]);
    assert_eq!(main_factor_count(&metadata), 2);
}

/// A request without `label` is signed with the empty label.
#[tokio::test]
#[serial]
async fn test_omitted_label_is_signed_as_empty_string() {
    let mut backup = create_passkey_backup().await;
    let challenges = passkey_registration_challenges("PASSKEY").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (credential_id, public_key) = registered_passkey_material(&new_passkey);

    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        "",
        None,
        &json!(null),
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let body = AddFactorBody {
        challenges: &challenges,
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        new_authorization: new_passkey_authorization(&credential, None),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    assert!(body.to_json()["newFactorAuthorization"]["label"].is_null());

    let response = assert_accepted(&body, None).await;
    let exported = exported_factor(&response);
    assert_eq!(exported["kind"]["label"], "");
    assert_eq!(
        exported["kind"]["credentialId"],
        URL_SAFE_NO_PAD.encode(&credential_id)
    );
}

// ---------------------------------------------------------------------------------------------
// 6. Nonce accounting at the commit
// ---------------------------------------------------------------------------------------------

/// Two different Google accounts presented with ID tokens minted for the SAME session keypair
/// carry the same nonce. The commit burns every key or none: the duplicate nonce is rejected as
/// `already_used`, nothing is persisted, and both challenge tokens stay usable.
#[tokio::test]
#[serial]
async fn test_shared_nonce_across_two_oidc_accounts_rejected_without_consuming_anything() {
    let backup = create_oidc_backup().await;
    let (public_key, secret_key) = generate_keypair();
    let existing = OidcSession {
        public_key: public_key.clone(),
        secret_key: secret_key.clone(),
        token: backup.token_for(&backup.subject, &public_key),
    };
    let new_account = OidcSession {
        public_key,
        secret_key,
        token: backup.token_for(&format!("other-{}", Uuid::new_v4()), &existing.public_key),
    };
    assert_ne!(existing.token, new_account.token);
    assert_eq!(
        oidc_nonce_from_jwt(&existing.token),
        oidc_nonce_from_jwt(&new_account.token)
    );

    let challenges = oidc_challenges(&new_account.token, "OIDC_ACCOUNT").await;
    let key = turnkey_key("turnkey-wrapped-key");
    let payload = add_factor_payload_for_oidc_new(
        &challenges,
        &new_account.token,
        Some(TURNKEY_PROVIDER_ID),
        &key,
    );
    let body = AddFactorBody {
        challenges: &challenges,
        existing_authorization: existing.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_account.authorization(new_factor_challenge(&challenges)),
        turnkey_provider_id: Some(TURNKEY_PROVIDER_ID),
        encrypted_backup_key: key,
    };

    assert_rejected_without_side_effects(
        &body,
        Some(backup.environment),
        &backup.backup_id,
        ALREADY_USED,
    )
    .await;
    assert_nonce_used(&existing.token, false).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert_eq!(main_factor_count(&metadata), 1);
    assert!(keys_of_kind(&metadata, "TURNKEY").is_empty());
}

// ---------------------------------------------------------------------------------------------
// 7. Registration response tamper: same credential id and key, different authenticator data
// ---------------------------------------------------------------------------------------------

/// Where `signCount` sits in `WebAuthn` `authenticatorData`:
/// `rpIdHash(32) || flags(1) || signCount(4, big-endian) || AAGUID(16) || credIdLen(2) || credId || COSE key`.
const AUTH_DATA_SIGN_COUNT: Range<usize> = 33..37;

/// `bytes` in the JSON form `original` used for the same `WebAuthn` field: the mock
/// authenticator's byte array, or the unpadded base64url string real clients send.
fn webauthn_json_like(original: &Value, bytes: &[u8]) -> Value {
    if original.is_array() {
        json!(bytes)
    } else {
        json!(URL_SAFE_NO_PAD.encode(bytes))
    }
}

/// The `authData` entry of a CBOR attestation object (a map of `fmt`, `attStmt` and `authData`).
fn attestation_auth_data(attestation_object: &[u8]) -> Vec<u8> {
    let attestation: ciborium::Value =
        ciborium::from_reader(attestation_object).expect("attestationObject is CBOR");
    attestation
        .as_map()
        .expect("attestationObject is a CBOR map")
        .iter()
        .find(|(key, _)| key.as_text() == Some("authData"))
        .and_then(|(_, value)| value.as_bytes())
        .expect("attestationObject has an authData byte string")
        .clone()
}

/// A copy of the registration response `credential` whose `response.attestationObject` carries
/// a different `signCount` and is otherwise byte-identical. The counter is patched in place
/// inside the CBOR-embedded `authData`, so the credential id and public key are untouched (the
/// tampered credential still passes new-factor verification on its own) and the field keeps the
/// JSON form the original used.
fn credential_with_tampered_sign_count(credential: &Value) -> Value {
    let original = &credential["response"]["attestationObject"];
    let original_bytes = webauthn_bytes(original);
    let auth_data = attestation_auth_data(&original_bytes);
    // A CBOR byte string's content is embedded verbatim, so `authData` is a contiguous run.
    let auth_data_at = original_bytes
        .windows(auth_data.len())
        .position(|window| window == auth_data.as_slice())
        .expect("authData appears verbatim in attestationObject");
    let sign_count_at =
        auth_data_at + AUTH_DATA_SIGN_COUNT.start..auth_data_at + AUTH_DATA_SIGN_COUNT.end;

    let mut tampered_bytes = original_bytes.clone();
    for byte in &mut tampered_bytes[sign_count_at.clone()] {
        *byte = !*byte;
    }
    let changed: Vec<usize> = original_bytes
        .iter()
        .zip(&tampered_bytes)
        .enumerate()
        .filter(|(_, (before, after))| before != after)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        changed,
        sign_count_at.collect::<Vec<_>>(),
        "only the signCount bytes may differ"
    );

    let mut tampered = credential.clone();
    tampered["response"]["attestationObject"] = webauthn_json_like(original, &tampered_bytes);
    tampered
}

/// With `none` attestation nothing signs `authenticatorData`, so a relay could rewrite the sign
/// count (or flags / AAGUID) that gets persisted with the credential while leaving the credential
/// id and key — and therefore the credential's own verification — intact. Only the binding over
/// the verbatim `attestationObject` catches it. Existing = OIDC account.
#[tokio::test]
#[serial]
async fn test_attestation_object_tamper_rejected_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let challenges = passkey_registration_challenges("OIDC_ACCOUNT").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (credential_id, public_key) = registered_passkey_material(&new_passkey);
    let tampered_credential = credential_with_tampered_sign_count(&credential);

    let session = backup.fresh_session();
    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let tampered = AddFactorBody {
        new_authorization: new_passkey_authorization(&tampered_credential, Some(APPROVED_LABEL)),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &tampered,
        Some(backup.environment),
        &backup.backup_id,
        BINDING_MISMATCH,
    )
    .await;
    assert_nonce_used(&session.token, false).await;

    // The untouched registration response, same tokens and same approval: accepted.
    let response = assert_accepted(&approved, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
    assert_eq!(
        exported_factor(&response)["kind"]["credentialId"],
        URL_SAFE_NO_PAD.encode(&credential_id)
    );
}

/// Same tamper with an existing passkey, whose approval travels in a stamped Turnkey activity.
#[tokio::test]
#[serial]
async fn test_attestation_object_tamper_rejected_with_passkey_existing_factor() {
    let mut backup = create_passkey_backup().await;
    let challenges = passkey_registration_challenges("PASSKEY").await;
    let mut new_passkey = get_mock_passkey_client();
    let credential = register_from_challenges(&mut new_passkey, &challenges).await;
    let (credential_id, public_key) = registered_passkey_material(&new_passkey);
    let tampered_credential = credential_with_tampered_sign_count(&credential);

    let payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &public_key,
        APPROVED_LABEL,
        None,
        &json!(null),
    );
    let (existing_authorization, activity) =
        existing_passkey_authorization(&mut backup.client, &payload).await;
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization,
        existing_turnkey_activity: Some(activity),
        new_authorization: new_passkey_authorization(&credential, Some(APPROVED_LABEL)),
        turnkey_provider_id: None,
        encrypted_backup_key: json!(null),
    };
    let tampered = AddFactorBody {
        new_authorization: new_passkey_authorization(&tampered_credential, Some(APPROVED_LABEL)),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(&tampered, None, &backup.backup_id, BINDING_MISMATCH)
        .await;

    let response = assert_accepted(&approved, None).await;
    assert_eq!(
        exported_factor(&response)["kind"]["credentialId"],
        URL_SAFE_NO_PAD.encode(&credential_id)
    );
    assert_eq!(
        main_factor_count(&verify_s3_metadata_exists(&backup.backup_id).await),
        2
    );
}

// ---------------------------------------------------------------------------------------------
// 8. New-factor descriptor swap: the ceremony was minted for another account's ID token
// ---------------------------------------------------------------------------------------------

/// The existing factor's challenge token is minted for the new-factor descriptor — here ID token
/// A — and the existing account signs the payload for A. Submitting another account's token B in
/// `newFactorAuthorization` trips the cross-ceremony descriptor check, which runs before any
/// signature or ID-token verification, so nothing is verified and nothing is consumed.
#[tokio::test]
#[serial]
async fn test_new_oidc_token_swap_rejected_with_oidc_existing_factor() {
    let backup = create_oidc_backup().await;
    let approved_account = backup.session_for(&format!("approved-{}", Uuid::new_v4()));
    let other_account = backup.session_for(&format!("other-{}", Uuid::new_v4()));
    let challenges = oidc_challenges(&approved_account.token, "OIDC_ACCOUNT").await;

    let session = backup.fresh_session();
    let payload = add_factor_payload_for_oidc_new(
        &challenges,
        &approved_account.token,
        Some(TURNKEY_PROVIDER_ID),
        &json!(null),
    );
    let approved = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization(&payload),
        existing_turnkey_activity: None,
        new_authorization: approved_account.authorization(new_factor_challenge(&challenges)),
        turnkey_provider_id: Some(TURNKEY_PROVIDER_ID),
        encrypted_backup_key: json!(null),
    };
    let swapped = AddFactorBody {
        new_authorization: other_account.authorization(new_factor_challenge(&challenges)),
        ..approved.clone()
    };

    assert_rejected_without_side_effects(
        &swapped,
        Some(backup.environment),
        &backup.backup_id,
        OIDC_TOKEN_MISMATCH,
    )
    .await;
    for token in [
        &session.token,
        &approved_account.token,
        &other_account.token,
    ] {
        assert_nonce_used(token, false).await;
    }

    let response = assert_accepted(&approved, Some(backup.environment)).await;
    assert_nonce_used(&session.token, true).await;
    assert_nonce_used(&approved_account.token, true).await;
    assert_nonce_used(&other_account.token, false).await;
    assert_eq!(exported_factor(&response)["kind"]["kind"], "OIDC_ACCOUNT");
    assert_eq!(
        main_factor_count(&verify_s3_metadata_exists(&backup.backup_id).await),
        2
    );
}

// ---------------------------------------------------------------------------------------------
// 9. Apple same-session upgrade: one Apple ID token, with and without an explicit `aud`
// ---------------------------------------------------------------------------------------------

/// Which side of a same-session Apple upgrade names the default `aud` explicitly; the other side
/// sends `{kind: APPLE, token}` and relies on the default.
#[derive(Clone, Copy)]
enum ExplicitAud {
    Existing,
    New,
}

/// Same-account metadata-only upgrade on an Apple account. The same-session detection compares
/// the raw JWT and session key per provider rather than the whole `oidcToken` object, so the two
/// wire shapes of one Apple token still count as one session: 200, one factor, nonce burned once.
async fn assert_apple_same_session_upgrade(explicit_aud: ExplicitAud) {
    let backup = create_apple_oidc_backup().await;
    let session = backup.fresh_session();
    let challenges = oidc_challenges(&session.token, "OIDC_ACCOUNT").await;

    let default_aud = backup.environment.allowed_apple_client_ids()[0];
    let plain = json!({ "kind": "APPLE", "token": session.token });
    let with_aud = json!({ "kind": "APPLE", "token": session.token, "aud": default_aud });
    let (existing_token, new_token) = match explicit_aud {
        ExplicitAud::Existing => (with_aud, plain),
        ExplicitAud::New => (plain, with_aud),
    };

    let key = turnkey_key("turnkey-wrapped-key");
    let payload = add_factor_payload_for_oidc_new(
        &challenges,
        &session.token,
        Some(TURNKEY_PROVIDER_ID),
        &key,
    );
    let body = AddFactorBody {
        challenges: &challenges,
        existing_authorization: session.authorization_with_oidc_token(&existing_token, &payload),
        existing_turnkey_activity: None,
        new_authorization: session
            .authorization_with_oidc_token(&new_token, new_factor_challenge(&challenges)),
        turnkey_provider_id: Some(TURNKEY_PROVIDER_ID),
        encrypted_backup_key: key.clone(),
    };

    let response = assert_accepted(&body, Some(backup.environment)).await;
    assert_nonce_used_for(&session.token, &OidcProvider::Apple, true).await;
    let metadata = verify_s3_metadata_exists(&backup.backup_id).await;
    assert_eq!(main_factor_count(&metadata), 1, "no duplicate factor row");
    let stored = factor_with_id(&metadata, response["factorId"].as_str().expect("factorId"));
    assert_eq!(stored["kind"]["kind"], "OIDC_ACCOUNT");
    assert_eq!(stored["kind"]["account"]["kind"], "APPLE");
    assert_eq!(keys_of_kind(&metadata, "TURNKEY"), vec![&key]);
}

#[tokio::test]
#[serial]
async fn test_same_apple_session_upgrade_with_explicit_aud_on_new_side() {
    // Boxed: the helper's future is just over clippy's `large_futures` threshold.
    Box::pin(assert_apple_same_session_upgrade(ExplicitAud::New)).await;
}

#[tokio::test]
#[serial]
async fn test_same_apple_session_upgrade_with_explicit_aud_on_existing_side() {
    Box::pin(assert_apple_same_session_upgrade(ExplicitAud::Existing)).await;
}
