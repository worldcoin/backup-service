//! Commit atomicity of `POST /v1/add-factor`.
//!
//! The handler must not write anything to Redis until both factors are fully verified and the
//! per-factor mutate lock is held; it then consumes both challenge tokens and every OIDC nonce in
//! one all-or-nothing step, and only then persists the factor. These tests observe that contract
//! from the outside: through the HTTP status / error code, by reading the used-token and
//! used-nonce markers straight from Redis, and by counting what landed in the backup metadata.
//!
//! Every test starts from one fully valid existing=OIDC → new=OIDC (different account) ceremony
//! and breaks exactly one thing, so a leak of any single-use value shows up as a replay that
//! should have succeeded but did not. (The existing factor signs the bare challenge here; binding
//! it to the new factor's material is a separate change.)

mod common;

use crate::common::{
    create_test_backup_with_oidc_account, generate_keypair, get_add_factor_challenges_generic,
    get_test_redis_cache_manager, oidc_nonce_from_jwt, parse_response_body,
    send_post_request_with_environment, sign_keypair_challenge, verify_s3_metadata_exists,
    TestBackupWithOidcAccount,
};
use axum::http::StatusCode;
use axum::response::Response;
use backup_service::environment::Environment;
use backup_service::factor_lookup::{
    factor_lookup_mutate_lock_id, FactorToLookup, FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
};
use backup_service::redis_cache::RedisCacheManager;
use backup_service_test_utils::{MockOidcProvider, MockOidcServer};
use openidconnect::SubjectIdentifier;
use p256::SecretKey;
use serde_json::{json, Value};
use serial_test::serial;
use types::OidcProvider;
use uuid::Uuid;

const TURNKEY_PROVIDER_ID: &str = "turnkey_provider_id";

/// The `encryptedBackupKey` every request in this file sends.
fn encrypted_backup_key() -> Value {
    json!({
        "kind": "TURNKEY",
        "encryptedKey": "ENCRYPTED_KEY",
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
    })
}

/// An ephemeral OIDC session: the keypair the ID token's nonce commits to, and the token itself.
struct OidcSession {
    public_key: String,
    secret_key: SecretKey,
    token: String,
}

impl OidcSession {
    fn mint(oidc_server: &MockOidcServer, subject: &str) -> Self {
        let (public_key, secret_key) = generate_keypair();
        let token = oidc_server.generate_token(
            &MockOidcProvider::Google,
            Some(SubjectIdentifier::new(subject.to_string())),
            &public_key,
        );
        Self {
            public_key,
            secret_key,
            token,
        }
    }

    fn nonce(&self) -> String {
        oidc_nonce_from_jwt(&self.token)
    }
}

/// One fully prepared add-factor ceremony: a fresh backup owned by an OIDC account, a new-factor
/// ID token for a different account, the challenge pair minted for it, and an existing-factor ID
/// token. `request()` is valid as-is; `request_with` lets a test substitute one signature.
struct Ceremony {
    backup_id: String,
    environment: Environment,
    oidc_server: MockOidcServer,
    existing_subject: String,
    new_subject: String,
    existing: OidcSession,
    new: OidcSession,
    challenges: Value,
}

impl Ceremony {
    async fn prepare() -> Self {
        let existing_subject = format!("existing-{}", Uuid::new_v4());
        let new_subject = format!("new-{}", Uuid::new_v4());
        let TestBackupWithOidcAccount {
            response,
            environment,
            oidc_server,
            ..
        } = create_test_backup_with_oidc_account(&existing_subject, b"BACKUP DATA").await;
        assert_eq!(response.status(), StatusCode::OK);
        let backup_id = parse_response_body(response).await["backupId"]
            .as_str()
            .unwrap()
            .to_string();

        let new = OidcSession::mint(&oidc_server, &new_subject);
        let challenges = get_add_factor_challenges_generic(
            json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new.token }),
            Some("OIDC_ACCOUNT"),
        )
        .await;
        let existing = OidcSession::mint(&oidc_server, &existing_subject);

        Self {
            backup_id,
            environment,
            oidc_server,
            existing_subject,
            new_subject,
            existing,
            new,
            challenges,
        }
    }

    /// A brand-new challenge pair for the *same* new-factor ID token, authorized by a fresh
    /// existing-factor session (fresh nonce). After an earlier commit, the new token's nonce is
    /// the only single-use value of this ceremony that is already spent.
    async fn reissue_challenges(&mut self) {
        self.challenges = get_add_factor_challenges_generic(
            json!({ "kind": "OIDC_ACCOUNT", "oidcToken": self.new.token }),
            Some("OIDC_ACCOUNT"),
        )
        .await;
        self.existing = OidcSession::mint(&self.oidc_server, &self.existing_subject);
    }

    fn existing_challenge_token(&self) -> &str {
        self.challenges["existingFactorToken"].as_str().unwrap()
    }

    fn new_challenge_token(&self) -> &str {
        self.challenges["newFactorToken"].as_str().unwrap()
    }

    /// The `existingFactorChallenge` (standard base64) the existing factor signs.
    fn existing_challenge(&self) -> &str {
        self.challenges["existingFactorChallenge"].as_str().unwrap()
    }

    /// The existing factor's correct signature, over `existingFactorChallenge`.
    fn existing_signature(&self) -> String {
        sign_keypair_challenge(&self.existing.secret_key, self.existing_challenge())
    }

    /// The new factor's correct signature, over `newFactorChallenge`.
    fn new_signature(&self) -> String {
        sign_keypair_challenge(
            &self.new.secret_key,
            self.challenges["newFactorChallenge"].as_str().unwrap(),
        )
    }

    fn request(&self) -> Value {
        self.request_with(&self.existing_signature(), &self.new_signature())
    }

    fn request_with(&self, existing_signature: &str, new_signature: &str) -> Value {
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": self.existing.token },
                "publicKey": self.existing.public_key,
                "signature": existing_signature,
            },
            "existingFactorChallengeToken": self.existing_challenge_token(),
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": self.new.token },
                "publicKey": self.new.public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": self.new_challenge_token(),
            "turnkeyProviderId": TURNKEY_PROVIDER_ID,
            "encryptedBackupKey": encrypted_backup_key(),
        })
    }

    async fn send(&self, body: Value) -> Response {
        send_post_request_with_environment("/v1/add-factor", body, Some(self.environment)).await
    }

    /// The mutate-lock id the handler takes for the new factor: its `FactorLookup` primary key,
    /// built from the issuer the mock provider stamps into the token and the new account's `sub`.
    fn new_factor_lock_id(&self) -> String {
        factor_lookup_mutate_lock_id(&FactorToLookup::from_oidc_account(
            self.environment.google_issuer_url().to_string(),
            self.new_subject.clone(),
        ))
    }

    /// How many OIDC factors on the backup carry the new account's `sub`.
    async fn persisted_new_factor_count(&self) -> usize {
        let metadata = verify_s3_metadata_exists(&self.backup_id).await;
        metadata["factors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|factor| {
                factor["kind"]["kind"] == "OIDC_ACCOUNT"
                    && factor["kind"]["account"]["sub"] == self.new_subject.as_str()
            })
            .count()
    }
}

/// The single-use values one ceremony puts on the line, in the order `consumed` reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SingleUse {
    ExistingChallengeToken,
    NewChallengeToken,
    ExistingNonce,
    NewNonce,
}

impl SingleUse {
    const ALL: [Self; 4] = [
        Self::ExistingChallengeToken,
        Self::NewChallengeToken,
        Self::ExistingNonce,
        Self::NewNonce,
    ];
    const NONE: [Self; 0] = [];
}

/// Which of the ceremony's single-use values Redis currently reports as consumed.
async fn consumed(redis: &RedisCacheManager, ceremony: &Ceremony) -> Vec<SingleUse> {
    let mut consumed = Vec::new();
    for value in SingleUse::ALL {
        let used = match value {
            SingleUse::ExistingChallengeToken => {
                redis
                    .is_challenge_token_used(ceremony.existing_challenge_token())
                    .await
            }
            SingleUse::NewChallengeToken => {
                redis
                    .is_challenge_token_used(ceremony.new_challenge_token())
                    .await
            }
            SingleUse::ExistingNonce => {
                redis
                    .is_oidc_nonce_used(&ceremony.existing.nonce(), &OidcProvider::Google)
                    .await
            }
            SingleUse::NewNonce => {
                redis
                    .is_oidc_nonce_used(&ceremony.new.nonce(), &OidcProvider::Google)
                    .await
            }
        }
        .unwrap();
        if used {
            consumed.push(value);
        }
    }
    consumed
}

/// Asserts a 200 and returns the parsed body; the body is in the failure message otherwise.
async fn assert_accepted(response: Response) -> Value {
    let status = response.status();
    let body = parse_response_body(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected success, got {status} {body}"
    );
    body
}

/// `(status, error.code)` of a rejected request.
async fn rejection(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let body = parse_response_body(response).await;
    let Some(code) = body["error"]["code"].as_str() else {
        panic!("expected an error body, got {status} {body}");
    };
    (status, code.to_string())
}

async fn assert_rejected(response: Response, expected_status: StatusCode, expected_code: &str) {
    let (status, code) = rejection(response).await;
    assert_eq!((status, code.as_str()), (expected_status, expected_code));
}

// 1. Two identical, fully valid submissions racing each other: exactly one commits. The other
//    loses either at the mutate lock (423 conflicting_lock) or, if it arrives after the winner
//    released the lock, at the all-or-nothing burn (400 already_used). Both are correct; anything
//    else (two successes, a 500, a different code) is not.
#[tokio::test]
#[serial]
async fn test_concurrent_double_submission_commits_exactly_once() {
    let ceremony = Ceremony::prepare().await;
    let request = ceremony.request();

    let (first, second) = tokio::join!(ceremony.send(request.clone()), ceremony.send(request));

    let (winner, loser) = if first.status() == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    let winner_body = assert_accepted(winner).await;
    assert!(winner_body["factorId"].is_string());

    let (loser_status, loser_code) = rejection(loser).await;
    assert!(
        matches!(
            (loser_status.as_u16(), loser_code.as_str()),
            (400, "already_used") | (423, "conflicting_lock")
        ),
        "the losing request must fail with already_used or conflicting_lock, got {loser_status} {loser_code}"
    );

    let redis = get_test_redis_cache_manager().await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::ALL);
    assert_eq!(ceremony.persisted_new_factor_count().await, 1);
}

// 2. Another writer holds the new factor's mutate lock: the request is rejected before the commit,
//    so nothing is consumed and the very same request succeeds once the lock is gone.
#[tokio::test]
#[serial]
async fn test_lock_contention_consumes_nothing_and_same_request_succeeds_after_release() {
    let ceremony = Ceremony::prepare().await;
    let request = ceremony.request();
    let redis = get_test_redis_cache_manager().await;

    let mut held_lock = redis
        .try_acquire_lock_guard(
            FACTOR_LOOKUP_MUTATE_LOCK_PREFIX,
            ceremony.new_factor_lock_id(),
            Some(30),
        )
        .await
        .unwrap();

    let response = ceremony.send(request.clone()).await;
    assert_rejected(response, StatusCode::LOCKED, "conflicting_lock").await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::NONE);
    assert_eq!(ceremony.persisted_new_factor_count().await, 0);

    held_lock.release().await.unwrap();

    assert_accepted(ceremony.send(request).await).await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::ALL);
    assert_eq!(ceremony.persisted_new_factor_count().await, 1);
}

// 3. After a success, the identical request is a replay; and a brand-new challenge pair that
//    reuses the (already burned) new-factor ID token fails as a whole, leaving the fresh
//    challenge tokens and the fresh existing-factor nonce unconsumed.
#[tokio::test]
#[serial]
async fn test_replay_after_success_is_rejected_without_consuming_fresh_values() {
    let mut ceremony = Ceremony::prepare().await;
    let redis = get_test_redis_cache_manager().await;
    let request = ceremony.request();

    assert_accepted(ceremony.send(request.clone()).await).await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::ALL);

    assert_rejected(
        ceremony.send(request).await,
        StatusCode::BAD_REQUEST,
        "already_used",
    )
    .await;
    assert_eq!(ceremony.persisted_new_factor_count().await, 1);

    ceremony.reissue_challenges().await;
    assert_eq!(consumed(&redis, &ceremony).await, [SingleUse::NewNonce]);

    assert_rejected(
        ceremony.send(ceremony.request()).await,
        StatusCode::BAD_REQUEST,
        "already_used",
    )
    .await;
    assert_eq!(consumed(&redis, &ceremony).await, [SingleUse::NewNonce]);
    assert_eq!(ceremony.persisted_new_factor_count().await, 1);
}

// 4. The new factor fails verification (well-formed signature by the right key over the wrong
//    bytes): the existing factor's approval is not spent, so the same tokens succeed once the new
//    signature is corrected. Before the restructuring, this rejection cost the user their
//    existing-factor challenge and nonce.
#[tokio::test]
#[serial]
async fn test_new_factor_signature_failure_consumes_nothing() {
    let ceremony = Ceremony::prepare().await;
    let redis = get_test_redis_cache_manager().await;

    let wrong_new_signature =
        sign_keypair_challenge(&ceremony.new.secret_key, ceremony.existing_challenge());
    let response = ceremony
        .send(ceremony.request_with(&ceremony.existing_signature(), &wrong_new_signature))
        .await;
    assert_rejected(
        response,
        StatusCode::BAD_REQUEST,
        "signature_verification_error",
    )
    .await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::NONE);
    assert_eq!(ceremony.persisted_new_factor_count().await, 0);

    assert_accepted(ceremony.send(ceremony.request()).await).await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::ALL);
    assert_eq!(ceremony.persisted_new_factor_count().await, 1);
}

// 5. The existing factor fails verification (well-formed signature by the wrong key), after the
//    new factor was already verified: still nothing on either side is consumed, and the same
//    tokens succeed with the right signature.
#[tokio::test]
#[serial]
async fn test_existing_factor_signature_failure_consumes_nothing() {
    let ceremony = Ceremony::prepare().await;
    let redis = get_test_redis_cache_manager().await;

    let (_, wrong_key) = generate_keypair();
    let wrong_existing_signature =
        sign_keypair_challenge(&wrong_key, ceremony.existing_challenge());
    let response = ceremony
        .send(ceremony.request_with(&wrong_existing_signature, &ceremony.new_signature()))
        .await;
    assert_rejected(
        response,
        StatusCode::BAD_REQUEST,
        "signature_verification_error",
    )
    .await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::NONE);
    assert_eq!(ceremony.persisted_new_factor_count().await, 0);

    assert_accepted(ceremony.send(ceremony.request()).await).await;
    assert_eq!(consumed(&redis, &ceremony).await, SingleUse::ALL);
    assert_eq!(ceremony.persisted_new_factor_count().await, 1);
}
