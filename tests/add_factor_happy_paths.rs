mod common;

use crate::common::{
    add_factor_payload_for_oidc_new, add_factor_payload_for_passkey_new, create_test_backup,
    create_test_backup_with_oidc_account, create_turnkey_activity_and_hash,
    get_add_factor_challenges_generic, get_passkey_retrieval_challenge,
    get_test_redis_cache_manager, oidc_nonce_from_jwt, parse_response_body,
    send_post_request_with_environment, verify_s3_metadata_exists,
};
use axum::http::StatusCode;
use backup_service_test_utils::{
    get_mock_passkey_client, make_credential_from_passkey_challenge, registered_passkey_material,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

// OIDC (existing) → Passkey (new)
#[tokio::test]
#[serial]
async fn test_add_factor_oidc_existing_to_passkey_new_happy_path() {
    // Create a backup with an OIDC account
    let subject = format!("subject-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);

    // Request challenges for adding a new Passkey with existing OIDC
    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "PASSKEY_REGISTRATION",
            "platform": "IOS"
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    // Complete passkey registration from challenge
    let mut passkey_client = get_mock_passkey_client();
    let registration_state = challenges["newFactorChallenge"].clone();
    let registration_payload = json!({ "challenge": registration_state });
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &registration_payload).await;
    let (new_credential_id, new_public_key_sec1) = registered_passkey_material(&passkey_client);

    // Use a fresh session keypair and OIDC token for existing-factor auth to avoid nonce replay
    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let fresh_existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject.clone())),
        &existing_session_public_key,
    );
    // The existing factor signs `existingFactorChallenge || SHA256(tag || new_factor_material)`:
    // the new passkey (credential id, public key and the verbatim registration response bytes)
    // plus the request's label, turnkeyProviderId (absent) and encryptedBackupKey (null), exactly
    // as sent below.
    let existing_payload = add_factor_payload_for_passkey_new(
        &challenges,
        &credential,
        &new_public_key_sec1,
        "Test Passkey",
        None,
        &json!(null),
    );
    let existing_sig =
        crate::common::sign_keypair_challenge(&existing_session_secret_key, &existing_payload);

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": fresh_existing_oidc_token },
                "publicKey": existing_session_public_key,
                "signature": existing_sig
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "PASSKEY",
                "credential": credential,
                "label": "Test Passkey"
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": null
        }),
        Some(test.environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let add_factor_response = parse_response_body(response).await;
    let new_factor_id = add_factor_response["factorId"]
        .as_str()
        .unwrap()
        .to_string();
    // The exported metadata lists the new factor under the credential id the authenticator
    // registered.
    let expected_credential_id = URL_SAFE_NO_PAD.encode(&new_credential_id);
    let exported_factors = add_factor_response["backupMetadata"]["factors"]
        .as_array()
        .unwrap();
    assert!(
        exported_factors.iter().any(|f| f["id"] == new_factor_id
            && f["kind"]["kind"] == "PASSKEY"
            && f["kind"]["credentialId"] == expected_credential_id),
        "exported metadata lacks passkey factor {new_factor_id} for {expected_credential_id}: {add_factor_response}"
    );

    // Verify stored metadata now contains the new passkey factor
    let body = test
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response_json["backupId"].as_str().unwrap();

    let metadata = verify_s3_metadata_exists(backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    let passkey_found = factors
        .iter()
        .any(|f| f["id"].as_str().unwrap() == new_factor_id && f["kind"]["kind"] == "PASSKEY");
    assert!(
        passkey_found,
        "stored metadata lacks passkey factor {new_factor_id}: {metadata}"
    );

    // Validate we can retrieve with passkey now
    let retrieve_challenge = get_passkey_retrieval_challenge().await;
    let passkey_assertion = backup_service_test_utils::authenticate_with_passkey_challenge(
        &mut passkey_client,
        &retrieve_challenge,
    )
    .await;
    let retrieve_response = crate::common::send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({
            "authorization": { "kind": "PASSKEY", "credential": passkey_assertion },
            "challengeToken": retrieve_challenge["token"],
        }),
        Some(test.environment),
    )
    .await;
    assert_eq!(retrieve_response.status(), StatusCode::OK);
}

// Passkey (existing) → OIDC (new) regression of the classic path
#[tokio::test]
#[serial]
async fn test_add_factor_passkey_existing_to_oidc_new_happy_path() {
    let mut passkey_client = get_mock_passkey_client();
    let (_cred, create_response) = create_test_backup(&mut passkey_client, b"BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);
    let body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_json["backupId"].as_str().unwrap();

    let oidc_server = backup_service_test_utils::MockOidcServer::new().await;
    let environment = backup_service::environment::Environment::development(Some(
        oidc_server.server.socket_address().port() as usize,
    ));
    let (session_public_key, session_secret_key) = crate::common::generate_keypair();
    let oidc_token = oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        None,
        &session_public_key,
    );

    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("PASSKEY"),
    )
    .await;

    let encrypted_backup_key = json!({
        "kind": "TURNKEY",
        "encryptedKey": "ENCRYPTED_KEY",
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
    });
    // The stamped Turnkey activity carries `existingFactorChallenge || SHA256(tag ||
    // new_factor_material)` as its metadata.challenge, covering the new OIDC token plus the
    // request's turnkeyProviderId and encryptedBackupKey.
    let existing_payload = add_factor_payload_for_oidc_new(
        &challenges,
        &oidc_token,
        Some("turnkey_provider_id"),
        &encrypted_backup_key,
    );
    let (turnkey_activity, challenge_hash) = create_turnkey_activity_and_hash(&existing_payload);
    let passkey_assertion =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash)
            .await;
    let new_signature = crate::common::sign_keypair_challenge(
        &session_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
                "publicKey": session_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": encrypted_backup_key,
        }),
        Some(environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = verify_s3_metadata_exists(backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    assert!(factors.iter().any(|f| f["kind"]["kind"] == "OIDC_ACCOUNT"));
}

// OIDC (existing) → OIDC (new, different subject)
#[tokio::test]
#[serial]
async fn test_add_factor_oidc_existing_to_oidc_new_happy_path() {
    let subject = format!("existing-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let body = test
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_json["backupId"].as_str().unwrap();

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let (new_session_public_key, new_session_secret_key) = crate::common::generate_keypair();

    let new_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(format!(
            "new-{}",
            Uuid::new_v4()
        ))),
        &new_session_public_key,
    );

    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new_oidc_token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    let existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_session_public_key,
    );
    let encrypted_backup_key = json!({
        "kind": "TURNKEY",
        "encryptedKey": "ENCRYPTED_KEY",
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
    });
    // Existing factor signs `existingFactorChallenge || SHA256(tag || new_factor_material)`.
    let existing_payload = add_factor_payload_for_oidc_new(
        &challenges,
        &new_oidc_token,
        Some("turnkey_provider_id"),
        &encrypted_backup_key,
    );
    let existing_sig =
        crate::common::sign_keypair_challenge(&existing_session_secret_key, &existing_payload);
    let new_sig = crate::common::sign_keypair_challenge(
        &new_session_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": existing_oidc_token },
                "publicKey": existing_session_public_key,
                "signature": existing_sig,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": new_oidc_token },
                "publicKey": new_session_public_key,
                "signature": new_sig,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": encrypted_backup_key,
        }),
        Some(test.environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let add_resp = parse_response_body(response).await;
    assert!(add_resp["backupMetadata"].is_object());

    let metadata = verify_s3_metadata_exists(backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    let oidc_count = factors
        .iter()
        .filter(|f| f["kind"]["kind"] == "OIDC_ACCOUNT")
        .count();
    assert_eq!(oidc_count, 2);
}

// Same OIDC account again with a new TURNKEY wrapped key (metadata-only upgrade)
#[tokio::test]
#[serial]
async fn test_add_factor_same_oidc_metadata_only_turnkey_upgrade() {
    let subject = format!("same-oidc-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let body = test
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_json["backupId"].as_str().unwrap();

    let metadata_before = verify_s3_metadata_exists(backup_id).await;
    assert!(!metadata_before["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["kind"] == "TURNKEY"));

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let (new_session_public_key, new_session_secret_key) = crate::common::generate_keypair();

    let new_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject.clone())),
        &new_session_public_key,
    );

    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new_oidc_token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    let existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_session_public_key,
    );
    let encrypted_backup_key = json!({
        "kind": "TURNKEY",
        "encryptedKey": "ENCRYPTED_KEY",
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
    });
    // Existing factor signs `existingFactorChallenge || SHA256(tag || new_factor_material)`.
    let existing_payload = add_factor_payload_for_oidc_new(
        &challenges,
        &new_oidc_token,
        Some("turnkey_provider_id"),
        &encrypted_backup_key,
    );
    let existing_sig =
        crate::common::sign_keypair_challenge(&existing_session_secret_key, &existing_payload);
    let new_sig = crate::common::sign_keypair_challenge(
        &new_session_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": existing_oidc_token },
                "publicKey": existing_session_public_key,
                "signature": existing_sig,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": new_oidc_token },
                "publicKey": new_session_public_key,
                "signature": new_sig,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": encrypted_backup_key,
        }),
        Some(test.environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = verify_s3_metadata_exists(backup_id).await;
    let keys = metadata["keys"].as_array().unwrap();
    assert!(keys.iter().any(|k| k["kind"] == "TURNKEY"));
    // Factor list should still be a single OIDC account (no duplicate factor row).
    let oidc_count = metadata["factors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"]["kind"] == "OIDC_ACCOUNT")
        .count();
    assert_eq!(oidc_count, 1);
}

// Same-account Turnkey upgrade with one OIDC ID token + session keypair for both sides.
#[tokio::test]
#[serial]
async fn test_add_factor_same_oidc_single_session_metadata_only_upgrade() {
    let subject = format!("same-oidc-one-session-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let body = test
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_json["backupId"].as_str().unwrap();

    let (session_public_key, session_secret_key) = crate::common::generate_keypair();
    let oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &session_public_key,
    );

    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": oidc_token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    let encrypted_backup_key = json!({
        "kind": "TURNKEY",
        "encryptedKey": "ENCRYPTED_KEY",
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
    });
    // The one session keypair signs `existingFactorChallenge || SHA256(tag || new_factor_material)`
    // on the existing side; the new-factor material is that same ID token.
    let existing_payload = add_factor_payload_for_oidc_new(
        &challenges,
        &oidc_token,
        Some("turnkey_provider_id"),
        &encrypted_backup_key,
    );
    let existing_sig =
        crate::common::sign_keypair_challenge(&session_secret_key, &existing_payload);
    let new_sig = crate::common::sign_keypair_challenge(
        &session_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
                "publicKey": session_public_key,
                "signature": existing_sig,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
                "publicKey": session_public_key,
                "signature": new_sig,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": encrypted_backup_key,
        }),
        Some(test.environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    // One atomic commit consumed both challenge tokens and the single nonce shared by both sides.
    let redis = get_test_redis_cache_manager().await;
    assert!(
        redis
            .is_oidc_nonce_used(
                &oidc_nonce_from_jwt(&oidc_token),
                &types::OidcProvider::Google
            )
            .await
            .unwrap(),
        "the shared OIDC nonce should be consumed after a successful add-factor"
    );
    for token_field in ["existingFactorToken", "newFactorToken"] {
        assert!(
            redis
                .is_challenge_token_used(challenges[token_field].as_str().unwrap())
                .await
                .unwrap(),
            "{token_field} should be consumed after a successful add-factor"
        );
    }

    let metadata = verify_s3_metadata_exists(backup_id).await;
    assert!(metadata["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["kind"] == "TURNKEY"));
    let oidc_count = metadata["factors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"]["kind"] == "OIDC_ACCOUNT")
        .count();
    assert_eq!(oidc_count, 1);
}

// Same OIDC account with a different Turnkey provider id must not create a duplicate factor.
#[tokio::test]
#[serial]
async fn test_add_factor_same_oidc_different_turnkey_provider_id_is_duplicate() {
    let subject = format!("same-oidc-tpid-{}", Uuid::new_v4());
    let test = create_test_backup_with_oidc_account(&subject, b"BACKUP DATA").await;
    assert_eq!(test.response.status(), StatusCode::OK);
    let body = test
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_json["backupId"].as_str().unwrap();

    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let (new_session_public_key, new_session_secret_key) = crate::common::generate_keypair();

    let new_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject.clone())),
        &new_session_public_key,
    );

    let challenges = get_add_factor_challenges_generic(
        json!({ "kind": "OIDC_ACCOUNT", "oidcToken": new_oidc_token }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    let existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &existing_session_public_key,
    );
    let encrypted_backup_key = json!({
        "kind": "TURNKEY",
        "encryptedKey": "ENCRYPTED_KEY",
        "turnkeyAccountId": "org123",
        "turnkeyUserId": "TURNKEY_USER_ID",
        "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
    });
    // Existing factor signs `existingFactorChallenge || SHA256(tag || new_factor_material)`; the
    // material commits to the turnkeyProviderId exactly as sent, i.e. the different one below.
    let existing_payload = add_factor_payload_for_oidc_new(
        &challenges,
        &new_oidc_token,
        Some("a-different-turnkey-provider-id"),
        &encrypted_backup_key,
    );
    let existing_sig =
        crate::common::sign_keypair_challenge(&existing_session_secret_key, &existing_payload);
    let new_sig = crate::common::sign_keypair_challenge(
        &new_session_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": existing_oidc_token },
                "publicKey": existing_session_public_key,
                "signature": existing_sig,
            },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": new_oidc_token },
                "publicKey": new_session_public_key,
                "signature": new_sig,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            // Different from create's "turnkey_provider_id" — must still be treated as the same factor.
            "turnkeyProviderId": "a-different-turnkey-provider-id",
            "encryptedBackupKey": encrypted_backup_key,
        }),
        Some(test.environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = verify_s3_metadata_exists(backup_id).await;
    let oidc_count = metadata["factors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"]["kind"] == "OIDC_ACCOUNT")
        .count();
    assert_eq!(oidc_count, 1);
    assert!(metadata["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["kind"] == "TURNKEY"));
    // Original Turnkey provider id is preserved (no duplicate row / no overwrite).
    let provider_ids: Vec<_> = metadata["factors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"]["kind"] == "OIDC_ACCOUNT")
        .map(|f| f["kind"]["turnkeyProviderId"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(provider_ids, vec!["turnkey_provider_id".to_string()]);
}
