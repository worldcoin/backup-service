mod common;

use crate::common::{
    create_test_backup, create_test_backup_with_oidc_account, create_turnkey_activity_and_hash,
    get_add_factor_challenges_generic, get_passkey_retrieval_challenge, parse_response_body,
    send_post_request_with_environment, verify_s3_metadata_exists,
};
use axum::http::StatusCode;
use backup_service_test_utils::{get_mock_passkey_client, make_credential_from_passkey_challenge};
use http_body_util::BodyExt;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

// Passkey (existing) → EC keypair (new)
#[tokio::test]
#[serial]
async fn test_add_factor_passkey_existing_to_ec_new_happy_path() {
    // Create a backup with a passkey
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

    // Request challenges for new EC keypair
    let challenges =
        get_add_factor_challenges_generic(json!({ "kind": "EC_KEYPAIR" }), Some("PASSKEY")).await;

    // Build Turnkey activity embedding existingFactorChallenge and get passkey assertion on its hash
    let (turnkey_activity, challenge_hash) =
        create_turnkey_activity_and_hash(challenges["existingFactorChallenge"].as_str().unwrap());
    let passkey_assertion =
        backup_service_test_utils::get_passkey_assertion(&mut passkey_client, &challenge_hash)
            .await;

    // Generate new EC keypair and sign the new-factor challenge
    let (new_public_key, new_secret_key) = crate::common::generate_keypair();
    let new_signature = crate::common::sign_keypair_challenge(
        &new_secret_key,
        challenges["newFactorChallenge"].as_str().unwrap(),
    );

    // Submit add-factor
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": { "kind": "PASSKEY", "credential": passkey_assertion },
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "existingFactorTurnkeyActivity": turnkey_activity,
            "newFactorAuthorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": new_public_key,
                "signature": new_signature,
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "encryptedBackupKey": {
                "kind": "TURNKEY",
                "encryptedKey": "ENCRYPTED_KEY",
                "turnkeyAccountId": "org123",
                "turnkeyUserId": "TURNKEY_USER_ID",
                "turnkeyPrivateKeyId": "TURNKEY_PRIVATE_KEY_ID"
            }
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let _json = parse_response_body(response).await;

    let metadata = verify_s3_metadata_exists(backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    let ec_found = factors.iter().any(|f| f["kind"]["kind"] == "EC_KEYPAIR");
    assert!(ec_found);
}

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
            "kind": "PASSKEY_REGISTRATION"
        }),
        Some("OIDC_ACCOUNT"),
    )
    .await;

    // Complete passkey registration from challeng
    let mut passkey_client = get_mock_passkey_client();
    let registration_state = challenges["newFactorChallenge"].clone();
    let registration_payload = json!({ "challenge": registration_state });
    let credential =
        make_credential_from_passkey_challenge(&mut passkey_client, &registration_payload).await;

    // Use a fresh session keypair and OIDC token for existing-factor auth to avoid nonce replay
    let (existing_session_public_key, existing_session_secret_key) =
        crate::common::generate_keypair();
    let fresh_existing_oidc_token = test.oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject.clone())),
        &existing_session_public_key,
    );
    let existing_sig = crate::common::sign_keypair_challenge(
        &existing_session_secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );

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
        Some(test.environment.clone()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let add_factor_response = parse_response_body(response).await;
    let new_factor_id = add_factor_response["factorId"]
        .as_str()
        .unwrap()
        .to_string();

    // Verify metadata now contains the new passkey factor
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
    assert!(passkey_found);

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

// EC keypair (existing) → OIDC (new)
#[tokio::test]
#[serial]
async fn test_add_factor_ec_existing_to_oidc_new_happy_path() {
    // Create a backup with EC keypair
    let ((existing_public_key, existing_secret_key), create_response) =
        crate::common::create_test_backup_with_keypair(b"BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Extract backup ID
    let body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backup_id = create_response_json["backupId"]
        .as_str()
        .unwrap()
        .to_string();

    // Setup OIDC server and generate token for a session keypair
    let oidc_server = backup_service_test_utils::MockOidcServer::new().await;
    let environment = backup_service::types::Environment::development(Some(
        oidc_server.server.socket_address().port() as usize,
    ));

    let (session_public_key, session_secret_key) = crate::common::generate_keypair();
    let subject = format!("subject-{}", Uuid::new_v4());
    let oidc_token = oidc_server.generate_token(
        &backup_service_test_utils::MockOidcProvider::Google,
        Some(openidconnect::SubjectIdentifier::new(subject)),
        &session_public_key,
    );

    // Request challenges with existing EC, new OIDC
    let challenges = get_add_factor_challenges_generic(
        json!({
            "kind": "OIDC_ACCOUNT",
            "oidcToken": oidc_token,
        }),
        Some("EC_KEYPAIR"),
    )
    .await;

    // Sign the existing-factor challenge with the existing EC factor's secret key
    let existing_authorization = json!({
        "kind": "EC_KEYPAIR",
        "publicKey": existing_public_key,
        "signature": crate::common::sign_keypair_challenge(&existing_secret_key, challenges["existingFactorChallenge"].as_str().unwrap()),
    });

    // Submit add-factor (new OIDC requires turnkeyProviderId)
    let response = send_post_request_with_environment(
        "/v1/add-factor",
        json!({
            "existingFactorAuthorization": existing_authorization,
            "existingFactorChallengeToken": challenges["existingFactorToken"],
            "newFactorAuthorization": {
                "kind": "OIDC_ACCOUNT",
                "oidcToken": { "kind": "GOOGLE", "token": oidc_token },
                "publicKey": session_public_key,
                "signature": crate::common::sign_keypair_challenge(&session_secret_key, challenges["newFactorChallenge"].as_str().unwrap()),
            },
            "newFactorChallengeToken": challenges["newFactorToken"],
            "turnkeyProviderId": "turnkey_provider_id",
            "encryptedBackupKey": null
        }),
        Some(environment),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    // Verify metadata now contains OIDC factor
    let metadata = verify_s3_metadata_exists(&backup_id).await;
    let factors = metadata["factors"].as_array().unwrap();
    let oidc_found = factors.iter().any(|f| f["kind"]["kind"] == "OIDC_ACCOUNT");
    assert!(oidc_found);
}
