mod common;

use std::sync::Arc;

use crate::common::{
    create_test_backup, create_test_backup_with_keypair, create_test_backup_with_sync_keypair,
    generate_keypair, get_keypair_retrieval_challenge, get_passkey_retrieval_challenge,
    send_post_request, send_post_request_with_bypass_attestation_token,
    send_post_request_with_multipart, sign_keypair_challenge, verify_s3_backup_exists,
    verify_s3_metadata_exists,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use backup_service::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use backup_service::types::Environment;
use backup_service_test_utils::{authenticate_with_passkey_challenge, get_mock_passkey_client};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use serial_test::serial;

#[tokio::test]
async fn test_add_sync_factor_happy_path() {
    let mut passkey_client = get_mock_passkey_client();

    // Create a backup first
    let (_credential, create_response) =
        create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);
    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_response: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
    let backup_id = create_response["backupMetadata"]["id"].as_str().unwrap();

    // Get a backup retrieval challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the retrieval challenge with the passkey
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    // Retrieve the backup to get a sync factor token
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": retrieve_credential,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
    )
    .await;

    assert_eq!(retrieve_response.status(), StatusCode::OK);
    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let retrieve_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let sync_factor_token = retrieve_response["syncFactorToken"].as_str().unwrap();

    // Get a challenge for adding a sync factor
    let sync_factor_challenge_response =
        send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await;

    assert_eq!(sync_factor_challenge_response.status(), StatusCode::OK);
    let challenge_body = sync_factor_challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();

    // Generate a new keypair and sign the challenge
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Add the sync factor
    let add_sync_factor_response = send_post_request(
        "/v1/add-sync-factor",
        json!({
            "challengeToken": challenge_response["token"],
            "syncFactor": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "syncFactorToken": sync_factor_token,
        }),
    )
    .await;

    assert_eq!(add_sync_factor_response.status(), StatusCode::OK);
    let body = add_sync_factor_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify the response contains the backup ID
    assert_eq!(response["backupId"], backup_id);

    // Verify the backup metadata was updated with the new sync factor
    let metadata = verify_s3_metadata_exists(backup_id).await;

    // Check that we now have both sync factors (initial + new one)
    let sync_factors = metadata["syncFactors"].as_array().unwrap();
    assert_eq!(sync_factors.len(), 2);

    // Verify the new sync factor is in the list
    let new_sync_factor_exists = sync_factors.iter().any(|factor| {
        factor["kind"]["kind"] == "EC_KEYPAIR" && factor["kind"]["publicKey"] == public_key
    });
    assert!(new_sync_factor_exists);

    // Try to use the same token again - should fail as tokens are one-time use
    let second_challenge_response =
        send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await;
    assert_eq!(second_challenge_response.status(), StatusCode::OK);
    let challenge_body = second_challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let second_challenge: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();

    let (another_public_key, another_secret_key) = generate_keypair();
    let another_signature = sign_keypair_challenge(
        &another_secret_key,
        second_challenge["challenge"].as_str().unwrap(),
    );
    let reuse_token_response = send_post_request(
        "/v1/add-sync-factor",
        json!({
            "challengeToken": second_challenge["token"],
            "syncFactor": {
                "kind": "EC_KEYPAIR",
                "publicKey": another_public_key,
                "signature": another_signature,
            },
            "syncFactorToken": sync_factor_token,  // Reusing the same token
        }),
    )
    .await;

    assert_eq!(reuse_token_response.status(), StatusCode::BAD_REQUEST);
    let error_body = reuse_token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "already_used"
    );

    // Now verify we can use the newly added sync factor to sync a backup
    // Get a sync challenge
    let sync_challenge_response = send_post_request("/v1/sync/challenge/keypair", json!({})).await;
    let sync_challenge_body = sync_challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let sync_challenge: serde_json::Value = serde_json::from_slice(&sync_challenge_body).unwrap();

    // Sign the challenge with our new sync factor's secret key
    let sync_signature =
        sign_keypair_challenge(&secret_key, sync_challenge["challenge"].as_str().unwrap());

    // Sync the backup with new content
    let sync_response = send_post_request_with_multipart(
        "/v1/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": sync_signature,
            },
            "challengeToken": sync_challenge["token"],
            "currentManifestHash": hex::encode([1u8; 32]), // this is the one created in the test create backup
            "newManifestHash": hex::encode([2u8; 32]),
        }),
        Bytes::from(b"UPDATED BACKUP DATA".as_slice()),
        None,
    )
    .await;

    assert_eq!(sync_response.status(), StatusCode::OK);
    let sync_body = sync_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let sync_response: serde_json::Value = serde_json::from_slice(&sync_body).unwrap();
    assert_eq!(sync_response["backupId"], backup_id);

    // Verify the backup was updated in S3
    verify_s3_backup_exists(backup_id, b"UPDATED BACKUP DATA").await;
}

#[tokio::test]
async fn test_add_sync_factor_with_invalid_token() {
    // Get a challenge for adding a sync factor
    let sync_factor_challenge_response =
        send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await;
    assert_eq!(sync_factor_challenge_response.status(), StatusCode::OK);
    let challenge_body = sync_factor_challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let challenge_response: serde_json::Value = serde_json::from_slice(&challenge_body).unwrap();

    // Generate a new keypair and sign the challenge
    let (public_key, secret_key) = generate_keypair();
    let signature = sign_keypair_challenge(
        &secret_key,
        challenge_response["challenge"].as_str().unwrap(),
    );

    // Try to add the sync factor with an invalid token
    let add_sync_factor_response = send_post_request(
        "/v1/add-sync-factor",
        json!({
            "challengeToken": challenge_response["token"],
            "syncFactor": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": signature,
            },
            "syncFactorToken": "INVALID_TOKEN_THAT_DOESNT_EXIST",
        }),
    )
    .await;

    assert_eq!(add_sync_factor_response.status(), StatusCode::BAD_REQUEST);
    let body = add_sync_factor_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        error_response["error"]["code"].as_str().unwrap(),
        "token_not_found"
    );
}

/// If a keypair is already a main factor, adding it as a sync factor must fail and roll back the
/// Sync `FactorLookup` insert + sync-factor token so the credential is not permanently blocked.
#[tokio::test]
#[serial]
async fn test_add_sync_factor_same_as_main_rolls_back_lookup_and_token() {
    dotenvy::from_filename(".env.example").ok();
    let environment = Environment::development(None);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let factor_lookup = FactorLookup::new(environment, dynamodb_client);

    let ((main_public_key, main_secret_key), create_response) =
        create_test_backup_with_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);
    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
    let backup_id = create_json["backupId"].as_str().unwrap();

    let main_factor = FactorToLookup::from_ec_keypair(main_public_key.clone());
    assert!(factor_lookup
        .lookup(FactorScope::Main, &main_factor)
        .await
        .unwrap()
        .is_some());
    assert!(factor_lookup
        .lookup(FactorScope::Sync, &main_factor)
        .await
        .unwrap()
        .is_none());

    // Retrieve with the main keypair to obtain a sync-factor token.
    let retrieve_challenge = get_keypair_retrieval_challenge().await;
    let retrieve_signature = sign_keypair_challenge(
        &main_secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": main_public_key,
                "signature": retrieve_signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
    )
    .await;
    assert_eq!(retrieve_response.status(), StatusCode::OK);
    let retrieve_body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let retrieve_json: serde_json::Value = serde_json::from_slice(&retrieve_body).unwrap();
    let sync_factor_token = retrieve_json["syncFactorToken"].as_str().unwrap();

    let metadata_before = verify_s3_metadata_exists(backup_id).await;
    let sync_count_before = metadata_before["syncFactors"].as_array().unwrap().len();

    // Attempt to register the main keypair as a sync factor (opposite scope).
    let sync_challenge_response =
        send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await;
    assert_eq!(sync_challenge_response.status(), StatusCode::OK);
    let sync_challenge_body = sync_challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let sync_challenge: serde_json::Value = serde_json::from_slice(&sync_challenge_body).unwrap();
    let sync_signature = sign_keypair_challenge(
        &main_secret_key,
        sync_challenge["challenge"].as_str().unwrap(),
    );

    let add_sync_response = send_post_request(
        "/v1/add-sync-factor",
        json!({
            "challengeToken": sync_challenge["token"],
            "syncFactor": {
                "kind": "EC_KEYPAIR",
                "publicKey": main_public_key,
                "signature": sync_signature,
            },
            "syncFactorToken": sync_factor_token,
        }),
    )
    .await;

    assert_eq!(add_sync_response.status(), StatusCode::BAD_REQUEST);
    let error_body = add_sync_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let error_json: serde_json::Value = serde_json::from_slice(&error_body).unwrap();
    assert_eq!(
        error_json["error"]["code"].as_str().unwrap(),
        "factor_already_exists"
    );

    // Sync lookup must have been rolled back; main lookup stays.
    assert!(factor_lookup
        .lookup(FactorScope::Main, &main_factor)
        .await
        .unwrap()
        .is_some());
    assert!(factor_lookup
        .lookup(FactorScope::Sync, &main_factor)
        .await
        .unwrap()
        .is_none());

    let metadata_after = verify_s3_metadata_exists(backup_id).await;
    assert_eq!(
        metadata_after["syncFactors"].as_array().unwrap().len(),
        sync_count_before
    );
    assert!(!metadata_after["syncFactors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|factor| {
            factor["kind"]["kind"] == "EC_KEYPAIR" && factor["kind"]["publicKey"] == main_public_key
        }));

    // Token must have been unused — a distinct sync factor can still be added with it.
    let retry_challenge_response =
        send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await;
    assert_eq!(retry_challenge_response.status(), StatusCode::OK);
    let retry_challenge_body = retry_challenge_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let retry_challenge: serde_json::Value = serde_json::from_slice(&retry_challenge_body).unwrap();
    let (other_public_key, other_secret_key) = generate_keypair();
    let other_signature = sign_keypair_challenge(
        &other_secret_key,
        retry_challenge["challenge"].as_str().unwrap(),
    );

    let retry_response = send_post_request(
        "/v1/add-sync-factor",
        json!({
            "challengeToken": retry_challenge["token"],
            "syncFactor": {
                "kind": "EC_KEYPAIR",
                "publicKey": other_public_key,
                "signature": other_signature,
            },
            "syncFactorToken": sync_factor_token,
        }),
    )
    .await;
    assert_eq!(
        retry_response.status(),
        StatusCode::OK,
        "sync token should be reusable after opposite-scope rejection"
    );

    let other_factor = FactorToLookup::from_ec_keypair(other_public_key.clone());
    assert!(factor_lookup
        .lookup(FactorScope::Sync, &other_factor)
        .await
        .unwrap()
        .is_some());
}

/// If the backup is deleted after a sync-factor token is issued, add-sync-factor must roll back the
/// Sync lookup and unuse the token so the credential is not pinned to a deleted backup.
#[tokio::test]
#[serial]
async fn test_add_sync_factor_after_backup_deleted_rolls_back_lookup_and_token() {
    dotenvy::from_filename(".env.example").ok();
    let environment = Environment::development(None);
    let dynamodb_client = Arc::new(aws_sdk_dynamodb::Client::new(
        &environment.aws_config().await,
    ));
    let factor_lookup = FactorLookup::new(environment, dynamodb_client);

    let ((main_public_key, main_secret_key), create_response, sync_secret_key) =
        create_test_backup_with_sync_keypair(b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);
    let create_body = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
    let backup_id = create_json["backupId"].as_str().unwrap();

    // Issue a sync-factor token while the backup still exists.
    let retrieve_challenge = get_keypair_retrieval_challenge().await;
    let retrieve_signature = sign_keypair_challenge(
        &main_secret_key,
        retrieve_challenge["challenge"].as_str().unwrap(),
    );
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": main_public_key,
                "signature": retrieve_signature,
            },
            "challengeToken": retrieve_challenge["token"],
        }),
        None,
    )
    .await;
    assert_eq!(retrieve_response.status(), StatusCode::OK);
    let retrieve_body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let retrieve_json: serde_json::Value = serde_json::from_slice(&retrieve_body).unwrap();
    let sync_factor_token = retrieve_json["syncFactorToken"].as_str().unwrap();

    // Concurrent delete: remove the backup before add-sync-factor writes metadata.
    let existing_sync_public_key = STANDARD.encode(sync_secret_key.public_key().to_sec1_bytes());
    let delete_challenge =
        send_post_request("/v1/delete-backup/challenge/keypair", json!({})).await;
    assert_eq!(delete_challenge.status(), StatusCode::OK);
    let delete_challenge_body = delete_challenge
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let delete_challenge_json: serde_json::Value =
        serde_json::from_slice(&delete_challenge_body).unwrap();
    let delete_signature = sign_keypair_challenge(
        &sync_secret_key,
        delete_challenge_json["challenge"].as_str().unwrap(),
    );
    let delete_response = send_post_request(
        "/v1/delete-backup",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": existing_sync_public_key,
                "signature": delete_signature,
            },
            "challengeToken": delete_challenge_json["token"],
        }),
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let (new_public_key, new_secret_key) = generate_keypair();
    let new_factor = FactorToLookup::from_ec_keypair(new_public_key.clone());

    let attempt_add = |challenge_token: serde_json::Value,
                       signature: String,
                       public_key: String,
                       token: String| async move {
        send_post_request(
            "/v1/add-sync-factor",
            json!({
                "challengeToken": challenge_token["token"],
                "syncFactor": {
                    "kind": "EC_KEYPAIR",
                    "publicKey": public_key,
                    "signature": signature,
                },
                "syncFactorToken": token,
            }),
        )
        .await
    };

    let challenge_1 = send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await;
    assert_eq!(challenge_1.status(), StatusCode::OK);
    let challenge_1_body = challenge_1.into_body().collect().await.unwrap().to_bytes();
    let challenge_1_json: serde_json::Value = serde_json::from_slice(&challenge_1_body).unwrap();
    let signature_1 = sign_keypair_challenge(
        &new_secret_key,
        challenge_1_json["challenge"].as_str().unwrap(),
    );

    let response_1 = attempt_add(
        challenge_1_json,
        signature_1,
        new_public_key.clone(),
        sync_factor_token.to_string(),
    )
    .await;
    assert_eq!(response_1.status(), StatusCode::BAD_REQUEST);
    let error_1: serde_json::Value =
        serde_json::from_slice(&response_1.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        error_1["error"]["code"].as_str().unwrap(),
        "backup_not_found"
    );

    // Lookup must have been rolled back — otherwise the retry hits factor_already_exists.
    assert!(factor_lookup
        .lookup(FactorScope::Sync, &new_factor)
        .await
        .unwrap()
        .is_none());

    let challenge_2 = send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await;
    assert_eq!(challenge_2.status(), StatusCode::OK);
    let challenge_2_body = challenge_2.into_body().collect().await.unwrap().to_bytes();
    let challenge_2_json: serde_json::Value = serde_json::from_slice(&challenge_2_body).unwrap();
    let signature_2 = sign_keypair_challenge(
        &new_secret_key,
        challenge_2_json["challenge"].as_str().unwrap(),
    );

    let response_2 = attempt_add(
        challenge_2_json,
        signature_2,
        new_public_key.clone(),
        sync_factor_token.to_string(),
    )
    .await;
    assert_eq!(response_2.status(), StatusCode::BAD_REQUEST);
    let error_2: serde_json::Value =
        serde_json::from_slice(&response_2.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        error_2["error"]["code"].as_str().unwrap(),
        "backup_not_found",
        "retry must see backup_not_found again (lookup+token rolled back), not factor_already_exists / already_used; backup_id={backup_id}"
    );
    assert!(factor_lookup
        .lookup(FactorScope::Sync, &new_factor)
        .await
        .unwrap()
        .is_none());
}
