mod common;

use crate::common::{
    authenticate_with_passkey_challenge, create_test_backup, generate_keypair,
    get_passkey_retrieval_challenge, send_post_request,
    send_post_request_with_bypass_attestation_token, send_post_request_with_multipart,
    sign_keypair_challenge, verify_s3_backup_exists, verify_s3_metadata_exists,
};
use axum::body::Bytes;
use axum::http::StatusCode;
use backup_service_test_utils::get_mock_passkey_client;
use http_body_util::BodyExt;
use serde_json::json;

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
    let backup_id = create_response["backupId"].as_str().unwrap();

    // Get a backup retrieval challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the retrieval challenge with the passkey
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    // Retrieve the backup to get a sync factor token
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/retrieve/from-challenge",
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
        send_post_request("/add-sync-factor/challenge/keypair", json!({})).await;

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
        "/add-sync-factor",
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
        send_post_request("/add-sync-factor/challenge/keypair", json!({})).await;
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
        "/add-sync-factor",
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
    let sync_challenge_response = send_post_request("/sync/challenge/keypair", json!({})).await;
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
        "/sync",
        json!({
            "authorization": {
                "kind": "EC_KEYPAIR",
                "publicKey": public_key,
                "signature": sync_signature,
            },
            "challengeToken": sync_challenge["token"],
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
        send_post_request("/add-sync-factor/challenge/keypair", json!({})).await;
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
        "/add-sync-factor",
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
        "sync_factor_token_not_found"
    );
}
