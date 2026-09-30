mod common;

use std::sync::Arc;

use crate::common::{
    create_test_backup, create_test_backup_with_keypair, create_test_backup_with_sync_keypair,
    generate_keypair, get_keypair_retrieval_challenge, get_passkey_retrieval_challenge,
    send_post_request, send_post_request_with_bypass_attestation_token,
    send_post_request_with_multipart, sign_keypair_challenge, verify_s3_backup_exists,
    verify_s3_metadata_exists,
};
use aws_sdk_s3::primitives::ByteStream;
use axum::http::StatusCode;
use axum::{body::Bytes, response::Response};
use backup_service::backup_metadata::{BackupMetadata, Factor, FactorKind};
use backup_service::backup_storage::BackupStorage;
use backup_service::environment::Environment;
use backup_service::factor_lookup::{FactorLookup, FactorToLookup};
use backup_service_test_utils::{authenticate_with_passkey_challenge, get_mock_passkey_client};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use mockito::{Matcher, Server};
use serde_json::{json, Value};
use serial_test::serial;
use types::FactorScope;

#[tokio::test]
#[allow(clippy::too_many_lines)] // end-to-end test
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

// SECTION: Sync factor replacement and recovery retries

async fn parsed(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    (status, common::parse_response_body(response).await)
}

async fn ok(response: Response) -> Value {
    let (status, body) = parsed(response).await;
    assert!(status.is_success(), "{status}: {body}");
    body
}

struct Fixture {
    main: (String, p256::SecretKey),
    keys: Vec<(String, p256::SecretKey)>,
    metadata: BackupMetadata,
    lookup: FactorLookup,
}

async fn fixture(count: usize) -> Fixture {
    let (main, response, initial_secret) =
        common::create_test_backup_with_sync_keypair(b"preserve this vault").await;
    let created = ok(response).await;
    let id = created["backupMetadata"]["id"].as_str().unwrap();
    let mut metadata: BackupMetadata =
        serde_json::from_value(common::verify_s3_metadata_exists(id).await).unwrap();
    let FactorKind::EcKeypair { public_key } = &metadata.sync_factors[0].kind else {
        panic!("expected initial sync key");
    };
    let mut keys = vec![(public_key.clone(), initial_secret)];
    let environment = Environment::development(None);
    let lookup = FactorLookup::new(
        environment,
        Arc::new(aws_sdk_dynamodb::Client::new(
            &environment.aws_config().await,
        )),
    );
    for _ in 1..count {
        let key = common::generate_keypair();
        let factor = Factor::new_ec_keypair(key.0.clone());
        lookup
            .insert(
                FactorScope::Sync,
                &factor.as_factor_to_lookup(&environment),
                id.to_string(),
            )
            .await
            .unwrap();
        metadata.sync_factors.push(factor);
        keys.push(key);
    }
    common::get_test_s3_client()
        .await
        .put_object()
        .bucket(environment.s3_bucket())
        .key(format!("{id}/metadata"))
        .body(ByteStream::from(serde_json::to_vec(&metadata).unwrap()))
        .send()
        .await
        .unwrap();
    Fixture {
        main,
        keys,
        metadata,
        lookup,
    }
}

async fn recover(key: &(String, p256::SecretKey)) -> Response {
    let challenge = common::get_keypair_retrieval_challenge().await;
    common::send_post_request_with_bypass_attestation_token("/v1/retrieve/from-challenge", json!({
        "authorization": {"kind":"EC_KEYPAIR", "publicKey":key.0,
            "signature":common::sign_keypair_challenge(&key.1, challenge["challenge"].as_str().unwrap())},
        "challengeToken":challenge["token"]
    }), None).await
}

async fn register(
    recovered: &Value,
    key: &(String, p256::SecretKey),
    target: Option<&str>,
) -> Response {
    let challenge =
        ok(common::send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await)
            .await;
    let mut request = json!({
        "challengeToken":challenge["token"], "syncFactorToken":recovered["syncFactorToken"],
        "syncFactor":{"kind":"EC_KEYPAIR", "publicKey":key.0,
            "signature":common::sign_keypair_challenge(&key.1, challenge["challenge"].as_str().unwrap())}
    });
    if let Some(target) = target {
        request["syncFactorToReplace"] = json!(target);
    }
    common::send_post_request("/v1/add-sync-factor", request).await
}

async fn sync_metadata(key: &(String, p256::SecretKey)) -> Response {
    let challenge =
        ok(common::send_post_request("/v1/retrieve-metadata/challenge/keypair", json!({})).await)
            .await;
    common::send_post_request("/v1/retrieve-metadata", json!({
        "authorization":{"kind":"EC_KEYPAIR", "publicKey":key.0,
            "signature":common::sign_keypair_challenge(&key.1, challenge["challenge"].as_str().unwrap())},
        "challengeToken":challenge["token"]
    })).await
}

async fn stored(id: &str) -> BackupMetadata {
    serde_json::from_value(common::verify_s3_metadata_exists(id).await).unwrap()
}

#[tokio::test]
async fn replacement_preserves_other_records_below_at_and_above_cap() {
    for count in [3, 25, 26] {
        let fixture = fixture(count).await;
        let id = &fixture.metadata.id;
        let new = common::generate_keypair();
        let target = &fixture.metadata.sync_factors[1];
        if count >= 25 {
            for absent in [
                None,
                Some("nonexistent"),
                Some(&*fixture.metadata.factors[0].id),
            ] {
                let recovered = ok(recover(&fixture.main).await).await;
                let (status, body) = parsed(register(&recovered, &new, absent).await).await;
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(body["error"]["code"], "too_many_factors");
            }
            assert_eq!(stored(id).await, fixture.metadata);
        }

        let recovered = ok(recover(&fixture.main).await).await;
        ok(register(&recovered, &new, Some(&target.id)).await).await;
        let after = stored(id).await;
        assert_eq!(after.sync_factors.len(), count);
        for (index, factor) in fixture.metadata.sync_factors.iter().enumerate() {
            assert_eq!(after.sync_factors[index] == *factor, index != 1);
        }
        assert_eq!(after.factors, fixture.metadata.factors);
        assert_eq!(after.keys, fixture.metadata.keys);
        assert_eq!(after.manifest_hash, fixture.metadata.manifest_hash);
        assert_eq!(
            fixture
                .lookup
                .lookup_consistent(
                    FactorScope::Sync,
                    &FactorToLookup::from_ec_keypair(fixture.keys[1].0.clone()),
                )
                .await
                .unwrap(),
            None
        );
        assert!(!sync_metadata(&fixture.keys[1]).await.status().is_success());
        ok(sync_metadata(&fixture.keys[0]).await).await;
        ok(sync_metadata(&new).await).await;
        let fresh = ok(recover(&fixture.main).await).await;
        assert_eq!(fresh["backup"], recovered["backup"]);

        let (status, body) =
            parsed(register(&fresh, &new, Some(&fixture.metadata.sync_factors[0].id)).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "factor_already_exists");
        assert_eq!(stored(id).await, after);

        if count < 25 {
            let added = common::generate_keypair();
            let recovered = ok(recover(&fixture.main).await).await;
            ok(register(&recovered, &added, Some(&target.id)).await).await;
            let after_add = stored(id).await;
            assert_eq!(after_add.sync_factors.len(), count + 1);
            assert_eq!(after_add.sync_factors[..count], after.sync_factors[..]);
            ok(sync_metadata(&added).await).await;
        }
    }
}

#[tokio::test]
async fn concurrent_replacements_never_exceed_cap_or_revoke_on_failure() {
    for different_targets in [false, true] {
        let fixture = fixture(25).await;
        let a = ok(recover(&fixture.main).await).await;
        let b = ok(recover(&fixture.main).await).await;
        let target_a = &fixture.metadata.sync_factors[0].id;
        let target_b = &fixture.metadata.sync_factors[usize::from(different_targets)].id;
        let (key_a, key_b) = (common::generate_keypair(), common::generate_keypair());
        let (a, b) = tokio::join!(
            register(&a, &key_a, Some(target_a)),
            register(&b, &key_b, Some(target_b))
        );
        let successes = usize::from(a.status().is_success()) + usize::from(b.status().is_success());
        assert!(successes >= 1);
        if !different_targets {
            assert_eq!(successes, 1);
        }
        let after = stored(&fixture.metadata.id).await;
        assert_eq!(after.sync_factors.len(), 25);
        assert_eq!(
            fixture
                .metadata
                .sync_factors
                .iter()
                .filter(|f| !after.sync_factors.contains(f))
                .count(),
            successes
        );
    }
}

#[tokio::test]
async fn existing_lookup_reservation_and_registered_key_are_rejected() {
    let fixture = fixture(1).await;
    let new = common::generate_keypair();
    // Model a previous ambiguous metadata failure after the lookup was reserved.
    fixture
        .lookup
        .insert(
            FactorScope::Sync,
            &FactorToLookup::from_ec_keypair(new.0.clone()),
            fixture.metadata.id.clone(),
        )
        .await
        .unwrap();
    for key in [&new, &fixture.keys[0]] {
        let recovered = ok(recover(&fixture.main).await).await;
        let (status, body) = parsed(register(&recovered, key, None).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "factor_already_exists");
        assert_eq!(stored(&fixture.metadata.id).await, fixture.metadata);
        assert_eq!(
            fixture
                .lookup
                .lookup_consistent(
                    FactorScope::Sync,
                    &FactorToLookup::from_ec_keypair(key.0.clone()),
                )
                .await
                .unwrap(),
            Some(fixture.metadata.id.clone())
        );
    }
    ok(sync_metadata(&fixture.keys[0]).await).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Two store snapshots reproduce the auth/registration race.
async fn auth_cleanup_rereads_membership_and_changed_lookup_owner_under_lock() {
    use backup_service::{
        auth::{AuthError, AuthHandler},
        challenge_manager::ChallengeContext,
        oidc_token_verifier::OidcTokenVerifier,
        redis_cache::RedisCacheManager,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    for changed_owner in [false, true] {
        let key = common::generate_keypair();
        let challenge = ok(common::send_post_request(
            "/v1/retrieve-metadata/challenge/keypair",
            json!({}),
        )
        .await)
        .await;
        let mut server = Server::new_async().await;
        let current_owner = if changed_owner {
            "backup-b"
        } else {
            "backup-a"
        };
        let original = BackupMetadata {
            id: "backup-a".to_string(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: "hash".to_string(),
        };
        let current = BackupMetadata {
            id: current_owner.to_string(),
            sync_factors: vec![Factor::new_ec_keypair(key.0.clone())],
            ..original.clone()
        };
        let reads = AtomicUsize::new(0);
        let metadata = server
            .mock("GET", Matcher::Any)
            .with_header("etag", "version")
            .with_body_from_request(move |_| {
                serde_json::to_vec(if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    &original
                } else {
                    &current
                })
                .unwrap()
            })
            .expect(2)
            .create_async()
            .await;
        let initial_lookup = server
            .mock("POST", "/")
            .match_header("x-amz-target", "DynamoDB_20120810.GetItem")
            .match_body(Matcher::PartialJson(json!({"ConsistentRead":false})))
            .with_header("content-type", "application/x-amz-json-1.0")
            .with_body(json!({"Item":{"BackupId":{"S":"backup-a"}}}).to_string())
            .expect(1)
            .create_async()
            .await;
        let current_lookup = server
            .mock("POST", "/")
            .match_header("x-amz-target", "DynamoDB_20120810.GetItem")
            .match_body(Matcher::PartialJson(json!({"ConsistentRead":true})))
            .with_header("content-type", "application/x-amz-json-1.0")
            .with_body(json!({"Item":{"BackupId":{"S":current_owner}}}).to_string())
            .expect(1)
            .create_async()
            .await;
        let no_delete = server
            .mock("POST", "/")
            .match_header("x-amz-target", "DynamoDB_20120810.DeleteItem")
            .expect(0)
            .create_async()
            .await;
        let s3_config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(server.url())
            .force_path_style(true)
            .build();
        let dynamo_config = aws_sdk_dynamodb::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(server.url())
            .build();
        let environment = Environment::development(None);
        let redis = Arc::new(
            RedisCacheManager::new(environment, environment.cache_default_ttl())
                .await
                .unwrap(),
        );
        let storage = Arc::new(BackupStorage::new(
            environment,
            Arc::new(aws_sdk_s3::Client::from_conf(s3_config)),
        ));
        let lookup = Arc::new(FactorLookup::new(
            environment,
            Arc::new(aws_sdk_dynamodb::Client::from_conf(dynamo_config)),
        ));
        let oidc = Arc::new(OidcTokenVerifier::new(environment, redis.clone()));
        let auth = AuthHandler::new(
            storage,
            redis,
            common::get_challenge_manager().await,
            environment,
            lookup,
            oidc,
        );
        let outcome = auth
            .verify(
                &types::Authorization::EcKeypair {
                    public_key: key.0,
                    signature: common::sign_keypair_challenge(
                        &key.1,
                        challenge["challenge"].as_str().unwrap(),
                    ),
                },
                FactorScope::Sync,
                ChallengeContext::RetrieveMetadata {},
                challenge["token"].as_str().unwrap().to_string(),
            )
            .await;
        assert!(matches!(outcome, Err(AuthError::UnauthorizedFactor)));
        metadata.assert_async().await;
        initial_lookup.assert_async().await;
        current_lookup.assert_async().await;
        no_delete.assert_async().await;
    }
}

#[tokio::test]
async fn ambiguous_lookup_insert_error_does_not_update_metadata() {
    use axum::body::Body;
    use tower::ServiceExt;

    let fixture = fixture(1).await;
    let key = common::generate_keypair();
    let recovered = ok(recover(&fixture.main).await).await;
    let environment = Environment::development(None);
    let mut server = Server::new_async().await;
    let insert = server
        .mock("POST", "/")
        .match_header("x-amz-target", "DynamoDB_20120810.PutItem")
        .with_status(500)
        .with_header("content-type", "application/x-amz-json-1.0")
        .with_body(r#"{"__type":"InternalServerError","message":"injected response loss"}"#)
        .expect(1)
        .create_async()
        .await;
    let read = server
        .mock("POST", "/")
        .match_header("x-amz-target", "DynamoDB_20120810.GetItem")
        .match_body(Matcher::PartialJson(json!({"ConsistentRead":true})))
        .with_header("content-type", "application/x-amz-json-1.0")
        .with_body(json!({"Item":{"BackupId":{"S":fixture.metadata.id}}}).to_string())
        .expect(0)
        .create_async()
        .await;
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
            "test", "test", None, None, "test",
        ))
        .endpoint_url(server.url())
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
        .build();
    let lookup = Arc::new(FactorLookup::new(
        environment,
        Arc::new(aws_sdk_dynamodb::Client::from_conf(config)),
    ));
    let challenge =
        ok(common::send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await)
            .await;
    let request = json!({"syncFactorToken":recovered["syncFactorToken"],"challengeToken":challenge["token"],
        "syncFactor":{"kind":"EC_KEYPAIR","publicKey":key.0,
            "signature":common::sign_keypair_challenge(&key.1,challenge["challenge"].as_str().unwrap())}});
    let app = registration_router(lookup).await;
    let response = app
        .oneshot(
            http::Request::builder()
                .method("POST")
                .uri("/v1/add-sync-factor")
                .header("content-type", "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = parsed(response).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal_server_error");
    assert_eq!(stored(&fixture.metadata.id).await, fixture.metadata);
    insert.assert_async().await;
    read.assert_async().await;
}

#[tokio::test]
async fn replacement_succeeds_when_old_lookup_delete_fails() {
    use axum::body::Body;
    use tower::ServiceExt;

    let fixture = fixture(1).await;
    let key = common::generate_keypair();
    let recovered = ok(recover(&fixture.main).await).await;
    let environment = Environment::development(None);
    let mut server = Server::new_async().await;
    let insert = server
        .mock("POST", "/")
        .match_header("x-amz-target", "DynamoDB_20120810.PutItem")
        .with_header("content-type", "application/x-amz-json-1.0")
        .with_body("{}")
        .expect(1)
        .create_async()
        .await;
    let read = server
        .mock("POST", "/")
        .match_header("x-amz-target", "DynamoDB_20120810.GetItem")
        .with_header("content-type", "application/x-amz-json-1.0")
        .with_body(json!({"Item":{"BackupId":{"S":fixture.metadata.id}}}).to_string())
        .expect(1)
        .create_async()
        .await;
    let delete = server
        .mock("POST", "/")
        .match_header("x-amz-target", "DynamoDB_20120810.DeleteItem")
        .with_status(500)
        .with_header("content-type", "application/x-amz-json-1.0")
        .with_body(r#"{"__type":"InternalServerError","message":"injected delete failure"}"#)
        .expect(1)
        .create_async()
        .await;
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
            "test", "test", None, None, "test",
        ))
        .endpoint_url(server.url())
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
        .build();
    let lookup = Arc::new(FactorLookup::new(
        environment,
        Arc::new(aws_sdk_dynamodb::Client::from_conf(config)),
    ));
    let challenge =
        ok(common::send_post_request("/v1/add-sync-factor/challenge/keypair", json!({})).await)
            .await;
    let request = json!({
        "syncFactorToken": recovered["syncFactorToken"], "challengeToken": challenge["token"],
        "syncFactorToReplace": fixture.metadata.sync_factors[0].id,
        "syncFactor": {"kind": "EC_KEYPAIR", "publicKey": key.0,
            "signature": common::sign_keypair_challenge(
                &key.1, challenge["challenge"].as_str().unwrap())}
    });
    ok(registration_router(lookup)
        .await
        .oneshot(
            http::Request::builder()
                .method("POST")
                .uri("/v1/add-sync-factor")
                .header("content-type", "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap())
    .await;
    let after = stored(&fixture.metadata.id).await;
    assert_eq!(after.sync_factors.len(), 1);
    assert_eq!(
        after.sync_factors[0].kind,
        Factor::new_ec_keypair(key.0).kind
    );
    assert_eq!(after.factors, fixture.metadata.factors);
    assert_eq!(after.keys, fixture.metadata.keys);
    assert_eq!(after.manifest_hash, fixture.metadata.manifest_hash);
    let (status, body) = parsed(sync_metadata(&fixture.keys[0]).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "unauthorized_factor");
    insert.assert_async().await;
    read.assert_async().await;
    delete.assert_async().await;
}

async fn registration_router(lookup: Arc<FactorLookup>) -> axum::Router {
    use axum::Extension;
    use backup_service::{
        auth::AuthHandler, oidc_token_verifier::OidcTokenVerifier, redis_cache::RedisCacheManager,
    };
    let environment = Environment::development(None);
    let storage = Arc::new(BackupStorage::new(
        environment,
        Arc::new(common::get_test_s3_client().await),
    ));
    let redis = Arc::new(
        RedisCacheManager::new(environment, environment.cache_default_ttl())
            .await
            .unwrap(),
    );
    let auth = AuthHandler::new(
        storage.clone(),
        redis.clone(),
        common::get_challenge_manager().await,
        environment,
        lookup.clone(),
        Arc::new(OidcTokenVerifier::new(environment, redis.clone())),
    );
    backup_service::routes::handler(environment)
        .finish_api(&mut Default::default())
        .layer(Extension(environment))
        .layer(Extension(storage))
        .layer(Extension(lookup))
        .layer(Extension(redis))
        .layer(Extension(auth))
}
