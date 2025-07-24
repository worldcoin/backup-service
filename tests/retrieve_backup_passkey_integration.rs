mod common;

use crate::common::{
    create_test_backup, generate_test_attestation_token, get_passkey_challenge,
    get_passkey_retrieval_challenge, get_test_router,
    send_post_request_with_bypass_attestation_token,
};
use axum::{extract::Request, http::StatusCode};
use backup_service::attestation_gateway::ATTESTATION_GATEWAY_HEADER;
use backup_service_test_utils::{
    authenticate_with_passkey_challenge, get_mock_passkey_client,
    make_credential_from_passkey_challenge,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use josekit::jwk::JwkSet;
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_retrieve_backup() {
    let mut passkey_client = get_mock_passkey_client();

    // Create a backup
    let (_, create_response) = create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a new challenge for retrieving the backup
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the same credential
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    let body = json!({
        "authorization": {
            "kind": "PASSKEY",
            "credential": retrieve_credential,
        },
        "challengeToken": retrieve_challenge["token"],
    });

    // Section: Attestation Gateway Token + Validation
    let (jwk, jwt) = generate_test_attestation_token(&body, "/retrieve/from-challenge");
    let mut server = mockito::Server::new_async().await;
    let mut key_response =
        json!({ "keys": [serde_json::to_value(jwk.to_public_key().unwrap()).unwrap()] });
    key_response["keys"][0]["kid"] = json!("integration-test-kid");

    server
        .mock("GET", "/.well-known/jwks.json")
        .with_status(200)
        .with_body(key_response.to_string())
        .create();
    let mut jwk_set = JwkSet::new();
    jwk_set.push_key(jwk);

    // Retrieve the backup using the solved challenge
    let router = get_test_router(None, Some(server.url().as_str())).await;
    let retrieve_response = router
        .oneshot(
            Request::builder()
                .uri("/v1/retrieve/from-challenge")
                .method("POST")
                .header("Content-Type", "application/json")
                .header(ATTESTATION_GATEWAY_HEADER, jwt)
                .body(body.to_string())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(retrieve_response.status(), StatusCode::OK);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify we got back a backup, metadata and factor sync token
    assert!(response["backup"].is_string());
    assert!(response["metadata"].is_object());
    assert!(response["syncFactorToken"].is_string());

    // Decode and verify the backup data
    let backup_base64 = response["backup"].as_str().unwrap();
    let backup_bytes = STANDARD.decode(backup_base64).unwrap();
    assert_eq!(backup_bytes, b"TEST BACKUP DATA");

    // Verify the metadata contains expected fields
    let metadata = &response["metadata"];
    assert_eq!(metadata["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_retrieve_backup_with_incorrect_token() {
    let mut passkey_client = get_mock_passkey_client();

    // Create a backup first
    let (_, create_response) = create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a retrieve challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the same credential
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    // Attempt to retrieve the backup using an incorrect token
    let retrieve_response = send_post_request_with_bypass_attestation_token(
        "/v1/retrieve/from-challenge",
        json!({
            "authorization": {
                "kind": "PASSKEY",
                "credential": retrieve_credential,
            },
            "challengeToken": "INCORRECT TOKEN",
        }),
        None,
    )
    .await;

    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "jwt_error",
                "message": "jwt_error",
            }
        })
    );
}

#[tokio::test]
async fn test_retrieve_backup_with_incorrectly_solved_challenge() {
    let mut passkey_client = get_mock_passkey_client();

    // Create a backup first
    let (_, create_response) = create_test_backup(&mut passkey_client, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // Get a retrieve challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the same credential
    let mut retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client, &retrieve_challenge).await;

    // Tamper with the credential response
    retrieve_credential["response"]["clientDataJSON"][10] = json!(
        retrieve_credential["response"]["clientDataJSON"][10]
            .as_u64()
            .unwrap()
            + 1
    );

    // Attempt to retrieve the backup using the tampered credential
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

    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);

    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "webauthn_error",
                "message": "webauthn_error",
            }
        })
    );
}

#[tokio::test]
async fn test_retrieve_backup_with_nonexistent_credential() {
    let mut passkey_client_1 = get_mock_passkey_client();
    let mut passkey_client_2 = get_mock_passkey_client();

    // Create backup for first client
    let (_, create_response) = create_test_backup(&mut passkey_client_1, b"TEST BACKUP DATA").await;
    assert_eq!(create_response.status(), StatusCode::OK);

    // For the second client, register a credential but do not create a backup
    let challenge_response = get_passkey_challenge().await;
    make_credential_from_passkey_challenge(&mut passkey_client_2, &challenge_response).await;

    // Get a retrieve challenge
    let retrieve_challenge = get_passkey_retrieval_challenge().await;

    // Solve the challenge with the second client (which has no associated backup)
    let retrieve_credential =
        authenticate_with_passkey_challenge(&mut passkey_client_2, &retrieve_challenge).await;

    // Attempt to retrieve a backup that doesn't exist
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

    assert_eq!(retrieve_response.status(), StatusCode::BAD_REQUEST);
    let body = retrieve_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response,
        json!({
            "allowRetry": false,
            "error": {
                "code": "backup_not_found",
                "message": "backup_not_found",
            }
        })
    );
}
