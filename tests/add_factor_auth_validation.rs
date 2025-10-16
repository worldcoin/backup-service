mod common;

use crate::common::{
    create_test_backup_with_oidc_account, get_add_factor_challenges_generic, parse_response_body,
    send_post_request_with_environment,
};
use axum::http::StatusCode;
use serde_json::json;
use serial_test::serial;

// OIDC provider/params and EC signature validation negatives
#[tokio::test]
#[serial]
async fn test_add_factor_auth_validation_matrix() {
    // Setup OIDC as existing
    let test = create_test_backup_with_oidc_account("sig-mismatch", b"DATA").await;

    // Request challenges for new EC
    let challenges =
        get_add_factor_challenges_generic(json!({ "kind": "EC_KEYPAIR" }), Some("OIDC_ACCOUNT"))
            .await;

    // Existing OIDC auth
    let existing_sig = crate::common::sign_keypair_challenge(
        &test.secret_key,
        challenges["existingFactorChallenge"].as_str().unwrap(),
    );

    // Case 1: Missing turnkeyProviderId for OIDC(new)
    {
        let new_sig = crate::common::sign_keypair_challenge(
            &test.secret_key,
            challenges["newFactorChallenge"].as_str().unwrap(),
        );
        let resp = send_post_request_with_environment(
            "/v1/add-factor",
            json!({
                "existingFactorAuthorization": {
                    "kind": "OIDC_ACCOUNT",
                    "oidcToken": { "kind": "GOOGLE", "token": test.oidc_token.clone() },
                    "publicKey": test.public_key,
                    "signature": existing_sig,
                },
                "existingFactorChallengeToken": challenges["existingFactorToken"],
                "newFactorAuthorization": {
                    "kind": "OIDC_ACCOUNT",
                    "oidcToken": { "kind": "GOOGLE", "token": test.oidc_token },
                    "publicKey": test.public_key,
                    "signature": new_sig,
                },
                "newFactorChallengeToken": challenges["newFactorToken"],
                "encryptedBackupKey": null
            }),
            Some(test.environment.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = parse_response_body(resp).await;
        assert_eq!(body["error"]["code"], "missing_turnkey_provider_id");
    }

    // Case 2: New EC signature verification error (sign with different key)
    {
        let (pub1, _sk1) = crate::common::generate_keypair();
        let (_pub2, sk2) = crate::common::generate_keypair();
        let wrong_sig = crate::common::sign_keypair_challenge(
            &sk2,
            challenges["newFactorChallenge"].as_str().unwrap(),
        );

        let resp = send_post_request_with_environment(
            "/v1/add-factor",
            json!({
                "existingFactorAuthorization": {
                    "kind": "OIDC_ACCOUNT",
                    "oidcToken": { "kind": "GOOGLE", "token": test.oidc_token.clone() },
                    "publicKey": test.public_key,
                    "signature": existing_sig,
                },
                "existingFactorChallengeToken": challenges["existingFactorToken"],
                "newFactorAuthorization": { "kind": "EC_KEYPAIR", "publicKey": pub1, "signature": wrong_sig },
                "newFactorChallengeToken": challenges["newFactorToken"],
                "encryptedBackupKey": null
            }),
            Some(test.environment.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = parse_response_body(resp).await;
        assert_eq!(body["error"]["code"], "signature_verification_error");
    }
}
