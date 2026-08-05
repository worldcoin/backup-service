use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Duration;
use p256::ecdsa::{self, signature::Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{COSEAlgorithm, COSEKey, COSEKeyType};

/// Verifies a Turnkey activity `WebAuthn` stamp. This function takes a passkey signature that was
/// used to approve a Turnkey activity and verifies it against the passkey public key (in the same
/// format as we store in the backup metadata, see `webauthn_credential.get_public_key()`).
///
/// After activity is verified, we can use fields from `activity_json` that are specific to backup
/// service and consider them signed by the user. This allows to verify that user solved backup service
/// challenge, while signing a Turnkey activity (to do Turnkey part of backup flow) with just
/// one passkey signature (and one tap UX).
///
/// Since we're using a single passkey message, user doesn't have to login twice — once to backup
/// service and once to Turnkey.
///
/// Reference:
/// * <https://docs.turnkey.com/developer-reference/api-overview/stamps#webauthn>
/// * <https://github.com/tkhq/sdk/blob/0c391acab671b0ccadfad66fd6b3e926f21654ea/packages/webauthn-stamper/src/index.ts#L70>
///
/// # Errors
/// - `TurnkeyActivityError`s will be raised if the stamp is not valid.
pub fn verify_turnkey_activity_webauthn_stamp(
    credential_public_key: &COSEKey,
    activity_json: &str,
    assertion_authenticator_data_base64url: &str,
    assertion_client_data_json_base64url: &str,
    signature_base64url: &str,
) -> Result<(), TurnkeyActivityError> {
    if credential_public_key.type_ != COSEAlgorithm::ES256 {
        return Err(TurnkeyActivityError::IncorrectKeyType);
    }

    // Chain of trust:
    //
    // activity JSON
    //      │
    //      ▼  (SHA-256 hash)
    // passkey challenge
    //      │
    //      ▼  (embedded in)
    // clientDataJSON
    //      │
    //      ▼  (combined into)
    // signedData
    //      │
    //      ▼  (signed with `signature_base64url` by)
    // credential_public_key

    // Compute the passkey challenge using Turnkey's algorithm based on the activity JSON
    // Ref: https://github.com/tkhq/sdk/blob/0c391acab671b0ccadfad66fd6b3e926f21654ea/packages/webauthn-stamper/src/index.ts#L70
    let activity_challenge_as_bytes = {
        let mut hasher = Sha256::new();
        hasher.update(activity_json.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        hash.as_bytes().to_vec()
    };

    // Check that client data JSON contains the expected challenge
    let client_data_json = BASE64_URL_SAFE_NO_PAD
        .decode(assertion_client_data_json_base64url)
        .map_err(|_| TurnkeyActivityError::AssertionDecodingError)?;
    let client_data_json_value: serde_json::Value = serde_json::from_slice(&client_data_json)
        .map_err(|_| TurnkeyActivityError::AssertionDecodingError)?;
    let client_data_challenge = client_data_json_value["challenge"]
        .as_str()
        .ok_or(TurnkeyActivityError::AssertionDecodingError)?;
    let client_data_challenge_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(client_data_challenge)
        .map_err(|_| TurnkeyActivityError::AssertionDecodingError)?;
    if client_data_challenge_bytes != activity_challenge_as_bytes {
        return Err(TurnkeyActivityError::PasskeyChallengeMismatch);
    }

    // Construct the signed data: authenticatorData || SHA-256(clientDataJSON)
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(
        &BASE64_URL_SAFE_NO_PAD
            .decode(assertion_authenticator_data_base64url)
            .map_err(|_| TurnkeyActivityError::AssertionDecodingError)?,
    );
    signed_data.extend_from_slice(&Sha256::digest(&client_data_json));

    // Convert COSEKey to p256::ecdsa::VerifyingKey
    let verifying_key = match &credential_public_key.key {
        COSEKeyType::EC_EC2(ec2_key) => {
            // Combine x and y coordinates into a SEC1-encoded uncompressed point (0x04 | x | y)
            let mut sec1_bytes = Vec::with_capacity(65);
            sec1_bytes.push(0x04); // Uncompressed point prefix
            sec1_bytes.extend_from_slice(ec2_key.x.as_slice());
            sec1_bytes.extend_from_slice(ec2_key.y.as_slice());

            // Create VerifyingKey from SEC1 bytes
            VerifyingKey::from_sec1_bytes(&sec1_bytes)
                .map_err(|_| TurnkeyActivityError::KeyConversionError)?
        }
        _ => return Err(TurnkeyActivityError::UnsupportedKeyType),
    };

    // Decode signature from base64url
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| TurnkeyActivityError::SignatureDecodingError)?;

    // The signature is already in DER format
    let signature = ecdsa::Signature::from_der(&signature_bytes)
        .map_err(|_| TurnkeyActivityError::SignatureConversionError)?;

    // Verify the signature
    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| TurnkeyActivityError::SignatureVerificationError)?;

    Ok(())
}

/// For a given Turnkey activity JSON, verifies that:
/// * The activity contains the expected activity type
/// * The activity is not expired (based on the TTL)
/// * The activity contains the expected account ID (only if the user previously had a Turnkey account already)
///
/// # Errors
/// - `TurnkeyActivityError::ActivityJsonParseError` if the activity JSON cannot be parsed
/// - `TurnkeyActivityError::MissingOrganizationId` if the activity JSON does not contain the `organizationId` field
/// - `TurnkeyActivityError::OrganizationIdMismatch` if the `organizationId` does not match the expected account ID
/// - `TurnkeyActivityError::MissingActivityType` if the activity JSON does not contain the `type` field
/// - `TurnkeyActivityError::ActivityTypeMismatch` if the `type` does not match the expected activity type
/// - `TurnkeyActivityError::MissingTimestamp` if the activity JSON does not contain the `timestampMs` field
/// - `TurnkeyActivityError::InvalidTimestamp` if the `timestampMs` cannot be parsed as an i64
/// - `TurnkeyActivityError::ActivityExpired` if the activity is expired based on the TTL
pub fn verify_turnkey_activity_parameters(
    activity_json: &str,
    expected_turnkey_account_id: Option<String>,
    expected_activity_type: &str,
    activity_ttl: Duration,
) -> Result<(), TurnkeyActivityError> {
    // Parse the activity JSON
    let activity: serde_json::Value = serde_json::from_str(activity_json)
        .map_err(|_| TurnkeyActivityError::ActivityJsonParseError)?;

    // Verify organization ID matches expected account ID
    let organization_id = activity["organizationId"]
        .as_str()
        .ok_or(TurnkeyActivityError::MissingOrganizationId)?;

    if let Some(expected_turnkey_account_id) = expected_turnkey_account_id {
        if organization_id != expected_turnkey_account_id {
            return Err(TurnkeyActivityError::OrganizationIdMismatch);
        }
    }

    // Verify activity type
    let activity_type = activity["type"]
        .as_str()
        .ok_or(TurnkeyActivityError::MissingActivityType)?;

    if activity_type != expected_activity_type {
        return Err(TurnkeyActivityError::ActivityTypeMismatch);
    }

    // Verify timestamp is not expired
    let timestamp_ms = activity["timestampMs"]
        .as_str()
        .ok_or(TurnkeyActivityError::MissingTimestamp)?
        .parse::<i64>()
        .map_err(|_| TurnkeyActivityError::InvalidTimestamp)?;

    let activity_time = chrono::DateTime::from_timestamp_millis(timestamp_ms)
        .ok_or(TurnkeyActivityError::InvalidTimestamp)?;

    let current_time = chrono::Utc::now();
    let time_diff = current_time.signed_duration_since(activity_time);

    if time_diff > activity_ttl {
        return Err(TurnkeyActivityError::ActivityExpired);
    }

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum TurnkeyActivityError {
    #[error("Incorrect key type, expected P256 with ECDSA")]
    IncorrectKeyType,
    #[error("Mismatch between challenge in the assertion and the hash of activity JSON")]
    PasskeyChallengeMismatch,
    #[error("Unsupported key type, expected EC2 key")]
    UnsupportedKeyType,
    #[error("Failed to decode key components")]
    KeyDecodingError,
    #[error("Failed to decode assertion components")]
    AssertionDecodingError,
    #[error("Failed to convert to verifying key")]
    KeyConversionError,
    #[error("Failed to decode signature from base64url")]
    SignatureDecodingError,
    #[error("Failed to convert signature format")]
    SignatureConversionError,
    #[error("Signature verification failed")]
    SignatureVerificationError,
    #[error("Failed to parse activity JSON")]
    ActivityJsonParseError,
    #[error("Missing organizationId field in activity JSON")]
    MissingOrganizationId,
    #[error("organizationId does not match expected Turnkey account ID")]
    OrganizationIdMismatch,
    #[error("Missing type field in activity JSON")]
    MissingActivityType,
    #[error("Activity type does not match expected type")]
    ActivityTypeMismatch,
    #[error("Missing timestampMs field in activity JSON")]
    MissingTimestamp,
    #[error("Invalid timestamp format in activity JSON")]
    InvalidTimestamp,
    #[error("Activity has expired based on TTL")]
    ActivityExpired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use webauthn_rs::prelude::{COSEEC2Key, COSEKeyType, ECDSACurve};

    #[test]
    fn test_verify_turnkey_challenge() {
        // Values below are fetched from a sample Turnkey application to test how this code works
        // against the actual Turnkey challenges.

        // Created from sample attestation object attached to a user that performed the request below
        // Attestation Object: o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGPWRm-AHACx7V0GD1IS9v29hS8nSJpOtZt2s8qy27srpQECAyYgASFYIIdX4EuNig8HMwpgcnqF-KFYenKev_XU0ZkyAZrPsmVKIlgg8QaXs80kBewTsVk4WjwULW6Ti-1mWOqggVrry4ln8eY
        // I parsed this attestation object, extracted the public key (x and y) and converted to base64url.
        let public_key = COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: serde_json::from_value(json!("h1fgS42KDwczCmByeoX4oVh6cp6_9dTRmTIBms-yZUo"))
                    .unwrap(),
                y: serde_json::from_value(json!("8QaXs80kBewTsVk4WjwULW6Ti-1mWOqggVrry4ln8eY"))
                    .unwrap(),
            }),
        };
        verify_turnkey_activity_webauthn_stamp(
            &public_key,
            // Activity JSON that was signed
            r#"{"parameters":{"userId":"d9620d04-e928-4ada-941c-beb2f17e968c"},"organizationId":"17d89304-c865-4485-ba45-277a5f2076af","timestampMs":"1746996827770","type":"ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY"}"#,
            // Authenticator data from header
            "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA",
            // Client data JSON from header
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWmpFeU1XSmpNMk00WVRNM1lqYzFZVEUwT0RZMU1qUTFOVFpoWWpjME9XTTRPV0V6WW1VNE1tWXpPRGxoTlRsaU5EWTFaVGcyTkRKa01XTmxNRGc1TkEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            // Signature from stamp header
            "MEQCIDjJBMjQD470A5dzt-JY1GIBwB5mbnxpsqoJx2tFAaBFAiAy2u97FwJnE8jZNbBKfV-mVHMVPlzeIYZhHuqrH7lWQg",
        ).expect("Failed to verify Turnkey challenge");
    }

    #[test]
    fn test_verify_turnkey_challenge_wrong_user() {
        // Same values in `verify_turnkey_activity_webauthn_stamp`, but `public_key` has x and y
        // coordinates of a different user.
        let public_key = COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: serde_json::from_value(json!("zZHnnOvLUSTyR5MN6ny3MRn3XBv4B8XYzKT490rQXFY"))
                    .unwrap(),
                y: serde_json::from_value(json!("JdPPHdXp5LReMsCKFwRdbLJKMUThHZrSoBJ52J5goPE"))
                    .unwrap(),
            }),
        };
        assert_eq!(verify_turnkey_activity_webauthn_stamp(
            &public_key,
            // Activity JSON that was signed
            r#"{"parameters":{"userId":"d9620d04-e928-4ada-941c-beb2f17e968c"},"organizationId":"17d89304-c865-4485-ba45-277a5f2076af","timestampMs":"1746996827770","type":"ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY"}"#,
            // Authenticator data from header
            "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA",
            // Client data JSON from header
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWmpFeU1XSmpNMk00WVRNM1lqYzFZVEUwT0RZMU1qUTFOVFpoWWpjME9XTTRPV0V6WW1VNE1tWXpPRGxoTlRsaU5EWTFaVGcyTkRKa01XTmxNRGc1TkEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            "MEQCIDjJBMjQD470A5dzt-JY1GIBwB5mbnxpsqoJx2tFAaBFAiAy2u97FwJnE8jZNbBKfV-mVHMVPlzeIYZhHuqrH7lWQg",
        ).unwrap_err().to_string(), "Signature verification failed");
    }

    #[test]
    fn test_verify_turnkey_challenge_modified_activity_json() {
        // Same values in `verify_turnkey_activity_webauthn_stamp` and `public_key`,
        // but `activity_json` has an extra space before last }.
        let public_key = COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: serde_json::from_value(json!("h1fgS42KDwczCmByeoX4oVh6cp6_9dTRmTIBms-yZUo"))
                    .unwrap(),
                y: serde_json::from_value(json!("8QaXs80kBewTsVk4WjwULW6Ti-1mWOqggVrry4ln8eY"))
                    .unwrap(),
            }),
        };
        assert_eq!(verify_turnkey_activity_webauthn_stamp(
            &public_key,
            // Activity JSON that was signed
            r#"{"parameters":{"userId":"d9620d04-e928-4ada-941c-beb2f17e968c"},"organizationId":"17d89304-c865-4485-ba45-277a5f2076af","timestampMs":"1746996827770","type":"ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY" }"#,
            // Authenticator data from header
            "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA",
            // Client data JSON from header
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWmpFeU1XSmpNMk00WVRNM1lqYzFZVEUwT0RZMU1qUTFOVFpoWWpjME9XTTRPV0V6WW1VNE1tWXpPRGxoTlRsaU5EWTFaVGcyTkRKa01XTmxNRGc1TkEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            "MEQCIDjJBMjQD470A5dzt-JY1GIBwB5mbnxpsqoJx2tFAaBFAiAy2u97FwJnE8jZNbBKfV-mVHMVPlzeIYZhHuqrH7lWQg",
        ).unwrap_err().to_string(), "Mismatch between challenge in the assertion and the hash of activity JSON");
    }

    #[test]
    fn test_verify_turnkey_activity_parameters_success() {
        let timestamp = Utc::now().timestamp_millis();
        let activity_json = json!({
            "parameters": {
                "userId": "d9620d04-e928-4ada-941c-beb2f17e968c"
            },
            "organizationId": "17d89304-c865-4485-ba45-277a5f2076af",
            "timestampMs": timestamp.to_string(),
            "type": "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY"
        })
        .to_string();
        let expected_account_id = "17d89304-c865-4485-ba45-277a5f2076af";
        let expected_activity_type = "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY";
        let ttl = Duration::minutes(60);

        verify_turnkey_activity_parameters(
            &activity_json,
            Some(expected_account_id.to_string()),
            expected_activity_type,
            ttl,
        )
        .expect("Should verify successfully");
    }

    #[test]
    fn test_verify_turnkey_activity_parameters_wrong_organization_id() {
        let timestamp = Utc::now().timestamp_millis();
        let activity_json = json!({
            "parameters": {
                "userId": "d9620d04-e928-4ada-941c-beb2f17e968c"
            },
            "organizationId": "17d89304-c865-4485-ba45-277a5f2076af",
            "timestampMs": timestamp.to_string(),
            "type": "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY"
        })
        .to_string();
        let expected_account_id = "different-account-id";
        let expected_activity_type = "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY";
        let ttl = Duration::minutes(60);

        let result = verify_turnkey_activity_parameters(
            &activity_json,
            Some(expected_account_id.to_string()),
            expected_activity_type,
            ttl,
        );

        assert_eq!(
            result.unwrap_err().to_string(),
            "organizationId does not match expected Turnkey account ID"
        );
    }

    #[test]
    fn test_verify_turnkey_activity_parameters_wrong_activity_type() {
        let timestamp = Utc::now().timestamp_millis();
        let activity_json = json!({
            "parameters": {
                "userId": "d9620d04-e928-4ada-941c-beb2f17e968c"
            },
            "organizationId": "17d89304-c865-4485-ba45-277a5f2076af",
            "timestampMs": timestamp.to_string(),
            "type": "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY"
        })
        .to_string();
        let expected_activity_type = "DIFFERENT_ACTIVITY_TYPE";
        let ttl = Duration::minutes(60);

        let result =
            verify_turnkey_activity_parameters(&activity_json, None, expected_activity_type, ttl);

        assert_eq!(
            result.unwrap_err().to_string(),
            "Activity type does not match expected type"
        );
    }

    #[test]
    fn test_verify_turnkey_activity_parameters_expired() {
        let timestamp = Utc::now().timestamp_millis() - 1000 * 60 * 61; // 61 minutes ago
        let activity_json = json!({
            "parameters": {
                "userId": "d9620d04-e928-4ada-941c-beb2f17e968c"
            },
            "organizationId": "17d89304-c865-4485-ba45-277a5f2076af",
            "timestampMs": timestamp.to_string(),
            "type": "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY"
        })
        .to_string();
        let expected_account_id = "17d89304-c865-4485-ba45-277a5f2076af";
        let expected_activity_type = "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY";
        let ttl = Duration::minutes(60);

        let result = verify_turnkey_activity_parameters(
            &activity_json,
            Some(expected_account_id.to_string()),
            expected_activity_type,
            ttl,
        );

        assert_eq!(
            result.unwrap_err().to_string(),
            "Activity has expired based on TTL"
        );
    }
}
