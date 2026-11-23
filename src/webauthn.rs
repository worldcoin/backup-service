#![allow(clippy::result_large_err)]

use crate::auth::AuthError;
use serde_json::Value;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

pub trait TryFromValue: Sized {
    /// Deserializes a passkey credential if it passes security checks (e.g. no PRF extension misuse).
    ///
    /// # Errors
    /// - Returns `AuthError::WebauthnPrfResultsNotAllowed` if PRF extension information is present in the credential. This is a security risk.
    /// - Returns `AuthError::WebauthnInvalidPayload` if the credential is invalid or cannot be deserialized.
    fn try_from_value(value: &Value) -> Result<Self, AuthError>;
}

impl TryFromValue for PublicKeyCredential {
    fn try_from_value(value: &Value) -> Result<Self, AuthError> {
        reject_prf_results(value)?;
        serde_json::from_value(value.clone()).map_err(|_| {
            tracing::info!(message = "Failed to deserialize passkey credential");
            AuthError::WebauthnInvalidPayload
        })
    }
}

impl TryFromValue for RegisterPublicKeyCredential {
    fn try_from_value(value: &Value) -> Result<Self, AuthError> {
        reject_prf_results(value)?;
        serde_json::from_value(value.clone()).map_err(|_| {
            tracing::info!(message = "Failed to deserialize passkey registration");
            AuthError::WebauthnInvalidPayload
        })
    }
}

fn reject_prf_results(value: &Value) -> Result<(), AuthError> {
    // Check both extension names accepted by webauthn-rs before deserialization drops PRF data.
    for extensions in ["clientExtensionResults", "extensions"] {
        if value
            .get(extensions)
            .and_then(|ext| ext.get("prf"))
            .and_then(|prf| prf.get("results"))
            .is_some()
        {
            return Err(AuthError::WebauthnPrfResultsNotAllowed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
    use serde_json::json;
    fn base_credential_json() -> Value {
        // AuthenticationResponseJSON schema: https://www.w3.org/TR/webauthn-3/
        json!({
            "id": "credential-id",
            "rawId": b64.encode("credential-id"),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "authenticatorData": b64.encode("authenticator-data"),
                "clientDataJSON": b64.encode("client-data-json"),
                "signature": b64.encode("signature")
            }
        })
    }

    #[test]
    fn test_valid_credential() {
        let raw = base_credential_json();
        let result = PublicKeyCredential::try_from_value(&raw);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prf_results_present_should_fail() {
        let mut raw = base_credential_json();
        raw["clientExtensionResults"] = json!( {
        "prf": {
            "enabled": true,
            "results": { "first": "something" }
        }});
        let result = PublicKeyCredential::try_from_value(&raw);
        assert!(matches!(
            result,
            Err(AuthError::WebauthnPrfResultsNotAllowed)
        ));
    }

    #[test]
    fn test_invalid_json_should_fail() {
        let raw = json!({ "some": "invalid" });
        let result = PublicKeyCredential::try_from_value(&raw);
        assert!(matches!(result, Err(AuthError::WebauthnInvalidPayload)));
    }

    #[test]
    fn rejects_prf_results_for_registration_and_authentication_with_either_alias() {
        for alias in ["clientExtensionResults", "extensions"] {
            for results in [json!({ "first": "secret-prf-value" }), Value::Null] {
                let raw = json!({alias: {"prf": {"results": results}}});
                assert!(matches!(
                    RegisterPublicKeyCredential::try_from_value(&raw),
                    Err(AuthError::WebauthnPrfResultsNotAllowed)
                ));
                assert!(matches!(
                    PublicKeyCredential::try_from_value(&raw),
                    Err(AuthError::WebauthnPrfResultsNotAllowed)
                ));
            }
        }
    }

    #[test]
    fn malformed_credentials_do_not_log_field_values() {
        use crate::test_logs::LogCapture;

        let logs = LogCapture::default();
        let subscriber = tracing_subscriber::fmt().with_writer(logs.clone()).finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut raw = base_credential_json();
            raw["response"] = json!("sensitive-malformed-value");
            assert!(PublicKeyCredential::try_from_value(&raw).is_err());
            assert!(RegisterPublicKeyCredential::try_from_value(&raw).is_err());
        });
        let logged = logs.dump();
        assert!(logged.contains("Failed to deserialize passkey"), "{logged}");
        assert!(!logged.contains("sensitive-malformed-value"), "{logged}");
    }
}
