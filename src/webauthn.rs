//! This module contains specific logic for `WebAuthn` operations (used for Passkey serialization and deserialization).
//!
//! Particularly for the `webauthn-rs` crate we use the `danger-allow-state-serialisation` feature flag. This
//! is required to serialize and deserialize the `PasskeyRegistration` and `PasskeyAuthentication` structs. It
//! is safe because the states are kept server-accessible only (stored in the encrypted Challenge token, see `ChallengeManager`).
//! Reference: <https://docs.rs/webauthn-rs/latest/webauthn_rs/#allow-serialising-registration-and-authentication-state>

use crate::types::ErrorResponse;
use serde_json::Value;
use webauthn_rs::prelude::PublicKeyCredential;

pub trait TryFromValue: Sized {
    /// Deserializes a passkey credential if it passes security checks (e.g. no PRF extension misuse).
    ///
    /// # Errors
    /// - Returns `webauthn_prf_results_not_allowed` if PRF extension information is present in the credential. This is a security risk.
    /// - Returns `webauthn_error` if the credential is invalid or cannot be deserialized.
    fn try_from_value(value: &Value) -> Result<Self, ErrorResponse>;
}

impl TryFromValue for PublicKeyCredential {
    fn try_from_value(value: &Value) -> Result<Self, ErrorResponse> {
        // https://w3c.github.io/webauthn/#prf-extension
        // Check for PRF extension misuse
        if value
            .get("clientExtensionResults")
            .and_then(|ext| ext.get("prf"))
            .and_then(|prf| prf.get("results")) // this field must be removed by the clients and never sent to the server
            .is_some()
        {
            tracing::info!(message = "PRF `results` are not allowed in clientExtensionResults");
            return Err(ErrorResponse::bad_request(
                "webauthn_prf_results_not_allowed",
            ));
        }

        //  Deserialize credential
        serde_json::from_value(value.clone()).map_err(|err| {
            tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
            ErrorResponse::bad_request("webauthn_error")
        })
    }
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
        assert!(matches!(result, Err(ErrorResponse { .. })));
    }

    #[test]
    fn test_invalid_json_should_fail() {
        let raw = json!({ "some": "invalid" });
        let result = PublicKeyCredential::try_from_value(&raw);
        assert!(matches!(result, Err(ErrorResponse { .. })));
    }
}
