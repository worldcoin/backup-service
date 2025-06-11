use crate::types::ErrorResponse;
use serde_json::Value;
use webauthn_rs::prelude::PublicKeyCredential;

/// Deserializes a passkey credential if it passes security checks (e.g. no PRF extension misuse).
pub fn safe_deserialize_passkey_credential(
    raw_credential: &Value,
) -> Result<PublicKeyCredential, ErrorResponse> {
    // https://w3c.github.io/webauthn/#prf-extension
    // Check for PRF extension misuse
    if raw_credential
        .get("clientExtensionResults")
        .and_then(|ext| ext.get("prf"))
        .and_then(|prf| prf.get("results")) // this field must be removed by the clients and never sent to the server
        .is_some()
    {
        tracing::info!(message = "PRF `results` are not allowed in clientExtensionResults");
        return Err(ErrorResponse::bad_request("webauthn_error"));
    }

    //  Deserialize credential
    let user_provided_credential: PublicKeyCredential =
        serde_json::from_value(raw_credential.clone()).map_err(|err| {
            tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
            ErrorResponse::bad_request("webauthn_error")
        })?;

    Ok(user_provided_credential)
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
        let result = safe_deserialize_passkey_credential(&raw);
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
        let result = safe_deserialize_passkey_credential(&raw);
        assert!(matches!(result, Err(ErrorResponse { .. })));
    }

    #[test]
    fn test_invalid_json_should_fail() {
        let raw = json!({ "some": "invalid" });
        let result = safe_deserialize_passkey_credential(&raw);
        assert!(matches!(result, Err(ErrorResponse { .. })));
    }
}
