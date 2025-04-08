use crate::oidc_nonce_verifier::OidcNonceVerifier;
use crate::types::{Environment, ErrorResponse};
use aws_sdk_s3::Client as S3Client;
use axum::{Extension, Json};
use openidconnect::core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet};
use openidconnect::reqwest;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum OidcToken {
    #[serde(rename_all = "camelCase")]
    Google { token: String },
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddOidcAccountRequest {
    // TODO/FIXME: Authorization from backup service account (primary factor)
    /// Token from the OIDC provider that's going to be an additional recovery factor for the backup
    pub oidc_token: OidcToken,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddOidcAccountResponse {}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(_s3_client): Extension<S3Client>,
    request: Json<AddOidcAccountRequest>,
) -> Result<Json<AddOidcAccountResponse>, ErrorResponse> {
    let reqwest_client = reqwest::Client::new();

    // Step 1: TODO/FIXME: Validate the primary factor

    // Step 2: Validate the OIDC token
    let _claims = match &request.oidc_token {
        OidcToken::Google { token } => {
            // Step 1A.1: Load the public keys from Google
            // TODO/FIXME: Cache the keys
            let signature_keys =
                CoreJsonWebKeySet::fetch_async(&environment.google_jwk_set_url(), &reqwest_client)
                    .await?;

            // Step 1A.2: Create the token verifier
            let token_verifier = CoreIdTokenVerifier::new_public_client(
                environment.google_client_id(),
                environment.google_issuer_url(),
                signature_keys,
            );

            // Step 1A.3: Verify the token
            let oidc_token = CoreIdToken::from_str(token).map_err(|_| {
                tracing::info!(message = "Failed to parse OIDC token");
                ErrorResponse::bad_request("invalid_oidc_token")
            })?;
            oidc_token
                .claims(&token_verifier, OidcNonceVerifier::default())
                .map_err(|err| {
                    tracing::info!(message = "Failed to verify OIDC token", error = ?err);
                    ErrorResponse::bad_request("invalid_oidc_token")
                })?
                .clone()
        }
    };

    // Step 3: TODO/FIXME: Store the OIDC account in the backup metadata with data from claims

    // Step 4: TODO/FIXME: Save the mapping between OIDC account and backup ID in DynamoDB

    Ok(Json(AddOidcAccountResponse {}))
}
