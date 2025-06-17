use std::sync::Arc;

use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::types::backup_metadata::{FactorKind, OidcAccountKind};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, Environment, ErrorResponse};
use axum::{Extension, Json};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorRequest {
    authorization: Authorization,
    challenge_token: String,
    factor_id: String,
    /// Key that should be deleted from encryption key list in the metadata as part of this request
    encryption_key: Option<BackupEncryptionKey>,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorResponse {}

/// Request to delete a factor from backup metadata using a solved challenge.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(auth_handler): Extension<AuthHandler>,
    request: Json<DeleteFactorRequest>,
) -> Result<Json<DeleteFactorResponse>, ErrorResponse> {
    // Step 1: Extract the factor IDs from the request
    let factor_id = request.factor_id.clone();
    let encryption_key = request.encryption_key.clone();

    // Step 2: Auth. Verify the solved challenge
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Sync,
            // this will be compared in the `AuthHandler::verify()` function.
            // if the ChallengeContext is not the same between the request and the challenge token,
            // the request will be rejected.
            ChallengeContext::DeleteFactor {
                factor_id: request.factor_id.clone(),
            },
            request.challenge_token.clone(),
        )
        .await?;

    // Step 3: Find the factor to delete from the backup
    let factor_to_delete = backup_metadata.factors.iter().find_map(|factor| {
        // Match on factor ID provided in the request
        if factor.id == factor_id {
            // And convert it to a factor to lookup format
            match &factor.kind {
                FactorKind::EcKeypair { public_key } => {
                    Some(FactorToLookup::from_ec_keypair(public_key.to_string()))
                }
                FactorKind::Passkey {
                    webauthn_credential,
                    ..
                } => Some(FactorToLookup::from_passkey(
                    BASE64_URL_SAFE_NO_PAD.encode(webauthn_credential.cred_id()),
                )),
                FactorKind::OidcAccount {
                    account,
                    turnkey_provider_id: _,
                } => match account {
                    OidcAccountKind::Google { sub, email: _ } => {
                        Some(FactorToLookup::from_oidc_account(
                            environment.google_issuer_url().to_string(),
                            sub.to_string(),
                        ))
                    }
                    OidcAccountKind::Apple { sub, email: _ } => {
                        Some(FactorToLookup::from_oidc_account(
                            environment.apple_issuer_url().to_string(),
                            sub.to_string(),
                        ))
                    }
                },
            }
        } else {
            None
        }
    });
    let Some(factor_to_delete) = factor_to_delete else {
        tracing::info!(message = "Factor not found in backup metadata");
        return Err(ErrorResponse::bad_request("factor_not_found"));
    };

    // Step 4: Delete the factor from the factor lookup & backup storage
    factor_lookup
        .delete(FactorScope::Main, &factor_to_delete)
        .await?;

    backup_storage
        .remove_factor(&backup_id, &factor_id, encryption_key.as_ref())
        .await?;

    Ok(Json(DeleteFactorResponse {}))
}
