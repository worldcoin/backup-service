use crate::auth::AuthHandler;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager};
use crate::dynamo_cache::DynamoCacheManager;
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::types::backup_metadata::{FactorKind, OidcAccountKind};
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
}

impl From<DeleteFactorRequest> for AuthHandler {
    fn from(request: DeleteFactorRequest) -> Self {
        AuthHandler::new(
            request.authorization,
            vec![FactorScope::Sync],
            ChallengeContext::DeleteFactor {
                factor_id: request.factor_id,
            },
            request.challenge_token,
        )
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorResponse {}

/// Request to delete a factor from backup metadata using a solved challenge.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
    Extension(dynamo_cache_manager): Extension<DynamoCacheManager>,
    request: Json<DeleteFactorRequest>,
) -> Result<Json<DeleteFactorResponse>, ErrorResponse> {
    // Step 1: Extract the factor IDs from the request
    let factor_id = request.factor_id.clone();

    let auth_handler: AuthHandler = request.0.into();
    let ChallengeContext::DeleteFactor {
        factor_id: challenge_factor_id,
    } = &auth_handler.challenge_context
    else {
        tracing::error!(message = "Invalid challenge context");
        return Err(ErrorResponse::internal_server_error());
    };
    let challenge_factor_id = challenge_factor_id.clone();

    // Step 2: Auth. Verify the solved challenge
    let (backup_id, backup_metadata) = auth_handler
        .verify(
            &backup_storage,
            &dynamo_cache_manager,
            &challenge_manager,
            &environment,
            &factor_lookup,
            None,
        )
        .await?;

    // Step 3: Verify the factor_id in the challenge context matches the one in the request
    if factor_id != *challenge_factor_id {
        tracing::info!(
            message = "Factor ID in request doesn't match token",
            request_factor_id = factor_id,
            token_factor_id = challenge_factor_id
        );
        return Err(ErrorResponse::bad_request("factor_id_mismatch"));
    }

    // Step 5: Delete the factor from the backup and factor lookup
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
    factor_lookup
        .delete(FactorScope::Main, &factor_to_delete)
        .await?;

    backup_storage.remove_factor(&backup_id, &factor_id).await?;

    Ok(Json(DeleteFactorResponse {}))
}
