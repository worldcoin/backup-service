use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::factor_lookup::{FactorLookup, FactorToLookup};
use crate::types::backup_metadata::{FactorKind, OidcAccountKind};
use crate::types::{Authorization, Environment, ErrorResponse};
use crate::verify_signature::verify_signature;
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

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorResponse {}

/// Request to delete a factor from backup metadata using a solved challenge.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
    request: Json<DeleteFactorRequest>,
) -> Result<Json<DeleteFactorResponse>, ErrorResponse> {
    // Step 1: Verify the solved challenge in the authorization parameter
    let (factor_to_lookup, sync_factor_public_key) = match &request.authorization {
        Authorization::EcKeypair {
            public_key,
            signature,
        } => {
            // Step 1.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;

            // Step 1.2: Verify the factor_id in the challenge context matches the one in the request
            let ChallengeContext::DeleteFactor { factor_id } = challenge_context else {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            };

            if factor_id != request.factor_id {
                tracing::info!(
                    message = "Factor ID in request doesn't match token",
                    request_factor_id = request.factor_id,
                    token_factor_id = factor_id
                );
                return Err(ErrorResponse::bad_request("factor_id_mismatch"));
            }

            // Step 1.3: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 1.4: Create a factor to lookup for the backup and save the verified public key
            (
                FactorToLookup::from_ec_keypair(public_key.to_string()),
                public_key.to_string(),
            )
        }
        Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
            tracing::info!(message = "Invalid authorization type for factor deletion");
            return Err(ErrorResponse::bad_request("invalid_authorization_type"));
        }
    };

    // Step 2: Find the backup metadata using the factor to lookup
    let backup_id = factor_lookup.lookup(&factor_to_lookup).await?;
    let Some(backup_id) = backup_id else {
        tracing::info!(message = "No backup ID found for the given keypair");
        return Err(ErrorResponse::bad_request("backup_not_found"));
    };

    // Step 3: Get the backup metadata to verify authorization
    let found_backup = backup_storage.get_by_backup_id(&backup_id).await?;
    let Some(found_backup) = found_backup else {
        tracing::info!(message = "No backup found for the given backup ID");
        return Err(ErrorResponse::internal_server_error());
    };

    // Step 4: Verify the backup metadata contains the factor as a sync factor
    let metadata_contains_sync_factor_from_signature =
        found_backup.metadata.sync_factors.iter().any(|factor| {
            if let FactorKind::EcKeypair { public_key } = &factor.kind {
                public_key == &sync_factor_public_key
            } else {
                false
            }
        });
    if !metadata_contains_sync_factor_from_signature {
        tracing::info!(
            message = "Backup metadata does not contain the sync factor",
            backup_id = backup_id,
            sync_factor_public_key = sync_factor_public_key
        );
        return Err(ErrorResponse::internal_server_error());
    }

    // Step 5: Delete the factor from the backup and factor lookup
    let factor_to_delete = found_backup.metadata.factors.iter().find_map(|factor| {
        // Match on factor ID provided in the request
        if factor.id == request.factor_id {
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
                FactorKind::OidcAccount { account } => match account {
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
    factor_lookup.delete(&factor_to_delete).await?;

    backup_storage
        .remove_factor(&backup_id, &request.factor_id)
        .await?;

    Ok(Json(DeleteFactorResponse {}))
}
