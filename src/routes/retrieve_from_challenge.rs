use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::dynamo_cache::DynamoCacheManager;
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::types::backup_metadata::{ExportedBackupMetadata, FactorKind, OidcAccountKind};
use crate::types::{Authorization, Environment, ErrorResponse};
use crate::verify_signature::verify_signature;
use axum::{Extension, Json};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{DiscoverableAuthentication, DiscoverableKey, PublicKeyCredential};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeRequest {
    authorization: Authorization,
    challenge_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeResponse {
    /// Encrypted backup in base64.
    backup: String,
    /// Metadata about the backup, including the Turnkey ID and encryption keys.
    metadata: ExportedBackupMetadata,
    /// Token to add a new sync factor later.
    sync_factor_token: String,
}

/// Request to retrieve a backup using a solved challenge.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
    Extension(oidc_token_verifier): Extension<OidcTokenVerifier>,
    Extension(dynamo_cache_manager): Extension<DynamoCacheManager>,
    request: Json<RetrieveBackupFromChallengeRequest>,
) -> Result<Json<RetrieveBackupFromChallengeResponse>, ErrorResponse> {
    // Step 1: Verify the solved challenge and get the backup from S3
    let (backup, metadata) = match &request.authorization {
        Authorization::Passkey { credential } => {
            // Step 1A.1: Decrypt passkey state from the token
            let (challenge_token_payload, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Passkey, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::Retrieve {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }
            let passkey_state: DiscoverableAuthentication =
                serde_json::from_slice(&challenge_token_payload).map_err(|err| {
                    // If a valid token cannot be deserialized, it's an internal error
                    tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
                    ErrorResponse::internal_server_error()
                })?;

            // Step 1A.2: Deserialize the credential
            let user_provided_credential: PublicKeyCredential = serde_json::from_value(
                credential.clone(),
            )
            .map_err(|err| {
                tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
                ErrorResponse::bad_request("webauthn_error")
            })?;

            // Step 1A.3: Identify which user is referenced by the credential. Note that at
            // this point, the credential is not verified yet.
            let (_not_verified_user_id, not_verified_credential_id) = environment
                .webauthn_config()
                .identify_discoverable_authentication(&user_provided_credential)?;

            // Step 1A.4: Lookup the credential ID in the factor lookup table and get potential
            // backup ID
            let not_verified_backup_id = factor_lookup
                .lookup(
                    FactorScope::Main,
                    &FactorToLookup::from_passkey(
                        URL_SAFE_NO_PAD.encode(not_verified_credential_id),
                    ),
                )
                .await?;
            let Some(not_verified_backup_id) = not_verified_backup_id else {
                tracing::info!(message = "No backup ID found for the given credential");
                return Err(ErrorResponse::bad_request("backup_not_found"));
            };

            // Step 1A.5: Fetch the backup from the storage to get the reference
            // credential objects from all passkey factors associated with the backup
            let backup_metadata = backup_storage
                .get_metadata_by_backup_id(&not_verified_backup_id)
                .await?;
            let backup_metadata = match backup_metadata {
                Some(backup_metadata) => backup_metadata,
                None => {
                    tracing::info!(message = "No backup metadata found for the given backup ID");
                    return Err(ErrorResponse::bad_request("webauthn_error"));
                }
            };
            let reference_credentials: Vec<DiscoverableKey> = backup_metadata
                .factors
                .iter()
                .filter_map(|factor| {
                    #[allow(irrefutable_let_patterns)]
                    if let FactorKind::Passkey {
                        webauthn_credential,
                        registration: _,
                    } = &factor.kind
                    {
                        Some(webauthn_credential.into())
                    } else {
                        None
                    }
                })
                .collect();
            if reference_credentials.is_empty() {
                tracing::info!(message = "No reference credentials found");
                return Err(ErrorResponse::bad_request("webauthn_error"));
            }

            // Step 1A.6: Verify the credential using the reference credential object
            let _authentication_result = environment
                .webauthn_config()
                .finish_discoverable_authentication(
                    &user_provided_credential,
                    passkey_state,
                    &reference_credentials,
                )?;
            // At this point, the credential is verified and we can use it to fetch the backup
            let backup_id = not_verified_backup_id;

            // TODO/FIXME: Track used challenges to prevent replay attacks
            // TODO/FIXME: Track authentication counter

            // Step 1A.7: Now that the credential is verified, we can fetch the backup
            // from the storage
            let backup = backup_storage.get_backup_by_backup_id(&backup_id).await?;
            match backup {
                Some(backup) => (backup, backup_metadata),
                None => {
                    tracing::info!(message = "No backup found for the given backup ID");
                    return Err(ErrorResponse::bad_request("webauthn_error"));
                }
            }
        }
        Authorization::OidcAccount {
            oidc_token,
            public_key,
            signature,
        } => {
            // Step 1B.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::Retrieve {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 1B.2: Verify the OIDC token
            let claims = oidc_token_verifier
                .verify_token(oidc_token)
                .await
                .map_err(|_| ErrorResponse::bad_request("oidc_token_verification_error"))?;

            // Step 1B.3: Verify the signature by the public key of the challenge
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 1B.4: Verify the nonce in the OIDC token matches the public key
            let _nonce = claims.nonce().ok_or_else(|| {
                tracing::info!(message = "Missing nonce in OIDC token");
                ErrorResponse::bad_request("missing_nonce")
            })?;
            // TODO/FIXME: Implement check

            // Step 1B.5: Look up the OIDC account in the factor lookup table
            let oidc_factor = match &oidc_token {
                crate::types::OidcToken::Google { .. } => FactorToLookup::from_oidc_account(
                    claims.issuer().to_string(),
                    claims.subject().to_string(),
                ),
            };

            let not_verified_backup_id = factor_lookup
                .lookup(FactorScope::Main, &oidc_factor)
                .await?;
            let Some(not_verified_backup_id) = not_verified_backup_id else {
                tracing::info!(message = "No backup ID found for the given OIDC account");
                return Err(ErrorResponse::bad_request("backup_not_found"));
            };

            // Step 1B.6: Fetch the backup metadata to verify the OIDC account exists in the factors
            let backup_metadata = backup_storage
                .get_metadata_by_backup_id(&not_verified_backup_id)
                .await?;
            let backup_metadata = match backup_metadata {
                Some(backup_metadata) => backup_metadata,
                None => {
                    tracing::info!(message = "No backup metadata found for the given backup ID");
                    return Err(ErrorResponse::bad_request("oidc_account_error"));
                }
            };

            // Step 1B.7: Verify that the OIDC account exists in the backup's factors
            let email = claims
                .email()
                .ok_or_else(|| {
                    tracing::info!(message = "Missing email in OIDC token");
                    ErrorResponse::bad_request("oidc_token_verification_error")
                })?
                .to_string();
            let is_oidc_account_in_factors = backup_metadata.factors.iter().any(|factor| {
                if let FactorKind::OidcAccount {
                    account,
                    turnkey_provider_id: _,
                } = &factor.kind
                {
                    match account {
                        OidcAccountKind::Google {
                            sub,
                            email: factor_email,
                        } => sub == &claims.subject().to_string() && factor_email == &email,
                    }
                } else {
                    false
                }
            });

            if !is_oidc_account_in_factors {
                tracing::info!(message = "OIDC account not found in backup factors");
                return Err(ErrorResponse::bad_request("oidc_account_error"));
            }

            // TODO/FIXME: Track used challenges to prevent replay attacks

            // Step 1B.8: Now that the OIDC token and signature are verified and the account exists
            // in the backup factors, we can fetch the backup from storage
            let backup = backup_storage
                .get_backup_by_backup_id(&not_verified_backup_id)
                .await?;
            match backup {
                Some(backup) => (backup, backup_metadata),
                None => {
                    tracing::info!(message = "No backup found for the given backup ID");
                    return Err(ErrorResponse::bad_request("oidc_account_error"));
                }
            }
        }
        Authorization::EcKeypair {
            public_key,
            signature,
        } => {
            // Step 1C.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::Retrieve {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 1C.2: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 1C.3: Lookup the public key in the factor lookup table and get potential backup ID
            let not_verified_backup_id = factor_lookup
                .lookup(
                    FactorScope::Main,
                    &FactorToLookup::from_ec_keypair(public_key.to_string()),
                )
                .await?;
            let Some(not_verified_backup_id) = not_verified_backup_id else {
                tracing::info!(message = "No backup ID found for the given EC keypair");
                return Err(ErrorResponse::bad_request("backup_not_found"));
            };

            // Step 1C.4: Fetch the backup from the storage to get the reference keypair
            let backup_metadata = backup_storage
                .get_metadata_by_backup_id(&not_verified_backup_id)
                .await?;
            let backup_metadata = match backup_metadata {
                Some(backup_metadata) => backup_metadata,
                None => {
                    tracing::info!(message = "No backup metadata found for the given backup ID");
                    return Err(ErrorResponse::bad_request("backup_not_found"));
                }
            };

            // Step 1C.5: Verify that the public key exists in the backup's factors
            let is_public_key_in_factors = backup_metadata.factors.iter().any(|factor| {
                if let FactorKind::EcKeypair {
                    public_key: factor_public_key,
                } = &factor.kind
                {
                    factor_public_key == public_key
                } else {
                    false
                }
            });

            if !is_public_key_in_factors {
                tracing::info!(message = "Public key not found in backup factors");
                return Err(ErrorResponse::bad_request("keypair_error"));
            }

            // TODO/FIXME: Track used challenges to prevent replay attacks

            // Step 1C.6: Now that the signature is verified and the public key is in the backup factors,
            // we can fetch the backup from the storage
            let backup = backup_storage
                .get_backup_by_backup_id(&not_verified_backup_id)
                .await?;
            match backup {
                Some(backup) => (backup, backup_metadata),
                None => {
                    tracing::info!(message = "No backup found for the given backup ID");
                    return Err(ErrorResponse::bad_request("keypair_error"));
                }
            }
        }
    };

    // Step 3: Create a sync factor token to allow the user to add a new sync factor later
    let sync_factor_token = dynamo_cache_manager
        .create_sync_factor_token(metadata.id.clone())
        .await?;

    // Step 4: Return the backup and metadata
    Ok(Json(RetrieveBackupFromChallengeResponse {
        backup: STANDARD.encode(backup),
        metadata: metadata.exported(),
        sync_factor_token,
    }))
}
