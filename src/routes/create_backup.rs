use crate::axum_utils::extract_fields_from_multipart;
use crate::backup_storage::BackupStorage;
use crate::challenge_manager::{ChallengeContext, ChallengeManager, ChallengeType};
use crate::dynamo_cache::DynamoCacheManager;
use crate::factor_lookup::{FactorLookup, FactorScope, FactorToLookup};
use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::types::backup_metadata::{BackupMetadata, Factor, OidcAccountKind};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::{Authorization, Environment, ErrorResponse, OidcToken};
use crate::verify_signature::verify_signature;
use axum::extract::Multipart;
use axum::{extract::Extension, Json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{PasskeyRegistration, RegisterPublicKeyCredential};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupRequest {
    authorization: Authorization,
    challenge_token: String,
    initial_encryption_key: BackupEncryptionKey,
    initial_sync_factor: Authorization,
    initial_sync_challenge_token: String,
    /// Provider ID from Turnkey ID. Only applicable if `initial_sync_factor` is `Authorization::OidcAccount`.
    turnkey_provider_id: Option<String>,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupResponse {
    pub backup_id: String,
}

pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(challenge_manager): Extension<ChallengeManager>,
    Extension(backup_storage): Extension<BackupStorage>,
    Extension(factor_lookup): Extension<FactorLookup>,
    Extension(oidc_token_verifier): Extension<OidcTokenVerifier>,
    Extension(dynamo_cache_manager): Extension<DynamoCacheManager>,
    mut multipart: Multipart,
) -> Result<Json<CreateBackupResponse>, ErrorResponse> {
    // Step 1: Parse multipart form data. It should include the main JSON payload with parameters
    // and the attached backup file.
    let multipart_fields = extract_fields_from_multipart(&mut multipart).await?;
    let request = multipart_fields.get("payload").ok_or_else(|| {
        tracing::info!(message = "Missing payload field in multipart data");
        ErrorResponse::bad_request("missing_payload_field")
    })?;
    let request: CreateBackupRequest = serde_json::from_slice(request).map_err(|err| {
        tracing::info!(message = "Failed to deserialize payload", error = ?err);
        ErrorResponse::bad_request("invalid_payload")
    })?;
    let backup = multipart_fields.get("backup").ok_or_else(|| {
        tracing::info!(message = "Missing backup field in multipart data");
        ErrorResponse::bad_request("missing_backup_field")
    })?;

    // Step 1.1: Validate the backup file size
    if backup.is_empty() {
        tracing::info!(message = "Empty backup file");
        return Err(ErrorResponse::bad_request("empty_backup_file"));
    }
    if backup.len() > environment.max_backup_file_size() {
        tracing::info!(message = "Backup file too large");
        return Err(ErrorResponse::bad_request("backup_file_too_large"));
    }

    // Step 2: Verify the solved challenge
    let (backup_factor, factor_to_lookup) = match &request.authorization {
        Authorization::Passkey { credential } => {
            // Step 2A: Verify the passkey credential using the WebAuthn implementation

            // Step 2A.1: Decrypt server-side passkey state from the token
            let (challenge_token_payload, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Passkey, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::Create {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }
            let passkey_state: PasskeyRegistration =
                serde_json::from_slice(&challenge_token_payload).map_err(|err| {
                    // If a valid token cannot be deserialized, it's an internal error
                    tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
                    ErrorResponse::internal_server_error()
                })?;

            // Step 2A.2: Verify the passkey credential using the WebAuthn implementation
            let user_provided_credential: RegisterPublicKeyCredential = serde_json::from_value(
                credential.clone(),
            )
            .map_err(|err| {
                tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
                ErrorResponse::bad_request("webauthn_error")
            })?;
            let verified_passkey = environment
                .webauthn_config()
                .finish_passkey_registration(&user_provided_credential, &passkey_state)?;

            // Step 2A.3: Track used challenge to prevent replay attacks
            dynamo_cache_manager
                .use_challenge_token(request.challenge_token.to_string())
                .await?;

            let credential_id = verified_passkey.cred_id().clone();
            (
                Factor::new_passkey(
                    verified_passkey,
                    serde_json::to_value(credential.clone()).map_err(|err| {
                        tracing::info!(message = "Failed to serialize passkey credential", error = ?err);
                        ErrorResponse::internal_server_error()
                    })?,
                ),
                FactorToLookup::from_passkey(URL_SAFE_NO_PAD.encode(credential_id)),
            )
        }
        Authorization::OidcAccount {
            oidc_token,
            public_key,
            signature,
        } => {
            // Step 2B: Verify the OIDC token and signature by keypair that's mentioned in the token

            // Step 2B.0: Get the Turnkey API OIDC provider ID from the request, if provided.
            // We should save it to metadata and allow client to look it up later.
            let turnkey_provider_id = request
                .turnkey_provider_id
                .as_ref()
                .ok_or_else(|| ErrorResponse::bad_request("missing_turnkey_provider_id"))?
                .to_string();

            // Step 2B.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::Create {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 2B.2: Verify the OIDC token
            let claims = oidc_token_verifier
                .verify_token(oidc_token, public_key.clone())
                .await?;

            // Step 2B.3: Verify the signature by the public key of the challenge
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 2B.4: Track used challenges to prevent replay attacks
            dynamo_cache_manager
                .use_challenge_token(request.challenge_token.to_string())
                .await?;

            // Step 2B.5: Create a factor and factor lookup
            let oidc_account = match &oidc_token {
                OidcToken::Google { .. } => {
                    let email = claims
                        .email()
                        .ok_or_else(|| {
                            tracing::info!(message = "Missing email in OIDC token");
                            ErrorResponse::bad_request("missing_email")
                        })?
                        .to_string();
                    OidcAccountKind::Google {
                        sub: claims.subject().to_string(),
                        email,
                    }
                }
            };
            (
                Factor::new_oidc_account(oidc_account, turnkey_provider_id),
                FactorToLookup::from_oidc_account(
                    claims.issuer().to_string(),
                    claims.subject().to_string(),
                ),
            )
        }
        Authorization::EcKeypair {
            public_key,
            signature,
        } => {
            // Step 2C: Verify the authorization using a custom keypair

            // Step 2C.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(ChallengeType::Keypair, request.challenge_token.to_string())
                .await?;
            if challenge_context != (ChallengeContext::Create {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 2C.2: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 2C.3: Track used challenges to prevent replay attacks
            dynamo_cache_manager
                .use_challenge_token(request.challenge_token.to_string())
                .await?;

            // Step 2C.4: Create a factor and factor lookup
            (
                Factor::new_ec_keypair(public_key.to_string()),
                FactorToLookup::from_ec_keypair(public_key.to_string()),
            )
        }
    };

    // Step 3: Verify sync factor, which is used for updating the backup content. Only EC keypair
    // authorization is supported for now.
    let (initial_sync_factor, initial_sync_factor_to_lookup) = match &request.initial_sync_factor {
        Authorization::EcKeypair {
            public_key,
            signature,
        } => {
            // Step 3.1: Get the challenge payload from the challenge token
            let (trusted_challenge, challenge_context) = challenge_manager
                .extract_token_payload(
                    ChallengeType::Keypair,
                    request.initial_sync_challenge_token.to_string(),
                )
                .await?;
            if challenge_context != (ChallengeContext::Create {}) {
                return Err(ErrorResponse::bad_request("invalid_challenge_context"));
            }

            // Step 3.2: Verify the signature using the public key
            verify_signature(public_key, signature, trusted_challenge.as_ref())?;

            // Step 3.3: Track used challenges to prevent replay attacks
            // TODO/FIXME

            // Step 3.4: Create a factor that's going to be saved in the metadata and a factor to lookup
            (
                Factor::new_ec_keypair(public_key.to_string()),
                FactorToLookup::from_ec_keypair(public_key.to_string()),
            )
        }
        Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
            tracing::info!(message = "Invalid sync factor type");
            return Err(ErrorResponse::bad_request("invalid_sync_factor"));
        }
    };

    // Step 4: Initialize backup metadata
    let backup_metadata = BackupMetadata {
        id: uuid::Uuid::new_v4().to_string(),
        factors: vec![backup_factor],
        sync_factors: vec![initial_sync_factor],
        keys: vec![request.initial_encryption_key.clone()],
    };

    // TODO/FIXME: More checks and metadata initialization

    // Step 5: Link credential ID and sync factor public key to backup ID for lookup during recovery
    // and sync. This should happen before the backup storage is updated, because
    // it might fail with a duplicate key error.
    factor_lookup
        .insert(
            FactorScope::Main,
            &factor_to_lookup,
            backup_metadata.id.clone(),
        )
        .await?;
    factor_lookup
        .insert(
            FactorScope::Sync,
            &initial_sync_factor_to_lookup,
            backup_metadata.id.clone(),
        )
        .await?;

    // Step 6: Save the backup to S3
    backup_storage
        .create(backup.to_vec(), &backup_metadata)
        .await?;

    // TODO/FIXME: remove factor from factor lookup if backup storage create fails

    Ok(Json(CreateBackupResponse {
        backup_id: backup_metadata.id,
    }))
}
