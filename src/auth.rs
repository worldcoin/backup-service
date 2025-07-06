use std::sync::Arc;

use webauthn_rs::prelude::{DiscoverableAuthentication, DiscoverableKey, PublicKeyCredential};

use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::types::backup_metadata::OidcAccountKind;
use crate::verify_signature::verify_signature;
use crate::webauthn::TryFromValue;
use crate::{
    backup_storage::BackupStorage,
    challenge_manager::{ChallengeContext, ChallengeManager},
    dynamo_cache::DynamoCacheManager,
    factor_lookup::{FactorLookup, FactorScope, FactorToLookup},
    types::{
        backup_metadata::{BackupMetadata, FactorKind},
        Authorization, Environment, ErrorResponse,
    },
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Clone)]
pub struct AuthHandler {
    backup_storage: Arc<BackupStorage>,
    dynamo_cache_manager: Arc<DynamoCacheManager>,
    challenge_manager: Arc<ChallengeManager>,
    environment: Environment,
    factor_lookup: Arc<FactorLookup>,
    oidc_token_verifier: Arc<OidcTokenVerifier>,
}

impl AuthHandler {
    #[must_use]
    pub fn new(
        backup_storage: Arc<BackupStorage>,
        dynamo_cache_manager: Arc<DynamoCacheManager>,
        challenge_manager: Arc<ChallengeManager>,
        environment: Environment,
        factor_lookup: Arc<FactorLookup>,
        oidc_token_verifier: Arc<OidcTokenVerifier>,
    ) -> Self {
        Self {
            backup_storage,
            dynamo_cache_manager,
            challenge_manager,
            environment,
            factor_lookup,
            oidc_token_verifier,
        }
    }

    pub async fn verify(
        self,
        authorization: &Authorization,
        expected_factor_scope: FactorScope,
        expected_challenge_context: ChallengeContext,
        challenge_token: String,
    ) -> Result<(String, BackupMetadata), ErrorResponse> {
        // Step 1: Verify that the authorization type is supported
        // `ECKeyPair` is the only supported factor type for `Sync` scope. When
        //  only `Sync` factors are allowed, other factors are rejected.
        if expected_factor_scope == FactorScope::Sync {
            match authorization {
                Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
                    return Err(ErrorResponse::bad_request("invalid_authorization_type"));
                }
                Authorization::EcKeypair { .. } => {}
            }
        }

        // Step 2: Extract challenge token
        let (challenge_token_payload, challenge_context) = self
            .challenge_manager
            .extract_token_payload(authorization.into(), challenge_token.clone())
            .await?;

        // Step 3: Verify the challenge context
        if challenge_context != expected_challenge_context {
            return Err(ErrorResponse::bad_request("invalid_challenge_context"));
        }

        // Step 4: Verify specific `Authorization` type
        let (backup_id, backup_metadata) = match authorization {
            Authorization::Passkey { credential } => {
                // Step 4A.1: Extract the passkey credential
                let passkey_state: DiscoverableAuthentication = serde_json::from_slice(
                    &challenge_token_payload,
                )
                .map_err(|err| {
                    // If a valid token cannot be deserialized, it's an internal error
                    tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
                    ErrorResponse::internal_server_error()
                })?;

                // Step 4A.2: Deserialize the credential
                let user_provided_credential = PublicKeyCredential::try_from_value(credential)?;

                // Step 4A.3: Identify which user is referenced by the credential. Note that at
                // this point, the credential is not verified yet.
                let (_not_verified_user_id, not_verified_credential_id) = self
                    .environment
                    .webauthn_config()
                    .identify_discoverable_authentication(&user_provided_credential)?;

                // Step 4A.4: Lookup the credential ID in the factor lookup table and get potential
                // backup ID
                let not_verified_backup_id = self
                    .factor_lookup
                    .lookup(
                        expected_factor_scope,
                        &FactorToLookup::from_passkey(
                            URL_SAFE_NO_PAD.encode(not_verified_credential_id),
                        ),
                    )
                    .await?;

                let Some(not_verified_backup_id) = not_verified_backup_id else {
                    tracing::info!(message = "No backup ID found for the given credential");
                    return Err(ErrorResponse::bad_request("backup_not_found"));
                };

                // Step 4A.5: Fetch the backup metadata from the storage to get the reference
                // credential objects from all passkey factors associated with the backup
                let backup_metadata = self
                    .backup_storage
                    .get_metadata_by_backup_id(&not_verified_backup_id)
                    .await?;
                let backup_metadata = match backup_metadata {
                    Some(backup_metadata) => backup_metadata,
                    None => {
                        tracing::info!(
                            message = "No backup metadata found for the given backup ID"
                        );
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

                // Step 4A.6: Verify the credential using the reference credential object
                let _authentication_result = self
                    .environment
                    .webauthn_config()
                    .finish_discoverable_authentication(
                        &user_provided_credential,
                        passkey_state,
                        &reference_credentials,
                    )?;
                // At this point, the credential is verified and we can use it to fetch the backup
                let backup_id = not_verified_backup_id;

                // Step 4A.7: Return the backup ID and metadata
                (backup_id, backup_metadata)
            }

            Authorization::OidcAccount {
                oidc_token,
                public_key,
                signature,
            } => {
                // Step 4B.1: Verify the OIDC token
                let claims = self
                    .oidc_token_verifier
                    .verify_token(oidc_token, public_key.clone())
                    .await?;

                // Step 4B.2: Verify the signature by the public key of the challenge
                verify_signature(public_key, signature, challenge_token_payload.as_ref())?;

                // Step 4B.3: Look up the OIDC account in the factor lookup table
                let oidc_factor = match &oidc_token {
                    crate::types::OidcToken::Google { .. } => FactorToLookup::from_oidc_account(
                        claims.issuer().to_string(),
                        claims.subject().to_string(),
                    ),
                    crate::types::OidcToken::Apple { .. } => FactorToLookup::from_oidc_account(
                        claims.issuer().to_string(),
                        claims.subject().to_string(),
                    ),
                };

                let not_verified_backup_id = self
                    .factor_lookup
                    .lookup(expected_factor_scope, &oidc_factor)
                    .await?;
                let Some(not_verified_backup_id) = not_verified_backup_id else {
                    tracing::info!(message = "No backup ID found for the given OIDC account");
                    return Err(ErrorResponse::bad_request("backup_not_found"));
                };

                // Step 4B.4: Fetch the backup metadata to verify the OIDC account exists in the factors
                let backup_metadata = self
                    .backup_storage
                    .get_metadata_by_backup_id(&not_verified_backup_id)
                    .await?;
                let backup_metadata = match backup_metadata {
                    Some(backup_metadata) => backup_metadata,
                    None => {
                        tracing::info!(
                            message = "No backup metadata found for the given backup ID"
                        );
                        return Err(ErrorResponse::bad_request("oidc_account_error"));
                    }
                };

                // Step 4B.5: Verify that the OIDC account exists in the backup's factors
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
                            OidcAccountKind::Apple {
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

                // At this point, the credential is verified and we can use it to fetch the backup
                let backup_id = not_verified_backup_id;

                // Step 4B.6: Return the backup ID and metadata
                (backup_id, backup_metadata)
            }
            Authorization::EcKeypair {
                public_key,
                signature,
            } => {
                // Step 4C.1: Verify the signature by the public key of the challenge
                verify_signature(public_key, signature, challenge_token_payload.as_ref())?;

                // Step 4C.2: Lookup the public key in the factor lookup table and get potential backup ID
                let not_verified_backup_id = self
                    .factor_lookup
                    .lookup(
                        expected_factor_scope,
                        &FactorToLookup::from_ec_keypair(public_key.to_string()),
                    )
                    .await?;
                let Some(not_verified_backup_id) = not_verified_backup_id else {
                    tracing::info!(message = "No backup ID found for the given EC keypair");
                    return Err(ErrorResponse::bad_request("backup_not_found"));
                };

                // Step 4C.3: Fetch the backup from the storage to get the reference keypair
                let backup_metadata = self
                    .backup_storage
                    .get_metadata_by_backup_id(&not_verified_backup_id)
                    .await?;
                let backup_metadata = match backup_metadata {
                    Some(backup_metadata) => backup_metadata,
                    None => {
                        tracing::info!(
                            message = "No backup metadata found for the given backup ID"
                        );
                        return Err(ErrorResponse::bad_request("backup_not_found"));
                    }
                };

                // Step 4C.4: Verify that the public key exists in the backup's `Sync` or `Main` factors
                let factors = if expected_factor_scope == FactorScope::Sync {
                    &backup_metadata.sync_factors
                } else {
                    &backup_metadata.factors
                };

                let is_public_key_in_factors = factors.iter().any(|factor| {
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

                // At this point, the credential is verified and we can use it to fetch the backup
                let backup_id = not_verified_backup_id;

                // Step 4C.5: Return the backup ID and metadata
                (backup_id, backup_metadata)
            }
        };

        // Step 5: Track the used challenge to prevent replay attacks
        self.dynamo_cache_manager
            .use_challenge_token(challenge_token)
            .await?;

        Ok((backup_id, backup_metadata))
    }
}
