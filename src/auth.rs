use webauthn_rs::prelude::{DiscoverableAuthentication, DiscoverableKey, PublicKeyCredential};

use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::types::backup_metadata::OidcAccountKind;
use crate::verify_signature::verify_signature;
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

pub struct AuthHandler {
    authorization: Authorization,
    expected_factor_scope: FactorScope,
    pub challenge_context: ChallengeContext,
    challenge_token: String,
}

impl AuthHandler {
    pub fn new(
        authorization: Authorization,
        expected_factor_scope: FactorScope,
        challenge_context: ChallengeContext,
        challenge_token: String,
    ) -> Self {
        Self {
            authorization,
            expected_factor_scope,
            challenge_context,
            challenge_token,
        }
    }

    pub async fn verify(
        self,
        backup_storage: &BackupStorage,
        dynamo_cache_manager: &DynamoCacheManager,
        challenge_manager: &ChallengeManager,
        environment: &Environment,
        factor_lookup: &FactorLookup,
        oidc_token_verifier: Option<&OidcTokenVerifier>,
    ) -> Result<(String, BackupMetadata), ErrorResponse> {
        // Step 1: Verify that the authorization type is supported
        // `ECKeyPair` is the only supported factor type for `Sync` scope. When
        //  only `Sync` factors are allowed, other factors are rejected.
        if self.expected_factor_scope == FactorScope::Sync {
            match &self.authorization {
                Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
                    return Err(ErrorResponse::bad_request("invalid_authorization_type"));
                }
                _ => {}
            }
        }

        // Step 2: Extract challenge token
        let (challenge_token_payload, challenge_context) = challenge_manager
            .extract_token_payload(
                (&self.authorization).into(),
                self.challenge_token.to_string(),
            )
            .await?;

        // Step 3: Verify the challenge context
        if challenge_context != self.challenge_context {
            return Err(ErrorResponse::bad_request("invalid_challenge_context"));
        }

        // Step 4: Track the used challenge to prevent replay attacks
        dynamo_cache_manager
            .use_challenge_token(self.challenge_token.to_string())
            .await?;

        // Step 5: Verify specific `Authorization` type
        let (backup_id, backup_metadata) = match &self.authorization {
            Authorization::Passkey { credential } => {
                // Step 5A.1: Extract the passkey credential
                let passkey_state: DiscoverableAuthentication = serde_json::from_slice(
                    &challenge_token_payload,
                )
                .map_err(|err| {
                    // If a valid token cannot be deserialized, it's an internal error
                    tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
                    ErrorResponse::internal_server_error()
                })?;

                // Step 5A.2: Deserialize the credential
                let user_provided_credential: PublicKeyCredential = serde_json::from_value(
                    credential.clone(),
                )
                .map_err(|err| {
                    tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
                    ErrorResponse::bad_request("webauthn_error")
                })?;

                // Step 5A.3: Identify which user is referenced by the credential. Note that at
                // this point, the credential is not verified yet.
                let (_not_verified_user_id, not_verified_credential_id) = environment
                    .webauthn_config()
                    .identify_discoverable_authentication(&user_provided_credential)?;

                // Step 5A.4: Lookup the credential ID in the factor lookup table and get potential
                // backup ID
                let not_verified_backup_id = factor_lookup
                    .lookup(
                        self.expected_factor_scope,
                        &FactorToLookup::from_passkey(
                            URL_SAFE_NO_PAD.encode(not_verified_credential_id),
                        ),
                    )
                    .await?;

                let Some(not_verified_backup_id) = not_verified_backup_id else {
                    tracing::info!(message = "No backup ID found for the given credential");
                    return Err(ErrorResponse::bad_request("backup_not_found"));
                };

                // Step 5A.5: Fetch the backup metadata from the storage to get the reference
                // credential objects from all passkey factors associated with the backup
                let backup_metadata = backup_storage
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

                // Step 5A.6: Verify the credential using the reference credential object
                let _authentication_result = environment
                    .webauthn_config()
                    .finish_discoverable_authentication(
                        &user_provided_credential,
                        passkey_state,
                        &reference_credentials,
                    )?;
                // At this point, the credential is verified and we can use it to fetch the backup
                let backup_id = not_verified_backup_id;

                // Step 5A.7: Return the backup ID and metadata
                (backup_id, backup_metadata)
            }

            Authorization::OidcAccount {
                oidc_token,
                public_key,
                signature,
            } => {
                let Some(oidc_token_verifier) = oidc_token_verifier else {
                    tracing::error!(message = "OIDC token verifier is not configured");
                    return Err(ErrorResponse::internal_server_error());
                };

                // Step 5B.1: Verify the OIDC token
                let claims = oidc_token_verifier
                    .verify_token(oidc_token, public_key.clone())
                    .await
                    .map_err(|_| ErrorResponse::bad_request("oidc_token_verification_error"))?;

                // Step 5B.2: Verify the signature by the public key of the challenge
                verify_signature(public_key, signature, challenge_token_payload.as_ref())?;

                // Step 5B.3: Verify the nonce in the OIDC token matches the public key
                let _nonce = claims.nonce().ok_or_else(|| {
                    tracing::info!(message = "Missing nonce in OIDC token");
                    ErrorResponse::bad_request("missing_nonce")
                })?;
                // TODO/FIXME: Implement check

                // Step 5B.4: Look up the OIDC account in the factor lookup table
                let oidc_factor = match &oidc_token {
                    crate::types::OidcToken::Google { .. } => FactorToLookup::from_oidc_account(
                        claims.issuer().to_string(),
                        claims.subject().to_string(),
                    ),
                };

                let not_verified_backup_id = factor_lookup
                    .lookup(self.expected_factor_scope, &oidc_factor)
                    .await?;
                let Some(not_verified_backup_id) = not_verified_backup_id else {
                    tracing::info!(message = "No backup ID found for the given OIDC account");
                    return Err(ErrorResponse::bad_request("backup_not_found"));
                };

                // Step 5B.5: Fetch the backup metadata to verify the OIDC account exists in the factors
                let backup_metadata = backup_storage
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

                // Step 5B.6: Verify that the OIDC account exists in the backup's factors
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

                // At this point, the credential is verified and we can use it to fetch the backup
                let backup_id = not_verified_backup_id;

                // Step 5B.7: Return the backup ID and metadata
                (backup_id, backup_metadata)
            }

            Authorization::EcKeypair {
                public_key,
                signature,
            } => {
                // Step 5C.1: Verify the signature by the public key of the challenge
                verify_signature(public_key, signature, challenge_token_payload.as_ref())?;

                // Step 5C.2: Lookup the public key in the factor lookup table and get potential backup ID
                let not_verified_backup_id = factor_lookup
                    .lookup(
                        self.expected_factor_scope,
                        &FactorToLookup::from_ec_keypair(public_key.to_string()),
                    )
                    .await?;
                let Some(not_verified_backup_id) = not_verified_backup_id else {
                    tracing::info!(message = "No backup ID found for the given EC keypair");
                    return Err(ErrorResponse::bad_request("backup_not_found"));
                };

                // Step 5C.3: Fetch the backup from the storage to get the reference keypair
                let backup_metadata = backup_storage
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

                // Step 5C.4: Verify that the public key exists in the backup's `Sync` or `Main` factors
                let factors = if self.expected_factor_scope == FactorScope::Sync {
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

                // Step 5C.5: Return the backup ID and metadata
                (backup_id, backup_metadata)
            }
        };

        Ok((backup_id, backup_metadata))
    }
}
