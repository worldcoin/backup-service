use std::sync::Arc;

use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use crate::oidc_token_verifier::OidcTokenVerifier;
use crate::types::backup_metadata::{Factor, OidcAccountKind};
use crate::types::OidcToken;
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

#[derive(Debug)]
pub struct ValidationResult {
    pub factor: Factor,
    pub factor_to_lookup: FactorToLookup,
}

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

    /// Verifies a request is properly authenticated and authorized for the specific action being performed.
    ///
    /// # Errors
    /// - Returns an error if the challenge token is not properly authorized (e.g. using a `FactorScope` not supported for the action).
    /// - Returns an error if the request is not properly authenticated (which depends on the `Authorization` type).
    #[allow(clippy::too_many_lines)] // the code is properly split out into steps
    pub async fn verify(
        self,
        authorization: &Authorization,
        expected_factor_scope: FactorScope,
        expected_challenge_context: ChallengeContext,
        challenge_token: String,
    ) -> Result<(String, BackupMetadata), ErrorResponse> {
        // Step 1: Verify that the authorization type is supported
        // `ECKeyPair` is the only supported factor type for `Sync` scope, other factors are rejected.
        if expected_factor_scope == FactorScope::Sync {
            match authorization {
                Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
                    return Err(ErrorResponse::bad_request("invalid_authorization_type"));
                }
                Authorization::EcKeypair { .. } => {}
            }
        }

        // Step 2: Extract challenge token (ensures the server actually issued a challenge for the request being performed)
        let (challenge_token_payload, challenge_context) = self
            .challenge_manager
            .extract_token_payload(authorization.into(), challenge_token.clone())
            .await?;

        // Step 3: Verify the challenge context (i.e. the purpose of the challenge is correct)
        if challenge_context != expected_challenge_context {
            return Err(ErrorResponse::bad_request("invalid_challenge_context"));
        }

        // Step 4: Verify each specific `Authorization` type and retrieve the backup ID and metadata
        let (backup_id, backup_metadata) = match authorization {
            Authorization::Passkey { credential } => {
                self.validate_passkey_authentication(
                    credential,
                    &challenge_token_payload,
                    expected_factor_scope,
                )
                .await?
            }
            Authorization::OidcAccount {
                oidc_token,
                public_key,
                signature,
            } => {
                self.validate_oidc_authentication(
                    oidc_token,
                    public_key,
                    signature,
                    &challenge_token_payload,
                    expected_factor_scope,
                )
                .await?
            }
            Authorization::EcKeypair {
                public_key,
                signature,
            } => {
                self.authenticate_ec_keypair(
                    public_key,
                    signature,
                    &challenge_token_payload,
                    expected_factor_scope,
                )
                .await?
            }
        };

        // Step 5: Track the used challenge to prevent replay attacks
        self.dynamo_cache_manager
            .use_challenge_token(challenge_token)
            .await?;

        Ok((backup_id, backup_metadata))
    }

    /// Validates a candidate **new** factor (`Sync` or `Main`) is valid for registration in the user's backup.
    ///
    /// This is called when creating a new backup with fresh factors or when adding a new `Sync` or `Main` factor to an existing backup.
    ///
    /// # Errors
    /// Returns error if the factor is not valid, or is improperly authenticated (following each factor type's specific rules).
    pub async fn validate_factor_registration(
        &self,
        authorization: &Authorization,
        challenge_token: String,
        expected_challenge_context: ChallengeContext,
        turnkey_provider_id: Option<String>,
        is_sync_factor: bool,
    ) -> Result<ValidationResult, ErrorResponse> {
        // Step 1: Verify that the authorization type is valid for the factor scope
        // Sync factors must be EC keypairs - passkeys and OIDC accounts are not allowed as sync factors
        if is_sync_factor {
            match authorization {
                Authorization::Passkey { .. } | Authorization::OidcAccount { .. } => {
                    tracing::info!(message = "Invalid sync factor type");
                    return Err(ErrorResponse::bad_request("invalid_sync_factor"));
                }
                Authorization::EcKeypair { .. } => {}
            }
        }

        // Step 2: Extract and verify the challenge token
        // This ensures the challenge was issued by us and hasn't expired
        let (challenge_token_payload, challenge_context) = self
            .challenge_manager
            .extract_token_payload(authorization.into(), challenge_token.clone())
            .await?;

        // Step 3: Verify the challenge context matches what we expect
        // This ensures the challenge was issued for the correct purpose (Create, AddSyncFactor, etc.)
        if challenge_context != expected_challenge_context {
            return Err(ErrorResponse::bad_request("invalid_challenge_context"));
        }

        // Step 4: Validate the specific authorization type and create the factor
        // Each factor type has its own validation rules for registration
        let (factor, factor_to_lookup) = match authorization {
            Authorization::Passkey { credential } => {
                self.validate_passkey_registration(credential, &challenge_token_payload)?
            }
            Authorization::OidcAccount {
                oidc_token,
                public_key,
                signature,
            } => {
                self.validate_oidc_registration(
                    oidc_token,
                    public_key,
                    signature,
                    &challenge_token_payload,
                    turnkey_provider_id
                        .ok_or_else(|| ErrorResponse::bad_request("missing_turnkey_provider_id"))?,
                )
                .await?
            }
            Authorization::EcKeypair {
                public_key,
                signature,
            } => Self::validate_ec_keypair_registration(
                public_key,
                signature,
                &challenge_token_payload,
            )?,
        };

        // Step 5: Mark the challenge token as used to prevent replay attacks
        // This ensures each challenge can only be used once
        self.dynamo_cache_manager
            .use_challenge_token(challenge_token)
            .await?;

        // Step 6: Return the validated factor and its lookup key
        // The caller will use these to store the factor in the backup metadata and lookup table
        Ok(ValidationResult {
            factor,
            factor_to_lookup,
        })
    }

    //------------------------------------------------------------------------------------------------
    // Internal: Passkey Validation
    //------------------------------------------------------------------------------------------------

    /// Validates a **new** passkey is valid for registration as a factor.
    ///
    /// To allow a new passkey to be registered, we check:
    /// - The trusted challenge token we issued is properly signed by the passkey following the `WebAuthn` spec.
    fn validate_passkey_registration(
        &self,
        credential: &serde_json::Value,
        challenge_token_payload: &[u8],
    ) -> Result<(Factor, FactorToLookup), ErrorResponse> {
        let passkey_state: PasskeyRegistration = serde_json::from_slice(challenge_token_payload)
            .map_err(|err| {
                tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
                ErrorResponse::internal_server_error()
            })?;

        let user_provided_credential: RegisterPublicKeyCredential =
            serde_json::from_value(credential.clone()).map_err(|err| {
                tracing::info!(message = "Failed to deserialize passkey credential", error = ?err);
                ErrorResponse::bad_request("webauthn_error")
            })?;

        let verified_passkey = self
            .environment
            .webauthn_config()
            .finish_passkey_registration(&user_provided_credential, &passkey_state)?;

        let credential_id = verified_passkey.cred_id().clone();
        let factor = Factor::new_passkey(
            verified_passkey,
            serde_json::to_value(credential.clone()).map_err(|err| {
                tracing::info!(message = "Failed to serialize passkey credential", error = ?err);
                ErrorResponse::internal_server_error()
            })?,
        );
        let factor_to_lookup = FactorToLookup::from_passkey(URL_SAFE_NO_PAD.encode(credential_id));

        Ok((factor, factor_to_lookup))
    }

    /// Validates an action is authenticated and authorized for an **existing** backup with a passkey.
    ///
    /// To allow an action to be performed, we check:
    /// - The trusted challenge token we issued is properly signed by the passkey following the `WebAuthn` spec.
    /// - The passkey is in the backup factors (by matching the credential ID).
    async fn validate_passkey_authentication(
        &self,
        credential: &serde_json::Value,
        challenge_token_payload: &[u8],
        expected_factor_scope: FactorScope,
    ) -> Result<(String, BackupMetadata), ErrorResponse> {
        let passkey_state: DiscoverableAuthentication =
            serde_json::from_slice(challenge_token_payload).map_err(|err| {
                tracing::error!(message = "Failed to deserialize passkey state", error = ?err);
                ErrorResponse::internal_server_error()
            })?;

        let user_provided_credential = PublicKeyCredential::try_from_value(credential)?;

        let (_not_verified_user_id, not_verified_credential_id) = self
            .environment
            .webauthn_config()
            .identify_discoverable_authentication(&user_provided_credential)?;

        let not_verified_backup_id = self
            .factor_lookup
            .lookup(
                expected_factor_scope,
                &FactorToLookup::from_passkey(URL_SAFE_NO_PAD.encode(not_verified_credential_id)),
            )
            .await?;

        let Some(not_verified_backup_id) = not_verified_backup_id else {
            tracing::info!(message = "No backup ID found for the given credential");
            return Err(ErrorResponse::bad_request("backup_not_found"));
        };

        let backup_metadata = self
            .backup_storage
            .get_metadata_by_backup_id(&not_verified_backup_id)
            .await?;
        let Some((backup_metadata, _e_tag)) = backup_metadata else {
            tracing::info!(message = "No backup metadata found for the given backup ID");
            return Err(ErrorResponse::bad_request("webauthn_error"));
        };

        let reference_credentials: Vec<DiscoverableKey> = backup_metadata
            .factors
            .iter()
            .filter_map(|factor| {
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

        let _authentication_result = self
            .environment
            .webauthn_config()
            .finish_discoverable_authentication(
                &user_provided_credential,
                passkey_state,
                &reference_credentials,
            )?;

        // At this point the backup is now authenticated and authorized.
        let verified_backup_id = not_verified_backup_id;

        Ok((verified_backup_id, backup_metadata))
    }

    //------------------------------------------------------------------------------------------------
    // Internal: OIDC Account Validation
    //------------------------------------------------------------------------------------------------

    /// Validates a **new** OIDC account is valid for registration as a factor.
    ///
    /// To allow a new OIDC account to be registered, we check:
    /// - The OIDC token is valid (following standard OIDC specs; signature, expiration, etc.)
    /// - The nonce of the OIDC token is equal to the SHA256 hash of the ephemeral "OIDC Session Keypair".
    /// - The trusted challenge token we issued is properly signed by the private key of the ephemeral "OIDC Session Keypair".
    ///
    /// We use an ephemeral keypair so that the user can authenticate once with the OIDC provider for both this service and Turnkey.
    async fn validate_oidc_registration(
        &self,
        oidc_token: &OidcToken,
        public_key: &str,
        signature: &str,
        challenge_token_payload: &[u8],
        turnkey_provider_id: String,
    ) -> Result<(Factor, FactorToLookup), ErrorResponse> {
        let claims = self
            .oidc_token_verifier
            .verify_token(oidc_token, public_key.to_string())
            .await?;

        verify_signature(public_key, signature, challenge_token_payload)?;

        let email = claims
            .email()
            .ok_or_else(|| {
                tracing::info!(message = "Missing email in OIDC token");
                ErrorResponse::bad_request("missing_email")
            })?
            .to_string();

        let oidc_account = match oidc_token {
            OidcToken::Google { .. } => OidcAccountKind::Google {
                sub: claims.subject().to_string(),
                email,
            },
            OidcToken::Apple { .. } => OidcAccountKind::Apple {
                sub: claims.subject().to_string(),
                email,
            },
        };

        let factor = Factor::new_oidc_account(oidc_account, turnkey_provider_id);
        let factor_to_lookup = FactorToLookup::from_oidc_account(
            claims.issuer().to_string(),
            claims.subject().to_string(),
        );

        Ok((factor, factor_to_lookup))
    }

    /// Validates an action is authenticated and authorized for an **existing** backup with an OIDC account.
    ///
    /// To allow a new OIDC account to be registered, we check:
    /// - The OIDC token is valid (following standard OIDC specs; signature, expiration, etc.)
    /// - The nonce of the OIDC token is equal to the SHA256 hash of the ephemeral "OIDC Session Keypair".
    /// - The trusted challenge token we issued is properly signed by the private key of the ephemeral "OIDC Session Keypair".
    /// - The OIDC account is in the backup factors (by matching the subject and email address).
    async fn validate_oidc_authentication(
        &self,
        oidc_token: &OidcToken,
        public_key: &str,
        signature: &str,
        challenge_token_payload: &[u8],
        expected_factor_scope: FactorScope,
    ) -> Result<(String, BackupMetadata), ErrorResponse> {
        let claims = self
            .oidc_token_verifier
            .verify_token(oidc_token, public_key.to_string())
            .await?;

        verify_signature(public_key, signature, challenge_token_payload)?;

        let oidc_factor = match oidc_token {
            OidcToken::Google { .. } | OidcToken::Apple { .. } => {
                FactorToLookup::from_oidc_account(
                    claims.issuer().to_string(),
                    claims.subject().to_string(),
                )
            }
        };

        let not_verified_backup_id = self
            .factor_lookup
            .lookup(expected_factor_scope, &oidc_factor)
            .await?;

        let Some(not_verified_backup_id) = not_verified_backup_id else {
            tracing::info!(message = "No backup ID found for the given OIDC account");
            return Err(ErrorResponse::bad_request("backup_not_found"));
        };

        let backup_metadata = self
            .backup_storage
            .get_metadata_by_backup_id(&not_verified_backup_id)
            .await?;

        let Some((backup_metadata, _e_tag)) = backup_metadata else {
            tracing::info!(message = "No backup metadata found for the given backup ID");
            return Err(ErrorResponse::bad_request("oidc_account_error"));
        };

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
                    }
                    | OidcAccountKind::Apple {
                        sub,
                        email: factor_email,
                    } => sub == &claims.subject().to_string() && factor_email == &email,
                }
            } else {
                false
            }
        });

        if !is_oidc_account_in_factors {
            tracing::info!(message = "OIDC account not found in backup factors. This should be a rare case where the FactorLookup is out of sync.");
            return Err(ErrorResponse::bad_request("oidc_account_error"));
        }

        // At this point the backup is now authenticated and authorized.
        let verified_backup_id = not_verified_backup_id;

        Ok((verified_backup_id, backup_metadata))
    }

    //------------------------------------------------------------------------------------------------
    // Internal: Elliptic Curve Keypair Validation
    //------------------------------------------------------------------------------------------------

    /// Validates a **new** EC keypair is valid for registration.
    ///
    /// To allow a new EC keypair to be registered, we check that the issued challenge is properly signed (proving the user holds the private key).
    fn validate_ec_keypair_registration(
        public_key: &str,
        signature: &str,
        challenge_token_payload: &[u8],
    ) -> Result<(Factor, FactorToLookup), ErrorResponse> {
        verify_signature(public_key, signature, challenge_token_payload)?;

        let factor = Factor::new_ec_keypair(public_key.to_string());
        let factor_to_lookup = FactorToLookup::from_ec_keypair(public_key.to_string());

        Ok((factor, factor_to_lookup))
    }

    /// Validates an action is authenticated and authorized for an **existing** backup with an EC keypair.
    ///
    /// To allow an action to be performed, we check that the issued challenge is properly signed by the keypair authorized **in the user's backup**.
    async fn authenticate_ec_keypair(
        &self,
        public_key: &str,
        signature: &str,
        challenge_token_payload: &[u8],
        expected_factor_scope: FactorScope,
    ) -> Result<(String, BackupMetadata), ErrorResponse> {
        verify_signature(public_key, signature, challenge_token_payload)?;

        let not_verified_backup_id = self
            .factor_lookup
            .lookup(
                expected_factor_scope,
                &FactorToLookup::from_ec_keypair(public_key.to_string()),
            )
            .await?;

        let Some(not_verified_backup_id) = not_verified_backup_id else {
            tracing::info!(message = "No backup ID found for the given EC keypair.");
            return Err(ErrorResponse::bad_request("backup_not_found"));
        };

        let backup_metadata = self
            .backup_storage
            .get_metadata_by_backup_id(&not_verified_backup_id)
            .await?;
        let Some((backup_metadata, _e_tag)) = backup_metadata else {
            tracing::info!(message = "No backup metadata found for the given backup ID");
            return Err(ErrorResponse::bad_request("backup_not_found"));
        };

        let factors = if expected_factor_scope == FactorScope::Sync {
            &backup_metadata.sync_factors
        } else {
            &backup_metadata.factors
        };

        // This is the source of truth as to what is an authorized factor, the FactorLookup is only a utility to faciliate lookup.
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
            tracing::warn!(message = "Public key not found in backup factors. This should be a rare case where the FactorLookup is out of sync.");
            return Err(ErrorResponse::bad_request("keypair_error"));
        }

        // At this point the backup is now authenticated and authorized.
        let verified_backup_id = not_verified_backup_id;

        Ok((verified_backup_id, backup_metadata))
    }
}
