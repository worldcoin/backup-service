use crate::attestation_gateway::AttestationGatewayError;
use crate::auth::AuthError;
use crate::backup_storage::BackupManagerError;
use crate::challenge_manager::ChallengeManagerError;
use crate::factor_lookup::FactorLookupError;
use crate::oidc_token_verifier::OidcTokenVerifierError;
use crate::redis_cache::RedisCacheError;
use crate::turnkey_activity::TurnkeyActivityError;
use crate::verify_signature::VerifySignatureError;
use aide::OperationOutput;
use aws_sdk_dynamodb::error::SdkError;
use axum::extract::multipart::MultipartError;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use openidconnect::DiscoveryError;
use schemars::JsonSchema;
use serde::Serialize;
use std::error::Error;
use webauthn_rs::prelude::WebauthnError;

#[derive(Debug, Clone)]
pub struct ErrorResponse {
    code: String,
    message: String,
    status: StatusCode,
}

impl ErrorResponse {
    #[must_use]
    pub fn internal_server_error() -> Self {
        Self {
            code: "internal_server_error".to_string(),
            message: "Internal server error".to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn bad_request(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            status: StatusCode::BAD_REQUEST,
        }
    }

    #[must_use]
    pub fn unauthorized() -> Self {
        Self {
            code: "unauthorized".to_string(),
            message: "Unauthorized".to_string(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    #[must_use]
    pub fn locked() -> Self {
        Self {
            code: "conflicting_lock".to_string(),
            message: "Conflicting lock on resource".to_string(),
            status: StatusCode::LOCKED,
        }
    }

    #[must_use]
    pub fn conflict(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            status: StatusCode::CONFLICT,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ErrorResponseSchema {
    allow_retry: bool,
    error: ErrorResponseObject,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ErrorResponseObject {
    code: String,
    message: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(ErrorResponseSchema {
                allow_retry: false,
                error: ErrorResponseObject {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

impl OperationOutput for ErrorResponse {
    type Inner = Self;

    fn operation_response(
        ctx: &mut aide::generate::GenContext,
        operation: &mut aide::openapi::Operation,
    ) -> Option<aide::openapi::Response> {
        Json::<ErrorResponseSchema>::operation_response(ctx, operation)
    }
}

impl From<WebauthnError> for ErrorResponse {
    fn from(err: WebauthnError) -> Self {
        match err {
            WebauthnError::Configuration => {
                tracing::error!(message = "Webauthn configuration error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            // User interaction issues which are safe to expose
            WebauthnError::UserNotPresent
            | WebauthnError::UserNotVerified
            | WebauthnError::CredentialNotFound
            | WebauthnError::CredentialAlreadyExists
            | WebauthnError::InvalidClientDataType
            | WebauthnError::InvalidUsername
            | WebauthnError::InvalidRPOrigin
            | WebauthnError::InvalidRPIDHash
            | WebauthnError::AuthenticationFailure => {
                tracing::info!(message = "Passkey webauthn error (safe to expose)", error = ?err);
                ErrorResponse::bad_request("webauthn_error", &err.to_string())
            }
            // Generic catch-all for all other errors
            _ => {
                tracing::info!(message = "Passkey webauthn error", error = ?err);
                ErrorResponse::bad_request(
                    "webauthn_error",
                    "Authentication failed with passkey. Please try again.",
                )
            }
        }
    }
}

impl From<serde_json::Error> for ErrorResponse {
    fn from(err: serde_json::Error) -> Self {
        tracing::warn!(message = "Serde JSON error", error = ?err);
        ErrorResponse::internal_server_error()
    }
}

impl From<MultipartError> for ErrorResponse {
    fn from(err: MultipartError) -> Self {
        tracing::info!(message = "Error when reading Multipart form data", error = ?err);
        ErrorResponse::bad_request("multipart_error", "Error reading multipart form data")
    }
}

impl From<AuthError> for ErrorResponse {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::BackupMissing => {
                tracing::warn!(message = "Backup is missing from storage but found in factor lookup (signals out-of-sync state)");
                Self::bad_request(&err.to_string(), &err.to_string())
            }
            AuthError::BackupUntraceable
            | AuthError::BackupDoesNotExist
            | AuthError::BackupIdMismatch
            | AuthError::FactorNotFound
            | AuthError::InvalidAuthorizationType
            | AuthError::InvalidChallengeContext
            | AuthError::InvalidSyncFactorType
            | AuthError::MissingTurnkeyProviderId
            | AuthError::WebauthnPrfResultsNotAllowed
            | AuthError::MissingEmail => {
                tracing::debug!(message = "Client-side auth failure", error = ?err);
                Self::bad_request(
                    &err.to_string(),
                    &format!("Client-side auth failure: {err}"),
                )
            }
            AuthError::WebauthnClientError => {
                // no additional logging is needed as where relevant it's handled by the auth module
                Self::bad_request("webauthn_client_error", "WebAuthn client error occurred.")
            }
            AuthError::PasskeySerializationError { err } => {
                tracing::error!(message = "Passkey serialization error", error = ?err);
                Self::internal_server_error()
            }
            AuthError::WebauthnServerError { err } => {
                tracing::error!(message = "Webauthn server error", error = ?err);
                Self::internal_server_error()
            }
            AuthError::UnauthorizedFactor => {
                tracing::warn!(message = "Unauthorized factor. Provided factor is in `FactorLookup` but is no longer authorized for the backup.");
                Self::bad_request(
                    &err.to_string(),
                    "The provided factor is not authorized for this backup.",
                )
            }
            AuthError::FactorLookupError(e) => e.into(),
            AuthError::ChallengeManagerError(e) => e.into(),
            AuthError::RedisCacheError(e) => e.into(),
            AuthError::BackupManagerError(e) => e.into(),
            AuthError::OidcTokenVerifierError(e) => e.into(),
            AuthError::VerifySignatureError(e) => e.into(),
        }
    }
}

impl From<ChallengeManagerError> for ErrorResponse {
    fn from(err: ChallengeManagerError) -> Self {
        match &err {
            ChallengeManagerError::SetClaim(_)
            | ChallengeManagerError::EncryptToken(_)
            | ChallengeManagerError::TokioError(_) => {
                tracing::warn!(message = "Challenge manager error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            ChallengeManagerError::FailedToDecryptToken(_)
            | ChallengeManagerError::NoValidPayloadClaim
            | ChallengeManagerError::NoValidChallengeTypeClaim
            | ChallengeManagerError::NoValidChallengeContextClaim
            | ChallengeManagerError::TokenExpiredOrNoExpiration => {
                tracing::debug!(message = "Challenge manager client failure", error = ?err);
                ErrorResponse::bad_request("jwt_error", "Invalid or expired token.")
            }
            ChallengeManagerError::UnexpectedChallengeType {
                expected: _,
                actual: _,
            } => {
                tracing::debug!(message = err.to_string(), error = ?err);
                ErrorResponse::bad_request(
                    "unexpected_challenge_type",
                    "The challenge type does not match the expected type.",
                )
            }
        }
    }
}

impl From<BackupManagerError> for ErrorResponse {
    fn from(err: BackupManagerError) -> Self {
        match &err {
            BackupManagerError::PutObjectError(_)
            | BackupManagerError::SerdeJsonError(_)
            | BackupManagerError::GetObjectError(_)
            | BackupManagerError::HeadObjectError(_)
            | BackupManagerError::ByteStreamError(_)
            | BackupManagerError::DeleteObjectError(_) => {
                tracing::error!(message = "Backup Manager Error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            BackupManagerError::SyncFactorMustBeKeypair => {
                tracing::info!(message = "Sync factor must be a keypair", error = ?err);
                ErrorResponse::bad_request(
                    "sync_factor_must_be_keypair",
                    "Sync factor must be a keypair.",
                )
            }
            BackupManagerError::BackupNotFound => {
                tracing::info!(message = "Backup not found", error = ?err);
                ErrorResponse::bad_request("backup_not_found", "Backup not found.")
            }
            BackupManagerError::ETagNotFound => {
                tracing::info!(message = "ETag not found", error = ?err);
                ErrorResponse::internal_server_error()
            }
            BackupManagerError::FactorAlreadyExists => {
                tracing::info!(message = "Factor already exists", error = ?err);
                ErrorResponse::bad_request("factor_already_exists", "This factor already exists.")
            }
            BackupManagerError::FactorNotFound => {
                tracing::info!(message = "Factor not found", error = ?err);
                ErrorResponse::bad_request("factor_not_found", "Factor not found.")
            }
            BackupManagerError::EncryptionKeyNotFound => {
                tracing::info!(message = "Encryption key not found", error = ?err);
                ErrorResponse::bad_request("encryption_key_not_found", "Encryption key not found.")
            }
            BackupManagerError::ManifestHashMismatch => {
                tracing::info!(message = BackupManagerError::ManifestHashMismatch.to_string());
                ErrorResponse {
                    code: "manifest_hash_mismatch".to_string(),
                    message: "The manifest hash does not match the expected value.".to_string(),
                    status: StatusCode::PRECONDITION_FAILED,
                }
            }
            BackupManagerError::FactorOrphanedFromEncryptionKey => {
                tracing::info!(message = "Factor would be orphaned by removing the specific encryption key.", error = ?err);
                ErrorResponse::bad_request(
                    "factor_orphaned_from_encryption_key",
                    "Cannot remove encryption key as it would orphan an existing factor.",
                )
            }
            BackupManagerError::OnlyOneEncryptionKeyPerTypeAllowed => {
                tracing::info!(message = "Only one encryption key per type is allowed", error = ?err);
                ErrorResponse::bad_request(
                    "only_one_encryption_key_per_type_allowed",
                    "Only one encryption key per type is allowed.",
                )
            }
        }
    }
}

impl<T: Error> From<DiscoveryError<T>> for ErrorResponse {
    fn from(err: DiscoveryError<T>) -> Self {
        tracing::error!(message = "OIDC discovery error", error = ?err);
        ErrorResponse::internal_server_error()
    }
}

impl From<FactorLookupError> for ErrorResponse {
    fn from(err: FactorLookupError) -> Self {
        match &err {
            FactorLookupError::DynamoDbPutError(inner) => match &inner {
                SdkError::ServiceError(inner)
                    if inner.err().is_conditional_check_failed_exception() =>
                {
                    tracing::info!(message = "Factor already exists", error = ?err);
                    ErrorResponse::bad_request(
                        "factor_already_exists",
                        "This factor already exists.",
                    )
                }
                _ => {
                    tracing::error!(message = "DynamoDB put error", error = ?err);
                    ErrorResponse::internal_server_error()
                }
            },
            FactorLookupError::DynamoDbGetError(_)
            | FactorLookupError::DynamoDbDeleteError(_)
            | FactorLookupError::DynamoDbQueryError(_)
            | FactorLookupError::ParseBackupIdError => {
                tracing::info!(message = "Factor lookup error", error = ?err);
                ErrorResponse::internal_server_error()
            }
        }
    }
}

impl From<VerifySignatureError> for ErrorResponse {
    fn from(err: VerifySignatureError) -> Self {
        tracing::info!(message = "Signature verification error", error = ?err);
        ErrorResponse::bad_request(
            "signature_verification_error",
            "Signature verification failed.",
        )
    }
}

impl From<OidcTokenVerifierError> for ErrorResponse {
    fn from(err: OidcTokenVerifierError) -> Self {
        match err {
            OidcTokenVerifierError::JwkSetFetchError => {
                tracing::error!(message = "Failed to fetch JWK set from OIDC provider", error = ?err);
                ErrorResponse::internal_server_error()
            }
            OidcTokenVerifierError::TokenParseError => {
                tracing::info!(message = "Failed to parse OIDC token", error = ?err);
                ErrorResponse::bad_request("oidc_token_parse_error", "Failed to parse OIDC token.")
            }
            OidcTokenVerifierError::TokenVerificationError => {
                tracing::info!(message = "Failed to verify OIDC token", error = ?err);
                ErrorResponse::bad_request(
                    "oidc_token_verification_error",
                    "Failed to verify OIDC token.",
                )
            }
            OidcTokenVerifierError::MissingNonce => {
                tracing::info!(message = "OIDC token is missing nonce claim", error = ?err);
                ErrorResponse::bad_request(
                    "oidc_token_parse_error",
                    "OIDC token is missing required nonce claim.",
                )
            }
            OidcTokenVerifierError::RedisCacheError(e) => e.into(),
        }
    }
}

impl From<TurnkeyActivityError> for ErrorResponse {
    fn from(err: TurnkeyActivityError) -> Self {
        tracing::info!(message = "Turnkey activity error", error = ?err);
        ErrorResponse::bad_request("turnkey_activity_error", &err.to_string())
    }
}

impl From<AttestationGatewayError> for ErrorResponse {
    fn from(err: AttestationGatewayError) -> Self {
        match &err {
            AttestationGatewayError::FetchJwkSet(_)
            | AttestationGatewayError::JwkSetIsNotObject
            | AttestationGatewayError::ParseJwkSet(_)
            | AttestationGatewayError::CreateVerifier(_)
            | AttestationGatewayError::SerializeRequestPayload(_) => {
                tracing::error!(message = "Attestation Gateway error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            _ => {
                tracing::info!(message = "Invalid attestation token", error = ?err);
                ErrorResponse::bad_request(
                    "invalid_attestation_token",
                    "Invalid attestation token.",
                )
            }
        }
    }
}

impl From<RedisCacheError> for ErrorResponse {
    fn from(err: RedisCacheError) -> Self {
        match &err {
            RedisCacheError::RedisError(_) => {
                tracing::error!(message = "Redis cache error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            RedisCacheError::ParseError(_) | RedisCacheError::EncodingError => {
                tracing::error!(message = "Redis cache parse/encoding error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            RedisCacheError::TokenNotFound => {
                tracing::info!(message = "Token not found", error = ?err);
                ErrorResponse::bad_request("token_not_found", "Token not found.")
            }
            RedisCacheError::AlreadyUsed => {
                tracing::info!(message = "Token already used", error = ?err);
                ErrorResponse::bad_request("already_used", "Token has already been used.")
            }
            RedisCacheError::TokenExpired => {
                tracing::info!(message = "Token expired", error = ?err);
                ErrorResponse::bad_request("token_expired", "Token has expired.")
            }
            RedisCacheError::Locked => {
                tracing::info!(message = "Conflicting lock", error = ?err);
                ErrorResponse::locked()
            }
        }
    }
}
