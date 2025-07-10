use crate::attestation_gateway::AttestationGatewayError;
use crate::backup_storage::BackupManagerError;
use crate::challenge_manager::ChallengeManagerError;
use crate::dynamo_cache::DynamoCacheError;
use crate::factor_lookup::FactorLookupError;
use crate::oidc_token_verifier::OidcTokenVerifierError;
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
    pub error: String,
    status: StatusCode,
}

impl ErrorResponse {
    #[must_use]
    pub fn internal_server_error() -> Self {
        Self {
            error: "internal_server_error".to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn bad_request(message: &str) -> Self {
        Self {
            error: message.to_string(),
            status: StatusCode::BAD_REQUEST,
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
                    code: self.error.clone(),
                    message: self.error,
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
        if err == WebauthnError::Configuration {
            tracing::error!(message = "Webauthn configuration error", error = ?err);
            ErrorResponse::internal_server_error()
        } else {
            tracing::info!(message = "Passkey webauthn error", error = ?err);
            ErrorResponse::bad_request("webauthn_error")
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
        ErrorResponse::bad_request("multipart_error")
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
                tracing::info!(message = "Challenge manager error", error = ?err);
                ErrorResponse::bad_request("jwt_error")
            }
            ChallengeManagerError::UnexpectedChallengeType {
                expected: _,
                actual: _,
            } => {
                tracing::info!(message = err.to_string(), error = ?err);
                ErrorResponse::bad_request("unexpected_challenge_type")
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
            | BackupManagerError::ByteStreamError(_)
            | BackupManagerError::DeleteObjectError(_) => {
                tracing::error!(message = "Backup Manager Error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            BackupManagerError::SyncFactorMustBeKeypair => {
                tracing::info!(message = "Sync factor must be a keypair", error = ?err);
                ErrorResponse::bad_request("sync_factor_must_be_keypair")
            }
            BackupManagerError::BackupNotFound => {
                tracing::info!(message = "Backup not found", error = ?err);
                ErrorResponse::bad_request("backup_not_found")
            }
            BackupManagerError::ETagNotFound => {
                tracing::info!(message = "ETag not found", error = ?err);
                ErrorResponse::internal_server_error()
            }
            BackupManagerError::FactorAlreadyExists => {
                tracing::info!(message = "Factor already exists", error = ?err);
                ErrorResponse::bad_request("factor_already_exists")
            }
            BackupManagerError::FactorNotFound => {
                tracing::info!(message = "Factor not found", error = ?err);
                ErrorResponse::bad_request("factor_not_found")
            }
            BackupManagerError::EncryptionKeyNotFound => {
                tracing::info!(message = "Encryption key not found", error = ?err);
                ErrorResponse::bad_request("encryption_key_not_found")
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
                    ErrorResponse::bad_request("factor_already_exists")
                }
                _ => {
                    tracing::error!(message = "DynamoDB put error", error = ?err);
                    ErrorResponse::internal_server_error()
                }
            },
            FactorLookupError::DynamoDbGetError(_)
            | FactorLookupError::DynamoDbDeleteError(_)
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
        ErrorResponse::bad_request("signature_verification_error")
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
                ErrorResponse::bad_request("oidc_token_parse_error")
            }
            OidcTokenVerifierError::TokenVerificationError => {
                tracing::info!(message = "Failed to verify OIDC token", error = ?err);
                ErrorResponse::bad_request("oidc_token_verification_error")
            }
            OidcTokenVerifierError::MissingNonce => {
                tracing::info!(message = "OIDC token is missing nonce claim", error = ?err);
                ErrorResponse::bad_request("oidc_token_parse_error")
            }
            OidcTokenVerifierError::DynamoCacheError(e) => e.into(),
        }
    }
}

impl From<DynamoCacheError> for ErrorResponse {
    fn from(err: DynamoCacheError) -> Self {
        match &err {
            DynamoCacheError::DynamoDbPutError(_)
            | DynamoCacheError::DynamoDbGetError(_)
            | DynamoCacheError::DynamoDbUpdateError(_)
            | DynamoCacheError::MalformedToken
            | DynamoCacheError::ParseBackupIdError
            | DynamoCacheError::ParseExpirationError => {
                tracing::error!(message = "Sync factor token error", error = ?err);
                ErrorResponse::internal_server_error()
            }
            DynamoCacheError::TokenNotFound => {
                tracing::info!(message = "Sync factor token not found", error = ?err);
                ErrorResponse::bad_request("sync_factor_token_not_found")
            }
            DynamoCacheError::TokenExpired => {
                tracing::info!(message = "Sync factor token expired", error = ?err);
                ErrorResponse::bad_request("sync_factor_token_expired")
            }
            DynamoCacheError::AlreadyUsed => {
                tracing::info!(message = "The token or challenge has already been used", error = ?err);
                ErrorResponse::bad_request("already_used")
            }
        }
    }
}

impl From<TurnkeyActivityError> for ErrorResponse {
    fn from(err: TurnkeyActivityError) -> Self {
        tracing::info!(message = "Turnkey activity error", error = ?err);
        ErrorResponse::bad_request("webauthn_error")
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
                ErrorResponse::bad_request("invalid_attestation_token")
            }
        }
    }
}
