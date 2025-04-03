use crate::challenge_manager::ChallengeManagerError;
use aide::OperationOutput;
use axum::extract::multipart::MultipartError;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use schemars::JsonSchema;
use serde::Serialize;
use webauthn_rs::prelude::WebauthnError;

#[derive(Debug, Clone)]
pub struct ErrorResponse {
    error: String,
    status: StatusCode,
}

impl ErrorResponse {
    pub fn internal_server_error() -> Self {
        Self {
            error: "internal_server_error".to_string(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn bad_request(message: &str) -> Self {
        Self {
            error: message.to_string(),
            status: StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct ErrorResponseSchema {
    error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(ErrorResponseSchema { error: self.error })).into_response()
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
            _ => {
                tracing::info!(message = "Passkey webauthn error", error = ?err);
                ErrorResponse::bad_request("webauthn_error")
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
            | ChallengeManagerError::TokenExpiredOrNoExpiration => {
                tracing::info!(message = "Challenge manager error", error = ?err);
                ErrorResponse::bad_request("jwt_error")
            }
        }
    }
}
