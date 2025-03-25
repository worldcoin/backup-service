use aide::OperationOutput;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug)]
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
