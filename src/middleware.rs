use crate::types::{Environment, ErrorResponse};
use axum::{
    body::Body,
    http::{Request, Response},
    middleware::Next,
    Extension,
};

/// Middleware to validate Content-Length header before body parsing.
///
/// This allows us to reject bona fide oversized requests early with a custom error message,
/// before Axum's multipart parser reads the body and returns a generic error.
///
/// # Errors
/// - Will return an error if the Content-Length header exceeds the maximum allowed size.
pub async fn validate_content_length(
    Extension(environment): Extension<Environment>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, ErrorResponse> {
    // Check if Content-Length header exists
    if let Some(content_length_header) = req.headers().get("content-length") {
        if let Ok(content_length_str) = content_length_header.to_str() {
            if let Ok(content_length) = content_length_str.parse::<usize>() {
                let max_allowed = environment.max_backup_file_size() + 1024 * 1024; // 1MB overhead for metadata

                if content_length > max_allowed {
                    tracing::debug!(
                        message = "Request Content-Length exceeds maximum allowed size",
                        content_length = content_length,
                        max_allowed = max_allowed
                    );
                    return Err(ErrorResponse::bad_request(
                        "backup_file_too_large",
                        "Backup file too large",
                    ));
                }
            }
        }
    }

    // Content-Length is acceptable or not present, proceed with request
    Ok(next.run(req).await)
}
