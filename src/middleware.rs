use crate::environment::Environment;
use crate::error::ErrorResponse;
use axum::{
    body::Body,
    http::{header::CONTENT_LENGTH, Request, Response},
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
    if let Some(content_length) = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length > environment.max_request_size())
    {
        tracing::debug!(
            message = "Request Content-Length exceeds maximum allowed size.",
            content_length = content_length,
        );
        return Err(ErrorResponse::content_too_large(format!(
            "Request body of {content_length} bytes is too large.",
        )));
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, middleware, routing::post, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn middleware_enforces_content_length_when_present() {
        let environment = Environment::development(None);
        let max_request_size = environment.max_request_size();
        let app = Router::new()
            .route("/", post(|| async { StatusCode::OK }))
            .route_layer(middleware::from_fn(validate_content_length))
            .layer(Extension(environment));

        let at_limit = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-length", max_request_size)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(at_limit).await.unwrap().status(),
            StatusCode::OK
        );

        let over_limit = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-length", max_request_size + 1)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(over_limit).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let without_header = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(without_header).await.unwrap().status(),
            StatusCode::OK
        );
    }
}
