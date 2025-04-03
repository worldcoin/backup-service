use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use axum::extract::DefaultBodyLimit;

mod create_backup;
mod create_challenge_passkey;
mod docs;
mod health;

pub fn handler() -> ApiRouter {
    ApiRouter::new()
        .merge(docs::handler())
        .api_route("/health", get(health::handler))
        .api_route(
            "/create/challenge/passkey",
            post(create_challenge_passkey::handler),
        )
        .api_route(
            "/create",
            // Use 10MB limit for payload in order to support backup uploads
            post(create_backup::handler).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
}
