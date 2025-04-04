use crate::types::Environment;
use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use axum::extract::DefaultBodyLimit;

mod create_backup;
mod create_challenge_passkey;
mod docs;
mod health;

pub fn handler(environment: Environment) -> ApiRouter {
    ApiRouter::new()
        .merge(docs::handler())
        .api_route("/health", get(health::handler))
        .api_route(
            "/create/challenge/passkey",
            post(create_challenge_passkey::handler),
        )
        .api_route(
            "/create",
            // Use 2x backup limit for payload size in order to support backup uploads with some
            // extra buffer for JSON data.
            post(create_backup::handler).layer(DefaultBodyLimit::max(
                2 * environment.max_backup_file_size(),
            )),
        )
}
