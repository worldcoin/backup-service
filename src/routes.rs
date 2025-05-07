use crate::types::Environment;
use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use axum::extract::DefaultBodyLimit;

mod add_oidc_account;
mod create_backup;
mod create_challenge_keypair;
mod create_challenge_passkey;
mod docs;
mod health;
mod retrieve_challenge_keypair;
mod retrieve_challenge_passkey;
mod retrieve_from_challenge;
mod sync_backup;
mod sync_challenge_keypair;

pub fn handler(environment: Environment) -> ApiRouter {
    ApiRouter::new()
        .merge(docs::handler())
        .api_route("/health", get(health::handler))
        .api_route(
            "/create/challenge/passkey",
            post(create_challenge_passkey::handler),
        )
        .api_route(
            "/create/challenge/keypair",
            post(create_challenge_keypair::handler),
        )
        .api_route(
            "/create",
            // Use 2x backup limit for payload size in order to support backup uploads with some
            // extra buffer for JSON data.
            post(create_backup::handler).layer(DefaultBodyLimit::max(
                2 * environment.max_backup_file_size(),
            )),
        )
        .api_route("/add-oidc-account", post(add_oidc_account::handler))
        .api_route(
            "/retrieve/challenge/passkey",
            post(retrieve_challenge_passkey::handler),
        )
        .api_route(
            "/retrieve/challenge/keypair",
            post(retrieve_challenge_keypair::handler),
        )
        .api_route(
            "/retrieve/from-challenge",
            post(retrieve_from_challenge::handler),
        )
        .api_route(
            "/sync/challenge/keypair",
            post(sync_challenge_keypair::handler),
        )
        .api_route("/sync", post(sync_backup::handler))
}
