use aide::axum::{
    routing::{get, post},
    ApiRouter,
};

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
        .api_route("/create", post(create_backup::handler))
}
