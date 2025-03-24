use aide::axum::{
    routing::{get, post},
    ApiRouter,
};

mod create_backup;
mod docs;
mod health;

pub fn handler() -> ApiRouter {
    ApiRouter::new()
        .merge(docs::handler())
        .api_route("/health", get(health::handler))
        .api_route("/create-backup", post(create_backup::handler))
}
