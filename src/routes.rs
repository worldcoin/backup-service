use crate::routes::create_challenge_keypair::CreateChallengeKeypairRequest;
use crate::routes::delete_backup_challenge_keypair::DeleteBackupChallengeKeypairRequest;
use crate::routes::delete_factor_challenge_keypair::DeleteFactorChallengeKeypairRequest;
use crate::routes::reset_challenge_keypair::ResetChallengeKeypairRequest;
use crate::routes::retrieve_challenge_keypair::RetrieveChallengeKeypairRequest;
use crate::routes::retrieve_metadata_challenge_keypair::RetrieveMetadataChallengeKeypairRequest;
use crate::routes::sync_challenge_keypair::SyncChallengeKeypairRequest;
use crate::types::Environment;
use crate::{
    attestation_gateway::AttestationGateway,
    routes::add_sync_factor_challenge_keypair::AddSyncFactorChallengeKeypairRequest,
};
use aide::axum::routing::post_with;
use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use axum::{extract::DefaultBodyLimit, middleware};

mod add_factor;
mod add_factor_challenge;
mod add_sync_factor;
mod add_sync_factor_challenge_keypair;
mod backup_status;
mod create_backup;
mod create_challenge_keypair;
mod create_challenge_passkey;
mod delete_backup;
mod delete_backup_challenge_keypair;
mod delete_factor;
mod delete_factor_challenge_keypair;
mod docs;
mod health;
mod keypair_challenge;
mod ready;
mod reset;
mod reset_challenge_keypair;
mod retrieve_challenge_keypair;
mod retrieve_challenge_passkey;
mod retrieve_from_challenge;
mod retrieve_metadata;
mod retrieve_metadata_challenge_keypair;
mod sync_backup;
mod sync_challenge_keypair;

pub fn handler(environment: Environment) -> ApiRouter {
    let v1_routes = ApiRouter::new()
        // Public
        .api_route("/backup/status", post(backup_status::handler))
        // Create new backup
        .api_route(
            "/create/challenge/passkey",
            post(create_challenge_passkey::handler),
        )
        .api_route(
            "/create/challenge/keypair",
            post(keypair_challenge::handler::<CreateChallengeKeypairRequest>),
        )
        .api_route(
            "/create",
            post(create_backup::handler).layer(DefaultBodyLimit::max(
                environment.max_backup_file_size() + 1024 * 1024, // 1MB buffer for metadata
            )),
        )
        // Recovery
        .api_route(
            "/retrieve/challenge/passkey",
            post(retrieve_challenge_passkey::handler),
        )
        .api_route(
            "/retrieve/challenge/keypair",
            post(keypair_challenge::handler::<RetrieveChallengeKeypairRequest>),
        )
        .api_route(
            "/retrieve/from-challenge",
            post_with(
                retrieve_from_challenge::handler,
                retrieve_from_challenge::docs,
            )
            .route_layer(middleware::from_fn(AttestationGateway::validator)),
        )
        // Add new factor for future sync after recovery
        .api_route(
            "/add-sync-factor/challenge/keypair",
            post(keypair_challenge::handler::<AddSyncFactorChallengeKeypairRequest>),
        )
        .api_route("/add-sync-factor", post(add_sync_factor::handler))
        // Add factor to the backup - new OIDC account, new passkey, etc.
        .api_route("/add-factor/challenge", post(add_factor_challenge::handler))
        .api_route("/add-factor", post(add_factor::handler))
        // Backup sync
        .api_route(
            "/sync/challenge/keypair",
            post(keypair_challenge::handler::<SyncChallengeKeypairRequest>),
        )
        .api_route(
            "/sync",
            post(sync_backup::handler).layer(DefaultBodyLimit::max(
                environment.max_backup_file_size() + 1024 * 1024, // 1MB buffer for metadata
            )),
        )
        // Metadata retrieval
        .api_route(
            "/retrieve-metadata/challenge/keypair",
            post(keypair_challenge::handler::<RetrieveMetadataChallengeKeypairRequest>),
        )
        .api_route("/retrieve-metadata", post(retrieve_metadata::handler))
        // Delete factor
        .api_route(
            "/delete-factor/challenge/keypair",
            post(keypair_challenge::handler::<DeleteFactorChallengeKeypairRequest>),
        )
        .api_route(
            "/delete-factor",
            post_with(delete_factor::handler, delete_factor::docs)
                .route_layer(middleware::from_fn(AttestationGateway::validator)),
        )
        // Delete backup
        .api_route(
            "/delete-backup/challenge/keypair",
            post(keypair_challenge::handler::<DeleteBackupChallengeKeypairRequest>),
        )
        .api_route("/delete-backup", post(delete_backup::handler))
        // Reset backup (when all factors are lost)
        .api_route(
            "/reset/challenge/keypair",
            post(keypair_challenge::handler::<ResetChallengeKeypairRequest>),
        )
        .api_route("/reset", post(reset::handler));

    // Compose the final router: keep docs & health at root, nest business logic under /v1
    ApiRouter::new()
        .merge(docs::handler())
        .api_route("/health", get(health::handler))
        .api_route("/ready", get(ready::handler))
        .nest("/v1", v1_routes)
}
