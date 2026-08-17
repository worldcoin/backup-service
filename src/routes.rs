use crate::attestation_gateway::AttestationGateway;
use crate::environment::Environment;
use crate::middleware::validate_content_length;
use aide::axum::routing::post_with;
use aide::axum::{
    routing::{get, post},
    ApiRouter,
};
use axum::{extract::DefaultBodyLimit, middleware};
use types::endpoints::{
    AddFactorChallengeRequest, AddFactorRequest, AddSyncFactorChallengeKeypairRequest,
    AddSyncFactorRequest, BackupStatusRequest, CreateBackupRequest, CreateChallengeKeypairRequest,
    CreateChallengePasskeyRequest, DeleteBackupChallengeKeypairRequest, DeleteBackupRequest,
    DeleteFactorChallengeKeypairRequest, DeleteFactorRequest, Endpoint,
    ResetChallengeKeypairRequest, ResetRequest, RetrieveBackupFromChallengeRequest,
    RetrieveChallengeKeypairRequest, RetrieveMetadataChallengeKeypairRequest,
    RetrieveMetadataRequest, SyncBackupRequest, SyncChallengeKeypairRequest,
    VerifyFactorChallengeKeypairRequest, VerifyFactorRequest, HEALTH_PATH, READY_PATH,
    RETRIEVE_CHALLENGE_PASSKEY_PATH, VERIFY_FACTOR_CHALLENGE_PASSKEY_PATH,
};

mod add_factor;
mod add_factor_challenge;
mod add_sync_factor;
mod backup_status;
mod challenge_contexts;
mod create_backup;
mod create_challenge_passkey;
mod delete_backup;
mod delete_factor;
mod docs;
mod health;
mod keypair_challenge;
mod ready;
mod reset;
mod retrieve_challenge_passkey;
mod retrieve_from_challenge;
mod retrieve_metadata;
mod sync_backup;
mod verify_factor;
mod verify_factor_challenge_passkey;

/// Builds the router. Paths come from [`types::endpoints`]
pub fn handler(environment: Environment) -> ApiRouter {
    ApiRouter::new()
        .merge(docs::handler())
        .api_route(HEALTH_PATH, get(health::handler))
        .api_route(READY_PATH, get(ready::handler))
        // Public
        .api_route(BackupStatusRequest::PATH, post(backup_status::handler))
        // Create new backup
        .api_route(
            CreateChallengePasskeyRequest::PATH,
            post(create_challenge_passkey::handler),
        )
        .api_route(
            CreateChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<CreateChallengeKeypairRequest>),
        )
        .api_route(
            CreateBackupRequest::PATH,
            post(create_backup::handler)
                .route_layer(middleware::from_fn(validate_content_length))
                .layer(DefaultBodyLimit::max(environment.max_request_size())),
        )
        // Recovery
        .api_route(
            RETRIEVE_CHALLENGE_PASSKEY_PATH,
            post(retrieve_challenge_passkey::handler),
        )
        .api_route(
            RetrieveChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<RetrieveChallengeKeypairRequest>),
        )
        .api_route(
            RetrieveBackupFromChallengeRequest::PATH,
            post_with(
                retrieve_from_challenge::handler,
                retrieve_from_challenge::docs,
            )
            .route_layer(middleware::from_fn(AttestationGateway::validator)),
        )
        // Verify factor (authenticate a main factor without retrieving the backup)
        .api_route(
            VERIFY_FACTOR_CHALLENGE_PASSKEY_PATH,
            post(verify_factor_challenge_passkey::handler),
        )
        .api_route(
            VerifyFactorChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<VerifyFactorChallengeKeypairRequest>),
        )
        .api_route(
            VerifyFactorRequest::PATH,
            post_with(verify_factor::handler, verify_factor::docs)
                .route_layer(middleware::from_fn(AttestationGateway::validator)),
        )
        // Add new factor for future sync after recovery
        .api_route(
            AddSyncFactorChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<AddSyncFactorChallengeKeypairRequest>),
        )
        .api_route(AddSyncFactorRequest::PATH, post(add_sync_factor::handler))
        // Add factor to the backup - new OIDC account, new passkey, etc.
        .api_route(
            AddFactorChallengeRequest::PATH,
            post(add_factor_challenge::handler),
        )
        .api_route(AddFactorRequest::PATH, post(add_factor::handler))
        // Backup sync
        .api_route(
            SyncChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<SyncChallengeKeypairRequest>),
        )
        .api_route(
            SyncBackupRequest::PATH,
            post(sync_backup::handler)
                .route_layer(middleware::from_fn(validate_content_length))
                .layer(DefaultBodyLimit::max(environment.max_request_size())),
        )
        // Metadata retrieval
        .api_route(
            RetrieveMetadataChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<RetrieveMetadataChallengeKeypairRequest>),
        )
        .api_route(
            RetrieveMetadataRequest::PATH,
            post(retrieve_metadata::handler),
        )
        // Delete factor
        .api_route(
            DeleteFactorChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<DeleteFactorChallengeKeypairRequest>),
        )
        .api_route(
            DeleteFactorRequest::PATH,
            post_with(delete_factor::handler, delete_factor::docs)
                .route_layer(middleware::from_fn(AttestationGateway::validator)),
        )
        // Delete backup
        .api_route(
            DeleteBackupChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<DeleteBackupChallengeKeypairRequest>),
        )
        .api_route(DeleteBackupRequest::PATH, post(delete_backup::handler))
        // Reset backup (when all factors are lost)
        .api_route(
            ResetChallengeKeypairRequest::PATH,
            post(keypair_challenge::handler::<ResetChallengeKeypairRequest>),
        )
        .api_route(ResetRequest::PATH, post(reset::handler))
}
