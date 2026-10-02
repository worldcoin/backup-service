use std::sync::Arc;

use crate::backup_storage::BackupStorage;
use crate::environment::Environment;
use crate::error::ErrorResponse;
use crate::factor_lookup::FactorLookup;
use crate::redis_cache::RedisCacheManager;
use aide::transform::TransformOperation;
use axum::{Extension, Json};
use tracing::Instrument;
use types::{FactorScope, ReclaimSyncFactorSlotRequest, ReclaimSyncFactorSlotResponse};

pub fn docs(op: TransformOperation) -> TransformOperation {
    op.description(
        "Reclaims one stale sync-factor slot after a Main-factor-authenticated recovery. The endpoint requires Attestation Gateway checks (through the `attestation-token` header).",
    )
    .security_requirement("AttestationToken")
}

/// Reclaims one stale sync-factor slot using a short-lived capability minted during recovery.
///
/// This is deliberately not a general main-factor delete API: it accepts no factor ID, can only
/// operate at the sync-factor cap, and removes at most the oldest server-defined stale factor.
pub async fn handler(
    Extension(environment): Extension<Environment>,
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Extension(factor_lookup): Extension<Arc<FactorLookup>>,
    Extension(redis_cache_manager): Extension<Arc<RedisCacheManager>>,
    request: Json<ReclaimSyncFactorSlotRequest>,
) -> Result<Json<ReclaimSyncFactorSlotResponse>, ErrorResponse> {
    let backup_id = redis_cache_manager
        .use_sync_factor_maintenance_token(request.sync_factor_maintenance_token.clone())
        .await?;
    let span = tracing::info_span!("reclaim_sync_factor_slot", backup_id = %backup_id);

    async move {
        let Some((removed, _metadata)) = backup_storage
            .reclaim_stale_sync_factor_slot(&backup_id)
            .await?
        else {
            tracing::info!("No stale sync factor was eligible for reclamation");
            return Ok(Json(ReclaimSyncFactorSlotResponse { reclaimed: false }));
        };

        // Metadata is the source of truth. A lookup-delete failure is explicitly degraded rather
        // than reported as a failed reclaim, because retrying would consume another recovery
        // capability even though the slot is already available.
        if let Err(error) = factor_lookup
            .delete(
                FactorScope::Sync,
                &removed.as_factor_to_lookup(&environment),
            )
            .await
        {
            tracing::warn!(
                error = ?error,
                factor_id = %removed.id,
                "Sync factor reclaimed from metadata but lookup cleanup failed"
            );
        }

        tracing::info!(factor_id = %removed.id, "Reclaimed stale sync factor slot");
        Ok(Json(ReclaimSyncFactorSlotResponse { reclaimed: true }))
    }
    .instrument(span)
    .await
}
