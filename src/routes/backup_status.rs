use std::sync::Arc;

use axum::{Extension, Json};
use types::{BackupStatusRequest, BackupStatusResponse, ExportedFactorSlim};

use crate::{backup_metadata::FactorKind, backup_storage::BackupStorage, error::ErrorResponse};

/// This public endpoint is used to check whether a backup exists and what are the factors associated with it.
///
/// It is used by the client when the user is logged in to a specific account but their device is not authorized
/// with a sync factor. This endpoint is public but requires knowing the high entropy of the backup ID. Does not change any state.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Json(request): Json<BackupStatusRequest>,
) -> Result<Json<BackupStatusResponse>, ErrorResponse> {
    let metadata = backup_storage
        .get_metadata_by_backup_id(&request.backup_id)
        .await?;

    let metadata = match metadata {
        Some(metadata) => metadata,
        None => return Err(ErrorResponse::not_found()),
    }
    .0;

    let factors: Vec<ExportedFactorSlim> = metadata
        .factors
        .iter()
        .map(|factor| ExportedFactorSlim {
            kind: factor.as_flattened_kind().to_string(),
            account_kind: match &factor.kind {
                FactorKind::OidcAccount { account, .. } => {
                    Some(account.as_flattened_kind().to_string())
                }
                _ => None,
            },
        })
        .collect();

    let response = BackupStatusResponse {
        backup_id: request.backup_id,
        factors,
    };

    Ok(Json(response))
}
