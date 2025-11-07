use std::sync::Arc;

use axum::{extract::Path, Extension, Json};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    backup_storage::BackupStorage,
    types::{backup_metadata::FactorKind, ErrorResponse},
};

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExportedFactorSlim {
    /// The kind of factor. E.g. `"PASSKEY"`, `"EC_KEYPAIR"`, `"OIDC_ACCOUNT"`.
    kind: String,
    /// The kind of account if the factor is an OIDC account. E.g. `"GOOGLE"`, `"APPLE"`.
    account_kind: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatusResponse {
    /// The ID of the backup.
    backup_id: String,
    /// The flattened list of factor kinds associated with the backup. E.g. `["PASSKEY", "EC_KEYPAIR"]`.
    factors: Vec<ExportedFactorSlim>,
}

/// This public endpoint is used to check whether a backup exists and what are the factors associated with it.
///
/// It is used by the client when the user is logged in to a specific account but their device is not authorized
/// with a sync factor. This endpoint is public but requires knowing the high entropy of the backup ID. Does not change any state.
pub async fn handler(
    Extension(backup_storage): Extension<Arc<BackupStorage>>,
    Path(backup_id): Path<String>,
) -> Result<Json<BackupStatusResponse>, ErrorResponse> {
    let metadata = backup_storage.get_metadata_by_backup_id(&backup_id).await?;

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

    let response = BackupStatusResponse { backup_id, factors };

    Ok(Json(response))
}
