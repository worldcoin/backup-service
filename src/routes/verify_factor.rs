use crate::auth::AuthHandler;
use crate::challenge_manager::ChallengeContext;
use crate::factor_lookup::FactorScope;
use crate::types::{Authorization, ErrorResponse};
use aide::transform::TransformOperation;
use axum::{Extension, Json};
use http::HeaderMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorRequest {
    authorization: Authorization,
    challenge_token: String,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorResponse {
    backup_id: String,
}

pub fn docs(op: TransformOperation) -> TransformOperation {
    op.description(
        "Authenticate with main factor and return the associated backup ID. Does not return the backup payload. This endpoint can be used by clients to verify the user still has access to up-to-date login methods. This endpoint requires Attestation Gateway checks (through the `attestation-token` header).",
    )
    .security_requirement("AttestationToken")
}

/// Authenticate a main factor and return the associated backup ID.
pub async fn handler(
    Extension(auth_handler): Extension<AuthHandler>,
    headers: HeaderMap,
    request: Json<VerifyFactorRequest>,
) -> Result<Json<VerifyFactorResponse>, ErrorResponse> {
    let (backup_id, _backup_metadata) = auth_handler
        .verify(
            &request.authorization,
            FactorScope::Main,
            ChallengeContext::VerifyFactor {},
            request.challenge_token.clone(),
        )
        .await?;

    let client_version = headers
        .get("client-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let client_name = headers
        .get("client-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let span = tracing::info_span!("verify_factor", backup_id = %backup_id, client_version = %client_version, client_name = %client_name);

    async move { Ok(Json(VerifyFactorResponse { backup_id })) }
        .instrument(span)
        .await
}
