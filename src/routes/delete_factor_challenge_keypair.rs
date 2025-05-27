use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

/// Request to retrieve a challenge for keypair authentication. Used to delete a factor
/// from the backup metadata. The challenge has to be signed by the keypair that's stored
/// as a sync factor in the backup metadata.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorChallengeKeypairRequest {
    factor_id: String,
}

impl From<DeleteFactorChallengeKeypairRequest> for ChallengeContext {
    fn from(request: DeleteFactorChallengeKeypairRequest) -> Self {
        ChallengeContext::DeleteFactor {
            factor_id: request.factor_id,
        }
    }
}
