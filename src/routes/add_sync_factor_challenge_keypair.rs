use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

/// Request to retrieve a challenge for keypair authentication. Used to add a new sync factor after
/// recovery. The challenge should be signed by the newly added sync factor, which a EC keypair.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddSyncFactorChallengeKeypairRequest {}

impl From<AddSyncFactorChallengeKeypairRequest> for ChallengeContext {
    fn from(_: AddSyncFactorChallengeKeypairRequest) -> Self {
        ChallengeContext::AddSyncFactor {}
    }
}
