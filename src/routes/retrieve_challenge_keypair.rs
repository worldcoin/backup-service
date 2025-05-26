use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

/// Request to retrieve a challenge for keypair authentication. Used to start the recovery process
/// for a backup.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveChallengeKeypairRequest {}

impl From<RetrieveChallengeKeypairRequest> for ChallengeContext {
    fn from(_: RetrieveChallengeKeypairRequest) -> Self {
        ChallengeContext::Retrieve {}
    }
}
