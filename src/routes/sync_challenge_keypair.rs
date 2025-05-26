use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

/// Request to retrieve a challenge for keypair authentication. Used to sync the backup by updating
/// the sealed backup content, while keeping metadata the same. The challenge has to be signed by the
/// keypair that's stored as a sync factor in the backup metadata.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncChallengeKeypairRequest {}

impl From<SyncChallengeKeypairRequest> for ChallengeContext {
    fn from(_: SyncChallengeKeypairRequest) -> Self {
        ChallengeContext::Sync {}
    }
}
