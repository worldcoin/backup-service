use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

/// Request to retrieve a challenge for keypair authentication. Used to delete a factor
/// from the backup metadata. The challenge has to be signed by the keypair that's stored
/// as a sync factor in the backup metadata.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteBackupChallengeKeypairRequest {}

impl From<DeleteBackupChallengeKeypairRequest> for ChallengeContext {
    fn from(_request: DeleteBackupChallengeKeypairRequest) -> Self {
        ChallengeContext::DeleteBackup {}
    }
}
