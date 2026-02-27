use crate::challenge_manager::ChallengeContext;
use crate::validate_backup_account_id;
use schemars::JsonSchema;
use serde::Deserialize;

/// Request to retrieve a challenge for keypair authentication. Used to reset the backup
/// when access to all main and sync factors is lost. The challenge has to be signed by the
/// keypair corresponding to the `backup_account_id`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResetChallengeKeypairRequest {
    #[serde(deserialize_with = "validate_backup_account_id")]
    backup_account_id: String,
}

impl From<ResetChallengeKeypairRequest> for ChallengeContext {
    fn from(request: ResetChallengeKeypairRequest) -> Self {
        ChallengeContext::Reset {
            backup_account_id: request.backup_account_id,
        }
    }
}
