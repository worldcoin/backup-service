use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

/// Request to retrieve a challenge for keypair authentication. Used to retrieve the metadata
/// of the backup using a sync factor. The challenge has to be signed by the keypair that's
/// stored as a sync factor in the backup metadata.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataChallengeKeypairRequest {}

impl From<RetrieveMetadataChallengeKeypairRequest> for ChallengeContext {
    fn from(_: RetrieveMetadataChallengeKeypairRequest) -> Self {
        ChallengeContext::RetrieveMetadata {}
    }
}
