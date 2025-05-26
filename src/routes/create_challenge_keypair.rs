use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateChallengeKeypairRequest {}

impl From<CreateChallengeKeypairRequest> for ChallengeContext {
    fn from(_: CreateChallengeKeypairRequest) -> Self {
        ChallengeContext::Create {}
    }
}
