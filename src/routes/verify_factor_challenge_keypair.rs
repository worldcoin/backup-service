use crate::challenge_manager::ChallengeContext;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorChallengeKeypairRequest {}

impl From<VerifyFactorChallengeKeypairRequest> for ChallengeContext {
    fn from(_: VerifyFactorChallengeKeypairRequest) -> Self {
        ChallengeContext::VerifyFactor {}
    }
}
