use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum SolvedChallenge {
    #[serde(rename_all = "camelCase")]
    Passkey { credential: serde_json::Value },
}
