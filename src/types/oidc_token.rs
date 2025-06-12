use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum OidcToken {
    #[serde(rename_all = "camelCase")]
    Google { token: String },
    #[serde(rename_all = "camelCase")]
    Apple { token: String },
}
