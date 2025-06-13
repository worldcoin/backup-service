use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Enum to specify which OIDC provider to use in tests
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub enum OidcProvider {
    Google,
    Apple,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum OidcToken {
    #[serde(rename_all = "camelCase")]
    Google { token: String },
    #[serde(rename_all = "camelCase")]
    Apple { token: String },
}
