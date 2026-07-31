use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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
    Apple {
        token: String,
        /// For Sign in with Apple, each mobile client has its own audience set to the app's
        /// bundle identifier. This service supports multiple clients (e.g. World App iOS and World App Android).
        ///
        /// The `aud` must be in an explicitly configured allowlist. When not present, the default
        /// audience will be used.
        // FIXME: double check optional, not present = None
        aud: Option<String>,
    },
}

impl From<&OidcToken> for OidcProvider {
    fn from(token: &OidcToken) -> Self {
        match token {
            OidcToken::Google { .. } => Self::Google,
            OidcToken::Apple { .. } => Self::Apple,
        }
    }
}
