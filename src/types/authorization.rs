use crate::{challenge_manager::ChallengeType, types::OidcToken};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum Authorization {
    #[serde(rename_all = "camelCase")]
    Passkey {
        credential: serde_json::Value,
        #[serde(default)]
        label: String,
    },
    #[serde(rename_all = "camelCase")]
    OidcAccount {
        // OIDC token from external provider, like Google or Apple
        oidc_token: OidcToken,
        // Base64-encoded public key of local P256 keypair in SEC1 representation.
        // In other words: base64-encode(keypair.public_key.to_sec1_bytes()).
        //
        // Nonce of the OIDC token should be equal to: sha256(public_key_as_hex).
        // This rule exists to ensure compatibility with Turnkey:
        // https://docs.turnkey.com/authentication/social-logins
        public_key: String,
        // Base64-encoded signature of the backend challenge, signed with the private key of
        // the local P256 keypair.
        signature: String,
    },
    #[serde(rename_all = "camelCase")]
    EcKeypair {
        // Base64-encoded public key of local P256 keypair in SEC1 representation.
        // In other words: base64-encode(keypair.public_key.to_sec1_bytes()).
        public_key: String,
        // Base64-encoded signature of the backend challenge in DER representation, signed with the private key of
        // the local P256 keypair.
        signature: String,
    },
}

impl From<&Authorization> for ChallengeType {
    fn from(value: &Authorization) -> Self {
        match value {
            Authorization::Passkey { .. } => ChallengeType::Passkey,
            // NOTE: OIDC Accounts also sign a `Keypair` challenge. The keypair is part of the OIDC nonce.
            Authorization::OidcAccount { .. } | Authorization::EcKeypair { .. } => {
                ChallengeType::Keypair
            }
        }
    }
}
