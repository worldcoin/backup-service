//! Types for the [backup service](https://github.com/worldcoin/backup-service),
//! consumed by the HTTP server and can be used by clients.

#![deny(missing_docs)] // TODO: Make this a workspace lint

pub mod endpoints;
pub mod error;

use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use strum_macros::{Display, EnumString};

pub use endpoints::*;
pub use error::{ErrorBody, ErrorCode, ErrorObject};

/// Proof that the client controls a factor, by solving a challenge issued by the service.
///
/// The variant determines which challenge endpoint issued the challenge: `Passkey` challenges
/// come from the `.../challenge/passkey` endpoints, the other two from `.../challenge/keypair`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum Authorization {
    /// A `WebAuthn` assertion produced by a passkey.
    #[serde(rename_all = "camelCase")]
    Passkey {
        /// The raw `WebAuthn` credential, passed through to the `WebAuthn` verifier untouched.
        credential: serde_json::Value,
        /// Human-readable label for the passkey, e.g. `"Google Credential Manager"`.
        #[serde(default)]
        label: String,
    },
    /// An OIDC token whose nonce commits to a local P-256 keypair, plus a signature from that
    /// keypair over the challenge.
    #[serde(rename_all = "camelCase")]
    OidcAccount {
        /// OIDC token from an external provider, like Google or Apple.
        oidc_token: OidcToken,
        /// Base64-encoded public key of the local P-256 keypair in SEC1 representation.
        /// In other words: `base64-encode(keypair.public_key.to_sec1_bytes())`.
        ///
        /// The nonce of the OIDC token must equal `sha256(public_key_as_hex)`. This rule exists
        /// to stay compatible with Turnkey:
        /// <https://docs.turnkey.com/authentication/social-logins>.
        public_key: String,
        /// Base64-encoded signature of the backend challenge, signed with the private key of the
        /// local P-256 keypair.
        signature: String,
    },
    /// A signature over the challenge from a P-256 keypair registered on the backup.
    #[serde(rename_all = "camelCase")]
    EcKeypair {
        /// Base64-encoded public key of the local P-256 keypair in SEC1 representation.
        /// In other words: `base64-encode(keypair.public_key.to_sec1_bytes())`.
        public_key: String,
        /// Base64-encoded DER signature of the backend challenge, signed with the private key of
        /// the local P-256 keypair.
        signature: String,
    },
}

/// An OIDC token from a supported identity provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum OidcToken {
    /// A Google ID token.
    #[serde(rename_all = "camelCase")]
    Google {
        /// The raw JWT.
        token: String,
    },
    /// An Apple ID token.
    #[serde(rename_all = "camelCase")]
    Apple {
        /// The raw JWT.
        token: String,
        /// For Sign in with Apple, each mobile client has its own audience set to the app's
        /// bundle identifier. This service supports multiple clients (e.g. World App iOS and
        /// World App Android).
        ///
        /// The `aud` must be in an explicitly configured allowlist. When not present, the default
        /// audience will be used.
        #[serde(default)]
        aud: Option<String>,
    },
}

/// The identity provider behind an [`OidcToken`], without the token itself. It is
/// an enum used internally for configuration, cache, telemetry.
///
/// The [`Display`] output is part of the service's Redis key layout for OIDC nonce replay
/// protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum OidcProvider {
    /// Google
    Google,
    /// Apple
    Apple,
}

impl From<&OidcToken> for OidcProvider {
    fn from(token: &OidcToken) -> Self {
        match token {
            OidcToken::Google { .. } => Self::Google,
            OidcToken::Apple { .. } => Self::Apple,
        }
    }
}

/// An encrypted copy of the backup encryption key.
///
/// For example, the PRF variant holds the backup encryption private key encrypted with the user's
/// passkey PRF value. Every variant decrypts to the same backup encryption key, so holding any
/// one of the corresponding secrets is enough to recover the backup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum BackupEncryptionKey {
    /// Encrypted with the user's passkey PRF value.
    #[serde(rename_all = "camelCase")]
    Prf {
        /// The encrypted backup encryption key.
        encrypted_key: String,
    },
    /// Encrypted with a key held in the user's iCloud Keychain.
    #[serde(rename_all = "camelCase")]
    Icloud {
        /// The encrypted backup encryption key.
        encrypted_key: String,
    },
    /// Encrypted with a private key stored in the user's Turnkey account.
    #[serde(rename_all = "camelCase")]
    Turnkey {
        /// The encrypted backup encryption key.
        encrypted_key: String,
        /// The Turnkey sub-organization holding the private key.
        turnkey_account_id: String,
        /// The Turnkey user owning the private key.
        turnkey_user_id: String,
        /// The Turnkey private key that decrypts `encrypted_key`.
        turnkey_private_key_id: String,
    },
}

impl BackupEncryptionKey {
    /// The variant name, for logs, metrics and equality checks that ignore the payload.
    #[must_use]
    pub fn flattened_kind(&self) -> &'static str {
        match self {
            Self::Prf { .. } => "prf",
            Self::Icloud { .. } => "icloud",
            Self::Turnkey { .. } => "turnkey",
        }
    }
}

/// What a factor is allowed to do.
///
/// Some factors are used as main factors for recovery, while others are used for just syncing.
/// This distinguishes between the two so lookups only consider the relevant kind.
///
/// Reference: <https://docs.toolsforhumanity.com/world-app/backup/factors>
#[derive(Debug, Clone, Copy, Display, EnumString, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "openapi", serde(rename_all = "UPPERCASE"))]
#[strum(serialize_all = "UPPERCASE")]
pub enum FactorScope {
    /// Main factors (e.g. passkeys, iCloud Keychain, OIDC accounts) can be used to recover the
    /// backup or add new factors.
    Main,
    /// Sync factors (e.g. EC keypairs stored on enclaves) are used to update the backup with new
    /// data, view metadata and delete factors. Sync factors cannot be used to recover the backup
    /// or add new factors.
    Sync,
}

// Serde implementations for `FactorScope` defer to the strum representation, so the wire format
// and the storage keys derived from `Display` can never drift apart.
impl Serialize for FactorScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FactorScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

/// The part of the backup metadata that is returned to the client.
///
/// The service stores more than this (raw `WebAuthn` credentials, OIDC subjects); those never
/// leave the service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ExportedBackupMetadata {
    /// The ID of the backup.
    pub id: String,
    /// Allows the user to decrypt the backup if they can decrypt any one of these keys (e.g.
    /// using PRF, Turnkey, etc.).
    pub keys: Vec<BackupEncryptionKey>,
    /// The factors that are used to access the backup and modify it (including adding other
    /// factors).
    pub factors: Vec<ExportedFactor>,
    /// Allows the user to see whether they already have a sync factor keypair or should generate
    /// a new one.
    pub sync_factors: Vec<ExportedFactor>,
    /// The hash of the backup manifest, representing the current state of the backup. This hash
    /// must be presented when performing updates (syncs) to the backup, which ensures updates are
    /// always performed on the latest state.
    pub manifest_hash: String,
}

/// A single authentication method registered on a backup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ExportedFactor {
    /// Unique identifier for the factor.
    pub id: String,
    /// Unix timestamp (seconds) when the factor was created.
    pub created_at: i64,
    /// The kind of factor and its associated metadata.
    pub kind: ExportedFactorKind,
}

/// The kind of a [`ExportedFactor`] and the metadata specific to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
#[allow(clippy::large_enum_variant)]
pub enum ExportedFactorKind {
    /// A `WebAuthn` passkey.
    #[serde(rename_all = "camelCase")]
    Passkey {
        /// The credential ID of the passkey, base64url-encoded (no padding). This matches the
        /// `WebAuthn` standard format used by iOS and Android.
        credential_id: String,
        /// Registration object presented by the client when signing up, so the client can
        /// register the passkey in Turnkey later rather than during initial sign up.
        registration: serde_json::Value,
        /// Human-readable label for the passkey, e.g. `"Google Credential Manager"`. Displayed to
        /// the user.
        label: String,
    },
    /// An OIDC account backed by a Turnkey OAuth provider.
    #[serde(rename_all = "camelCase")]
    OidcAccount {
        /// Which provider backs the account, and the user's masked email.
        account: ExportedOidcAccountKind,
        /// The Turnkey OAuth provider ID for this factor, used to remove it from Turnkey.
        /// <https://docs.turnkey.com/api-reference/activities/create-oauth-providers>.
        turnkey_provider_id: String,
    },
    /// A P-256 keypair, held locally by a device.
    #[serde(rename_all = "camelCase")]
    EcKeypair {
        /// Base64-encoded SEC1 public key.
        public_key: String,
    },
}

/// Which OIDC provider backs a factor, and the user's masked email.
///
/// The subject identifier is deliberately not exposed; the masked email is enough for the client
/// to render which account was added.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ExportedOidcAccountKind {
    /// A Google account.
    #[serde(rename_all = "camelCase")]
    Google {
        /// The user's masked email, e.g. `j***@gmail.com`.
        masked_email: String,
    },
    /// An Apple account.
    #[serde(rename_all = "camelCase")]
    Apple {
        /// The user's masked email, e.g. `j***@icloud.com`.
        masked_email: String,
    },
}

/// Deserializes a hex string into a byte array and verifies it is exactly 32 bytes long.
///
/// A leading `0x` is stripped and the result is lowercased, so callers always observe the same
/// representation regardless of what the client sent.
///
/// # Errors
///
/// Returns an error if the hex string is not a valid hex-encoded byte array or if it is not
/// exactly 32 bytes long.
pub fn normalize_hex_32<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s).map_err(de::Error::custom)?;
    if bytes.len() != 32 {
        return Err(de::Error::custom("Expected 32 bytes"));
    }
    Ok(s.to_lowercase())
}

/// Deserializes a backup account ID and verifies it has the correct format.
///
/// # Errors
///
/// Returns an error if the value is missing the `backup_account_` prefix, or if the remainder is
/// not a hex-encoded SEC1 compressed public key (33 bytes).
pub fn validate_backup_account_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if !s.starts_with("backup_account_") {
        return Err(de::Error::custom(
            "Invalid backup account ID. Missing expected prefix.",
        ));
    }
    let bytes = hex::decode(s.trim_start_matches("backup_account_")).map_err(de::Error::custom)?;
    // 33 bytes because we expect a SEC.1 compressed public key
    if bytes.len() != 33 {
        return Err(de::Error::custom(
            "Invalid backup account ID. Expected 33 bytes after the prefix.",
        ));
    }
    Ok(s)
}
