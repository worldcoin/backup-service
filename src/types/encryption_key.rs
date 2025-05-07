use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Backup encryption key is an encrypted version of the key that is used to encrypt the backup.
/// For example, PRF encryption key is a backup encryption private key that was encrypted with user's
/// PRF value.
///
/// This key is stored in the backup metadata and allows to decrypt the backup during
/// recovery, provided that the user has access to the PRF value / iCloud keychain / access to
/// Turnkey.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum BackupEncryptionKey {
    /// Backup encryption key that is encrypted with the user's PRF value.
    #[serde(rename_all = "camelCase")]
    Prf { encrypted_key: String },
    /// Backup encryption key that is encrypted with the user's iCloud keychain.
    #[serde(rename_all = "camelCase")]
    Icloud { encrypted_key: String },
    /// Backup encryption key that is encrypted with a private key that is stored in Turnkey account.
    #[serde(rename_all = "camelCase")]
    Turnkey {
        encrypted_key: String,
        turnkey_account_id: String,
        turnkey_user_id: String,
        turnkey_private_key_id: String,
    },
}
