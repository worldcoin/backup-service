use crate::types::encryption_key::BackupEncryptionKey;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

/// Backup metadata is stored alongside every backup in the backup bucket. It's used to
/// store information about entities and keys that are allowed to access the backup.
/// It also stores encrypted version of the backup decryption key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupMetadata {
    /// Backup ID, generated randomly.
    pub id: String,
    /// Factors that are used to access the backup and modify it (including adding other factors).
    pub factors: Vec<Factor>,
    /// OIDC accounts that are used to access the backup in addition to the primary factor.
    pub oidc_accounts: Vec<OidcAccount>,
    /// Stores versions of backup encryption key that were encrypted with different methods.
    pub keys: Vec<BackupEncryptionKey>,
}

impl BackupMetadata {
    /// Creates an exported version of the backup metadata that contains only the fields that are
    /// exported to the client.
    pub fn exported(&self) -> ExportedBackupMetadata {
        ExportedBackupMetadata {
            keys: self.keys.clone(),
        }
    }
}

/// A factor is a unique identifier for a specific authentication method. It can be a passkey,
/// OIDC account or a keypair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Factor {
    /// Used as a unique identifier for the factor
    pub id: String,
    /// The kind of factor and the associated metadata
    pub kind: FactorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum FactorKind {
    #[serde(rename_all = "camelCase")]
    Passkey { webauthn_credential: Passkey },
}

impl Factor {
    pub fn new_passkey(webauthn_credential: Passkey) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: FactorKind::Passkey {
                webauthn_credential,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OidcAccount {
    /// The ID of the OIDC account connection, generated randomly
    pub id: String,
    /// The kind of OIDC account and the associated metadata
    pub kind: OidcAccountKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum OidcAccountKind {
    #[serde(rename_all = "camelCase")]
    Google { sub: String, email: String },
}

/// The part of metadata of the backup that's exported to the client when performing the recovery.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExportedBackupMetadata {
    /// Allows user to decrypt the backup if they are able to decrypt one of keys (e.g. using PRF,
    /// Turnkey, etc.)
    keys: Vec<BackupEncryptionKey>,
}
