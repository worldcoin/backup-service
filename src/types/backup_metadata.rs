use crate::types::encryption_key::BackupEncryptionKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

/// Backup metadata is stored alongside every backup in the backup bucket. It's used to
/// store information about entities and keys that are allowed to access the backup.
/// It also stores encrypted version of the backup decryption key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupMetadata {
    /// Backup ID, generated randomly.
    pub id: String,
    /// The primary factor of authentication that is used to access the backup.
    pub primary_factor: PrimaryFactor,
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

/// The primary factor is the main factor of authentication that relies on a trusted type of credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PrimaryFactor {
    /// Used as a primary key for the whole backup
    pub id: String,
    /// The kind of primary factor and the associated metadata
    pub kind: PrimaryFactorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum PrimaryFactorKind {
    #[serde(rename_all = "camelCase")]
    Passkey { webauthn_credential: Passkey },
}

impl PrimaryFactor {
    pub fn new_passkey(webauthn_credential: Passkey) -> Self {
        Self {
            id: URL_SAFE_NO_PAD.encode(webauthn_credential.cred_id()),
            kind: PrimaryFactorKind::Passkey {
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
