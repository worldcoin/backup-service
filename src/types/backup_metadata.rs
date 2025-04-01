use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

/// Backup metadata is stored alongside every backup in the backup bucket. It's used to
/// store information about entities and keys that are allowed to access the backup.
/// It also stores encrypted version of the backup decryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupMetadata {
    pub primary_factor: PrimaryFactor,
    /// The ID of the turnkey account that stores the decryption key. Only present if Turnkey account
    /// is initialized. If backup only uses passkeys for decryption, this field is not present.
    pub turnkey_account_id: Option<String>,
    // TODO/FIXME: More fields, e.g. keys, oidc accounts
}

/// The primary factor is the main factor of authentication that relies on a trusted type of credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrimaryFactor {
    /// Used as a primary key for the whole backup
    pub id: String,
    /// The kind of primary factor and the associated metadata
    pub kind: PrimaryFactorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum PrimaryFactorKind {
    #[serde(rename_all = "camelCase")]
    Passkey { webauthn_credential: Passkey },
}

impl PrimaryFactor {
    pub fn new_passkey(webauthn_credential: Passkey) -> Self {
        Self {
            id: STANDARD.encode(webauthn_credential.cred_id()),
            kind: PrimaryFactorKind::Passkey {
                webauthn_credential,
            },
        }
    }
}
