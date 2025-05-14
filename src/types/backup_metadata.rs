use crate::mask_email;
use crate::types::encryption_key::BackupEncryptionKey;
use chrono::{DateTime, Utc};
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
    /// Factors that are used to update backup content and view backup metadata
    /// (but not update backup metadata).
    pub sync_factors: Vec<Factor>,
    /// Stores versions of backup encryption key that were encrypted with different methods.
    pub keys: Vec<BackupEncryptionKey>,
}

impl BackupMetadata {
    /// Creates an exported version of the backup metadata that contains only the fields that are
    /// exported to the client.
    pub fn exported(&self) -> ExportedBackupMetadata {
        ExportedBackupMetadata {
            id: self.id.clone(),
            keys: self.keys.clone(),
            factors: self
                .factors
                .iter()
                .map(|factor| factor.exported())
                .collect(),
            sync_factors: self
                .sync_factors
                .iter()
                .map(|factor| factor.exported())
                .collect(),
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
    /// The time when the factor was created
    pub created_at: DateTime<Utc>,
}

impl Factor {
    pub fn exported(&self) -> ExportedFactor {
        ExportedFactor {
            id: self.id.clone(),
            created_at: self.created_at.timestamp() as u64,
            kind: match &self.kind {
                FactorKind::Passkey { registration, .. } => ExportedFactorKind::Passkey {
                    registration: registration.clone(),
                },
                FactorKind::OidcAccount { account } => ExportedFactorKind::OidcAccount {
                    account: match account {
                        OidcAccountKind::Google { email, .. } => ExportedOidcAccountKind::Google {
                            masked_email: mask_email(email).unwrap_or_default(),
                        },
                    },
                },
                FactorKind::EcKeypair { public_key } => ExportedFactorKind::EcKeypair {
                    public_key: public_key.clone(),
                },
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
#[allow(clippy::large_enum_variant)]
pub enum FactorKind {
    #[serde(rename_all = "camelCase")]
    Passkey {
        webauthn_credential: Passkey,
        // Registration object presented by the client when signing up. Used by the client to be
        // to register the passkey in Turnkey later, not during initial sign up.
        registration: serde_json::Value,
    },
    #[serde(rename_all = "camelCase")]
    OidcAccount { account: OidcAccountKind },
    #[serde(rename_all = "camelCase")]
    EcKeypair { public_key: String },
}

impl Factor {
    pub fn new_passkey(webauthn_credential: Passkey, registration: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: FactorKind::Passkey {
                webauthn_credential,
                registration,
            },
            created_at: Utc::now(),
        }
    }

    pub fn new_oidc_account(account: OidcAccountKind) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: FactorKind::OidcAccount { account },
            created_at: Utc::now(),
        }
    }

    pub fn new_ec_keypair(public_key: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: FactorKind::EcKeypair { public_key },
            created_at: Utc::now(),
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
    /// The ID of the backup.
    id: String,
    /// Allows user to decrypt the backup if they are able to decrypt one of keys (e.g. using PRF,
    /// Turnkey, etc.)
    keys: Vec<BackupEncryptionKey>,
    /// The factors that are used to access the backup and modify it (including adding other factors).
    factors: Vec<ExportedFactor>,
    /// Allows user to see if they already have the sync factor keypair or they should generate a
    /// new one.
    sync_factors: Vec<ExportedFactor>,
}

/// See [`Factor`] for more details. Exported version of the factor that contains only the fields
/// that are exported to the client when performing the recovery / viewing the metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExportedFactor {
    /// Used as a unique identifier for the factor
    pub id: String,
    /// Timestamp when the factor was created
    pub created_at: u64,
    /// The kind of factor and the associated metadata
    pub kind: ExportedFactorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
#[allow(clippy::large_enum_variant)]
pub enum ExportedFactorKind {
    #[serde(rename_all = "camelCase")]
    Passkey {
        // Registration object presented by the client when signing up. Used by the client to be
        // to register the passkey in Turnkey later, not during initial sign up.
        registration: serde_json::Value,
    },
    #[serde(rename_all = "camelCase")]
    OidcAccount { account: ExportedOidcAccountKind },
    #[serde(rename_all = "camelCase")]
    EcKeypair { public_key: String },
}

/// Exported version of the OIDC account. Allows the mobile app to render that some account was
/// added, but for now, it doesn't contain which account it is.
/// TODO/FIXME: Figure out if we should export email and sub here or not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ExportedOidcAccountKind {
    #[serde(rename_all = "camelCase")]
    Google { masked_email: String },
}
