use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::Environment;
use crate::{factor_lookup::FactorToLookup, mask_email};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::str::FromStr;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

/// A unique global identifier that identifies the type of file. This is used to prevent accidental overwrites to a user's backup.
#[derive(strum::Display, strum::EnumString, Debug, Clone, PartialEq, Eq, JsonSchema, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum FileDesignator {
    OrbPkg,
    DocumentPkg,
    SecureDocumentPkg,
}

impl Serialize for FileDesignator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FileDesignator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(D::Error::custom)
    }
}

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
    /// **Important:** Only `FactorKind::EcKeypair` is allowed to be a sync factor.
    pub sync_factors: Vec<Factor>,
    /// Stores versions of backup encryption key that were encrypted with different methods.
    pub keys: Vec<BackupEncryptionKey>,
    /// Stores the list of file designators that are contained in the backup. This is used on `sync_backup` validation
    /// to prevent accidental file removals on a user's backup.
    #[serde(default = "HashSet::new")]
    pub file_list: HashSet<FileDesignator>,
}

impl BackupMetadata {
    /// Creates an exported version of the backup metadata that contains only the fields that are
    /// exported to the client.
    pub fn exported(&self) -> ExportedBackupMetadata {
        ExportedBackupMetadata {
            id: self.id.clone(),
            keys: self.keys.clone(),
            factors: self.factors.iter().map(Factor::exported).collect(),
            sync_factors: self.sync_factors.iter().map(Factor::exported).collect(),
            file_list: self.file_list.clone(),
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
    #[must_use]
    pub fn exported(&self) -> ExportedFactor {
        ExportedFactor {
            id: self.id.clone(),
            created_at: self.created_at.timestamp(),
            kind: match &self.kind {
                FactorKind::Passkey { registration, .. } => ExportedFactorKind::Passkey {
                    registration: registration.clone(),
                },
                FactorKind::OidcAccount {
                    account,
                    turnkey_provider_id,
                } => ExportedFactorKind::OidcAccount {
                    account: match account {
                        OidcAccountKind::Google { email, .. } => ExportedOidcAccountKind::Google {
                            masked_email: mask_email(email).unwrap_or_default(),
                        },
                        OidcAccountKind::Apple { email, .. } => ExportedOidcAccountKind::Apple {
                            masked_email: mask_email(email).unwrap_or_default(),
                        },
                    },
                    turnkey_provider_id: turnkey_provider_id.clone(),
                },
                FactorKind::EcKeypair { public_key } => ExportedFactorKind::EcKeypair {
                    public_key: public_key.clone(),
                },
            },
        }
    }

    pub fn as_factor_to_lookup(&self, environment: &Environment) -> FactorToLookup {
        match &self.kind {
            FactorKind::Passkey {
                webauthn_credential,
                ..
            } => FactorToLookup::from_passkey(
                BASE64_URL_SAFE_NO_PAD.encode(webauthn_credential.cred_id()),
            ),
            FactorKind::OidcAccount {
                account,
                turnkey_provider_id: _,
            } => {
                let (issuer_url, sub) = match account {
                    OidcAccountKind::Google { sub, email: _ } => {
                        (environment.google_issuer_url().to_string(), sub.to_string())
                    }
                    OidcAccountKind::Apple { sub, email: _ } => {
                        (environment.apple_issuer_url().to_string(), sub.to_string())
                    }
                };
                FactorToLookup::from_oidc_account(issuer_url, sub)
            }
            FactorKind::EcKeypair { public_key } => {
                FactorToLookup::from_ec_keypair(public_key.to_string())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    OidcAccount {
        account: OidcAccountKind,
        /// The ID of the Turnkey OIDC provider. Returned from Turnkey API when creating account
        /// or adding new factor. This is used to be able to delete this factor from Turnkey
        /// if needed.
        /// <https://docs.turnkey.com/api-reference/activities/create-oauth-providers>.
        turnkey_provider_id: String,
    },
    #[serde(rename_all = "camelCase")]
    EcKeypair { public_key: String },
}

impl PartialEq for FactorKind {
    fn eq(&self, other: &Self) -> bool {
        use FactorKind::{EcKeypair, OidcAccount, Passkey};
        match (self, other) {
            // compare only the passkey (through the credential ID), ignore the registration
            // note `Passkey` implements `PartialEq` correctly based on the `cred_id` field
            (
                Passkey {
                    webauthn_credential: a,
                    ..
                },
                Passkey {
                    webauthn_credential: b,
                    ..
                },
            ) => a == b,

            // compare the rest of the fields regularly
            (
                OidcAccount {
                    account: a0,
                    turnkey_provider_id: a1,
                },
                OidcAccount {
                    account: b0,
                    turnkey_provider_id: b1,
                },
            ) => a0 == b0 && a1 == b1,

            (EcKeypair { public_key: a }, EcKeypair { public_key: b }) => a == b,

            // Different variants are never equal
            _ => false,
        }
    }
}

impl Factor {
    #[must_use]
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

    #[must_use]
    pub fn new_oidc_account(account: OidcAccountKind, turnkey_provider_id: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: FactorKind::OidcAccount {
                account,
                turnkey_provider_id,
            },
            created_at: Utc::now(),
        }
    }

    #[must_use]
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
    #[serde(rename_all = "camelCase")]
    Apple { sub: String, email: String },
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
    /// The list of file designators that are contained in the backup.
    file_list: HashSet<FileDesignator>,
}

/// See [`Factor`] for more details. Exported version of the factor that contains only the fields
/// that are exported to the client when performing the recovery / viewing the metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExportedFactor {
    /// Used as a unique identifier for the factor
    pub id: String,
    /// Timestamp when the factor was created
    pub created_at: i64,
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
    OidcAccount {
        account: ExportedOidcAccountKind,
        turnkey_provider_id: String,
    },
    #[serde(rename_all = "camelCase")]
    EcKeypair { public_key: String },
}

/// Exported version of the OIDC account. Allows the mobile app to render that some account was
/// added, but for now, it doesn't contain which account it is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ExportedOidcAccountKind {
    #[serde(rename_all = "camelCase")]
    Google { masked_email: String },
    #[serde(rename_all = "camelCase")]
    Apple { masked_email: String },
}

#[cfg(test)]
mod tests {
    use backup_service_test_utils::{
        get_mock_passkey_client, make_credential_from_passkey_challenge,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use p256::SecretKey;
    use rand::rngs::OsRng;
    use serde_json::json;

    use crate::types::Environment;

    use super::*;

    #[test]
    fn test_factor_kind_comparison_keypair() {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = STANDARD.encode(secret_key.public_key().to_sec1_bytes());
        let factor_1 = FactorKind::EcKeypair {
            public_key: public_key.clone(),
        };
        let factor_2 = FactorKind::EcKeypair {
            public_key: public_key.clone(),
        };

        let factor_3 = FactorKind::EcKeypair {
            public_key: public_key[..public_key.len() - 1].to_string(),
        };

        assert_eq!(factor_1, factor_2);
        assert_ne!(factor_1, factor_3);
    }

    #[test]
    fn test_factor_kind_comparison_oidc_account() {
        let factor_1 = FactorKind::OidcAccount {
            account: OidcAccountKind::Google {
                sub: "1234567890".to_string(),
                email: "test@example.com".to_string(),
            },
            turnkey_provider_id: "1234567890".to_string(),
        };

        let factor_2 = FactorKind::OidcAccount {
            account: OidcAccountKind::Google {
                sub: "1234567890".to_string(),
                email: "test@example.com".to_string(),
            },
            turnkey_provider_id: "1234567890".to_string(),
        };

        let factor_3 = FactorKind::OidcAccount {
            account: OidcAccountKind::Google {
                sub: "1234567890".to_string(),
                email: "test@example.com".to_string(),
            },
            turnkey_provider_id: "1234567891".to_string(), // different provider ID
        };

        let factor_4 = FactorKind::OidcAccount {
            account: OidcAccountKind::Google {
                sub: "1234567891".to_string(), // different sub
                email: "test@example.com".to_string(),
            },
            turnkey_provider_id: "1234567890".to_string(),
        };

        let factor_5 = FactorKind::OidcAccount {
            account: OidcAccountKind::Apple {
                // different `OidcAccountKind`
                sub: "1234567890".to_string(),
                email: "test@example.com".to_string(),
            },
            turnkey_provider_id: "1234567890".to_string(),
        };

        assert_eq!(factor_1, factor_2);
        assert_ne!(factor_1, factor_3);
        assert_ne!(factor_1, factor_4);
        assert_ne!(factor_1, factor_5);
    }

    #[tokio::test]
    async fn test_factor_kind_comparison_passkey() {
        let mut client = get_mock_passkey_client();

        let (challenge, registration) = Environment::development(None)
            .webauthn_config()
            .start_passkey_registration(Uuid::new_v4(), "test", "test", None)
            .unwrap();

        let challenge = json!({
            "challenge": challenge,
        });

        let passkey = Environment::development(None)
            .webauthn_config()
            .finish_passkey_registration(
                &serde_json::from_value(
                    make_credential_from_passkey_challenge(&mut client, &challenge).await,
                )
                .unwrap(),
                &registration,
            )
            .unwrap();

        let factor_1 = FactorKind::Passkey {
            webauthn_credential: passkey.clone(),
            registration: json!([1]),
        };
        let factor_2 = FactorKind::Passkey {
            webauthn_credential: passkey,
            registration: json!([2]),
        };

        assert_eq!(factor_1, factor_2);
    }
}
