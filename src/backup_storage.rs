use crate::types::backup_metadata::{BackupMetadata, Factor, FactorKind};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::Environment;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;

use std::sync::Arc;

// Limits for factors and keys. Serves as general client limits, incentivize housekeeping and
// to ensure metadata fits within S3 object metadata (2KB limit)
const MAX_MAIN_FACTORS: usize = 10; // `MainFactor`
const MAX_SYNC_FACTORS: usize = 10; // `SyncFactor`
const MAX_BACKUP_ENCRYPTION_KEYS: usize = 10; // `BackupEncryptionKey`
const MAX_PASSKEYS: usize = 2; // Specific limit for passkeys due to their size

/// Stores and retrieves backups and metadata from S3. Does not handle access checks or validate
/// limits.
#[derive(Clone, Debug)]
pub struct BackupStorage {
    environment: Environment,
    s3_client: Arc<S3Client>,
}

type ETag = Option<String>;

impl BackupStorage {
    #[must_use]
    pub fn new(environment: Environment, s3_client: Arc<S3Client>) -> Self {
        Self {
            environment,
            s3_client,
        }
    }

    /// Creates a backup with metadata stored as object metadata in S3.
    ///
    /// # Errors
    /// * If the metadata cannot be serialized to CBOR, `BackupManagerError::CompressionError` is returned.
    /// * If the compressed metadata is too large (>2KB), `BackupManagerError::MetadataTooLarge` is returned.
    /// * If the backup cannot be uploaded to S3 (e.g. due to internal error or because
    ///   this backup ID is already used), `BackupManagerError::PutObjectError` is returned.
    ///   Note that if the backup already exists, this function will throw an error.
    pub async fn create(
        &self,
        backup: Vec<u8>,
        backup_metadata: &BackupMetadata,
    ) -> Result<(), BackupManagerError> {
        // Validate factor limits
        Self::validate_factor_limits(backup_metadata)?;

        // Serialize and compress metadata
        let compressed_metadata = backup_metadata.to_compressed_metadata()?;

        // Save encrypted backup to S3 with compressed metadata
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(&backup_metadata.id))
            .body(ByteStream::from(backup))
            .metadata("backup-metadata", compressed_metadata)
            .if_none_match("*")
            .send()
            .await?;

        Ok(())
    }

    /// Retrieves a backup and metadata from S3 by backup ID, which is linked to credential using
    /// separate `FactorLookup` service.
    ///
    /// If the backup does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, `BackupManagerError::SerdeJsonError` is returned.
    /// * If the backup cannot be downloaded from S3, `BackupManagerError::GetObjectError` is returned.
    /// * If the backup cannot be converted to bytes, `BackupManagerError::ByteStreamError` is returned.
    pub async fn get_by_backup_id(
        &self,
        backup_id: &str,
    ) -> Result<Option<FoundBackup>, BackupManagerError> {
        let result = self
            .s3_client
            .get_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .send()
            .await;

        match result {
            Ok(result) => {
                let backup = result.body.collect().await?.into_bytes().to_vec();

                let compressed_metadata = result
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("backup-metadata"))
                    .ok_or(BackupManagerError::MetadataNotFound)?;
                let metadata = BackupMetadata::from_compressed_metadata(compressed_metadata)?;

                Ok(Some(FoundBackup { backup, metadata }))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(err) => Err(BackupManagerError::GetObjectError(err)),
        }
    }

    /// Retrieves metadata from S3 by backup ID using HEAD request to get object metadata.
    ///
    /// If the backup does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, `BackupManagerError::SerdeJsonError` is returned.
    /// * If the backup cannot be accessed from S3, `BackupManagerError::HeadObjectError` is returned.
    pub async fn get_metadata_by_backup_id(
        &self,
        backup_id: &str,
    ) -> Result<Option<(BackupMetadata, ETag)>, BackupManagerError> {
        let result = self
            .s3_client
            .head_object() // note HEAD to avoid loading the entire object
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .send()
            .await;

        match result {
            Ok(result) => {
                let compressed_metadata = result
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("backup-metadata"))
                    .ok_or(BackupManagerError::MetadataNotFound)?;
                let metadata = BackupMetadata::from_compressed_metadata(compressed_metadata)?;
                Ok(Some((metadata, result.e_tag)))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_not_found() => Ok(None),
            Err(err) => Err(BackupManagerError::HeadObjectError(err)),
        }
    }

    /// Updates a backup in S3 by backup ID. Overwrites the existing backup with the new one.
    ///
    /// # Errors
    /// * If the backup cannot be uploaded to S3, `BackupManagerError::PutObjectError` is returned.
    /// * If the metadata is too large (>2KB), `BackupManagerError::MetadataTooLarge` is returned.
    pub async fn update_backup(
        &self,
        backup_id: &str,
        backup: Vec<u8>,
        current_manifest_hash: String,
        new_manifest_hash: String,
    ) -> Result<(), BackupManagerError> {
        let Some((mut metadata, e_tag)) = self.get_metadata_by_backup_id(backup_id).await? else {
            return Err(BackupManagerError::BackupNotFound);
        };

        let Some(e_tag) = e_tag else {
            return Err(BackupManagerError::ETagNotFound);
        };

        if metadata.manifest_hash != current_manifest_hash {
            return Err(BackupManagerError::UpdateConflict);
        }

        metadata.manifest_hash = new_manifest_hash;

        let compressed_metadata = metadata.to_compressed_metadata()?;

        // Update backup with new compressed metadata (atomic update)
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .body(ByteStream::from(backup))
            .metadata("backup-metadata", compressed_metadata)
            .if_match(e_tag)
            .send()
            .await?;

        Ok(())
    }

    /// Adds a `Main` factor to the backup metadata in S3.
    /// Optionally adds a new backup encryption key.
    ///
    /// # Errors
    /// - `BackupManagerError::BackupNotFound` - if the backup does not exist.
    /// - `BackupManagerError::FactorAlreadyExists` - if the factor already exists. Duplicates are prevented because it makes no sense and makes
    ///   maintenance harder (e.g. when deleting a factor).
    pub async fn add_factor(
        &self,
        backup_id: &str,
        factor: Factor,
        new_encryption_key: Option<BackupEncryptionKey>,
    ) -> Result<(), BackupManagerError> {
        // Get the current metadata
        let Some((mut metadata, e_tag)) = self.get_metadata_by_backup_id(backup_id).await? else {
            return Err(BackupManagerError::BackupNotFound);
        };

        let Some(e_tag) = e_tag else {
            return Err(BackupManagerError::ETagNotFound);
        };

        // Check if this factor already exists by comparing the full `FactorKind` (which includes its relevant credential identifier, e.g. `cred_id` for Passkey)
        if metadata.factors.iter().any(|f| f.kind == factor.kind)
            || metadata.sync_factors.iter().any(|f| f.kind == factor.kind)
        {
            return Err(BackupManagerError::FactorAlreadyExists);
        }

        // Add the factor to the metadata
        metadata.factors.push(factor);

        // Add the new encryption key if provided
        if let Some(encryption_key) = new_encryption_key {
            metadata.keys.push(encryption_key);
        }

        // Validate factor limits after adding
        Self::validate_factor_limits(&metadata)?;

        self.update_backup_metadata(backup_id, &e_tag, &metadata)
            .await
    }

    /// Adds a sync factor to the backup metadata in S3.
    ///
    /// # Errors
    /// - `BackupManagerError::SyncFactorMustBeKeypair` - if the sync factor is not a keypair. Only keypairs are supported sync factors.
    /// - `BackupManagerError::BackupNotFound` - if the backup does not exist.
    /// - `BackupManagerError::FactorAlreadyExists` - if the sync factor already exists. Duplicates are prevented because it makes no sense and makes
    ///    maintenance harder (e.g. when deleting a factor)
    pub async fn add_sync_factor(
        &self,
        backup_id: &str,
        sync_factor: Factor,
    ) -> Result<(), BackupManagerError> {
        // Sync factor must be a keypair
        match sync_factor.kind {
            FactorKind::EcKeypair { .. } => {}
            FactorKind::Passkey { .. } | FactorKind::OidcAccount { .. } => {
                return Err(BackupManagerError::SyncFactorMustBeKeypair);
            }
        }

        // Get the current metadata
        let Some((mut metadata, e_tag)) = self.get_metadata_by_backup_id(backup_id).await? else {
            return Err(BackupManagerError::BackupNotFound);
        };

        let Some(e_tag) = e_tag else {
            return Err(BackupManagerError::ETagNotFound);
        };

        // Check if this factor already exists by comparing the full `FactorKind` (which includes its relevant credential identifier, e.g. `cred_id` for Passkey)
        if metadata.factors.iter().any(|f| f.kind == sync_factor.kind)
            || metadata
                .sync_factors
                .iter()
                .any(|f| f.kind == sync_factor.kind)
        {
            return Err(BackupManagerError::FactorAlreadyExists);
        }

        // Add the sync factor to the metadata
        metadata.sync_factors.push(sync_factor);

        // Validate factor limits after adding
        Self::validate_factor_limits(&metadata)?;

        self.update_backup_metadata(backup_id, &e_tag, &metadata)
            .await
    }

    /// Removes a `Main` factor from the backup metadata in S3 by factor ID.
    /// If this is the last `Main` factor, the entire backup will be deleted, even if sync factors exist.
    ///
    /// `backup_encryption_key_to_delete` is optionally used to delete the provided backup encryption key from
    /// metadata if it is no longer needed. For example, if last OIDC factor is removed, the Turnkey
    /// account can no longer be used to decrypt the backup, so the key and reference to Turnkey IDs
    /// should be deleted.
    ///
    /// # Errors
    /// - `BackupManagerError::BackupNotFound` - if the backup does not exist.
    /// - `BackupManagerError::FactorNotFound` - if the factor does not exist.
    /// - `BackupManagerError::EncryptionKeyNotFound` - if the backup encryption key is not found in the metadata.
    pub async fn remove_factor(
        &self,
        backup_id: &str,
        factor_id: &str,
        backup_encryption_key_to_delete: Option<&BackupEncryptionKey>,
    ) -> Result<(), BackupManagerError> {
        let Some((mut metadata, e_tag)) = self.get_metadata_by_backup_id(backup_id).await? else {
            return Err(BackupManagerError::BackupNotFound);
        };

        let Some(e_tag) = e_tag else {
            return Err(BackupManagerError::ETagNotFound);
        };

        let factor_index = metadata.factors.iter().position(|f| f.id == factor_id);

        let Some(index) = factor_index else {
            return Err(BackupManagerError::FactorNotFound);
        };

        metadata.factors.remove(index);

        // If there are no more regular factors, delete the backup
        if metadata.factors.is_empty() {
            return self.delete_backup(backup_id).await;
        }

        // If a backup encryption key is provided, remove it from the metadata
        if let Some(encryption_key) = backup_encryption_key_to_delete {
            if let Some(key_index) = metadata.keys.iter().position(|k| k == encryption_key) {
                metadata.keys.remove(key_index);
            } else {
                // return Err if the key is not found
                return Err(BackupManagerError::EncryptionKeyNotFound);
            }
        }

        self.update_backup_metadata(backup_id, &e_tag, &metadata)
            .await
    }

    /// Removes a `Sync` factor from the backup metadata in S3 by factor ID.
    ///
    /// # Errors
    /// - `BackupManagerError::BackupNotFound` - if the backup does not exist.
    /// - `BackupManagerError::FactorNotFound` - if the factor does not exist.
    pub async fn remove_sync_factor(
        &self,
        backup_id: &str,
        factor_id: &str,
    ) -> Result<(), BackupManagerError> {
        let Some((mut metadata, e_tag)) = self.get_metadata_by_backup_id(backup_id).await? else {
            return Err(BackupManagerError::BackupNotFound);
        };

        let Some(e_tag) = e_tag else {
            return Err(BackupManagerError::ETagNotFound);
        };

        let factor_index = metadata.sync_factors.iter().position(|f| f.id == factor_id);

        let Some(index) = factor_index else {
            return Err(BackupManagerError::FactorNotFound);
        };

        metadata.sync_factors.remove(index);

        self.update_backup_metadata(backup_id, &e_tag, &metadata)
            .await
    }

    /// Deletes a backup from S3.
    ///
    /// # Errors
    /// - Will return S3 errors if the backup does not exist or something else goes wrong deleting from S3.
    pub async fn delete_backup(&self, backup_id: &str) -> Result<(), BackupManagerError> {
        self.s3_client
            .delete_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .send()
            .await?;

        Ok(())
    }

    /// Updates the backup metadata in S3 by backup ID.
    ///
    /// Uses COPY to preserve backup content.
    async fn update_backup_metadata(
        &self,
        backup_id: &str,
        e_tag: &str,
        metadata: &BackupMetadata,
    ) -> Result<(), BackupManagerError> {
        let compressed_metadata = metadata.to_compressed_metadata()?;

        self.s3_client
            .copy_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .copy_source(format!(
                "{}/{}",
                self.environment.s3_bucket(),
                get_backup_key(backup_id)
            ))
            .metadata_directive(aws_sdk_s3::types::MetadataDirective::Replace)
            .metadata("backup-metadata", compressed_metadata)
            .copy_source_if_match(e_tag)
            .send()
            .await
            .map_err(BackupManagerError::CopyObjectError)?;

        Ok(())
    }

    /// Validates that factor limits are not exceeded
    fn validate_factor_limits(metadata: &BackupMetadata) -> Result<(), BackupManagerError> {
        let passkey_count = metadata
            .factors
            .iter()
            .filter(|f| matches!(f.kind, FactorKind::Passkey { .. }))
            .count();

        if passkey_count > MAX_PASSKEYS {
            return Err(BackupManagerError::LimitExceeded {
                attr: "passkey".to_string(),
                current: passkey_count,
                max: MAX_PASSKEYS,
            });
        }

        if metadata.factors.len() > MAX_MAIN_FACTORS {
            return Err(BackupManagerError::LimitExceeded {
                attr: "main factor".to_string(),
                current: metadata.factors.len(),
                max: MAX_MAIN_FACTORS,
            });
        }

        if metadata.sync_factors.len() > MAX_SYNC_FACTORS {
            return Err(BackupManagerError::LimitExceeded {
                attr: "sync factor".to_string(),
                current: metadata.sync_factors.len(),
                max: MAX_SYNC_FACTORS,
            });
        }

        if metadata.keys.len() > MAX_BACKUP_ENCRYPTION_KEYS {
            return Err(BackupManagerError::LimitExceeded {
                attr: "backup_encryption_key".to_string(),
                current: metadata.keys.len(),
                max: MAX_BACKUP_ENCRYPTION_KEYS,
            });
        }

        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        let result = self
            .s3_client
            .head_bucket()
            .bucket(self.environment.s3_bucket())
            .send()
            .await;

        match result {
            Ok(_) => true,
            Err(err) => {
                tracing::error!("System is not ready. BackupStorage (HeadBucket): {:?}", err);
                false
            }
        }
    }
}

pub struct FoundBackup {
    pub backup: Vec<u8>,
    pub metadata: BackupMetadata,
}

fn get_backup_key(backup_id: &str) -> String {
    backup_id.to_string()
}

#[derive(thiserror::Error, Debug)]
pub enum BackupManagerError {
    #[error("Failed to upload object to S3: {0:?}")]
    PutObjectError(#[from] SdkError<aws_sdk_s3::operation::put_object::PutObjectError>),
    #[error("Failed to serialize/deserialize JSON: {0:?}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Failed to download object from S3: {0:?}")]
    GetObjectError(#[from] SdkError<aws_sdk_s3::operation::get_object::GetObjectError>),
    #[error("Failed to get object metadata from S3: {0:?}")]
    HeadObjectError(#[from] SdkError<aws_sdk_s3::operation::head_object::HeadObjectError>),
    #[error("Failed to copy object in S3: {0:?}")]
    CopyObjectError(SdkError<aws_sdk_s3::operation::copy_object::CopyObjectError>),
    #[error("Failed to convert ByteStream to bytes: {0:?}")]
    ByteStreamError(#[from] aws_sdk_s3::primitives::ByteStreamError),
    #[error("Sync factor must be a keypair")]
    SyncFactorMustBeKeypair,
    #[error("Backup not found")]
    BackupNotFound,
    #[error("Metadata not found in object metadata")]
    MetadataNotFound,
    #[error("Compressed metadata too large ({0} bytes). Maximum size is 2048 bytes.")]
    MetadataTooLarge(usize),
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[error("Limit exceeded for {attr}: {current}, maximum allowed: {max}")]
    LimitExceeded {
        attr: String,
        current: usize,
        max: usize,
    },
    #[error("Factor already exists")]
    FactorAlreadyExists,
    #[error("Factor not found")]
    FactorNotFound,
    #[error("Encryption key not found in metadata")]
    EncryptionKeyNotFound,
    #[error("ETag not found")]
    ETagNotFound,
    #[error("Failed to delete object from S3: {0:?}")]
    DeleteObjectError(#[from] SdkError<aws_sdk_s3::operation::delete_object::DeleteObjectError>),
    #[error("Update conflict. The provided manifest hash does not match the current manifest hash. Sync the latest state first.")]
    UpdateConflict,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::backup_metadata::{BackupMetadata, Factor, FactorKind, OidcAccountKind};
    use crate::types::encryption_key::BackupEncryptionKey;
    use crate::types::Environment;
    use aws_sdk_s3::error::ProvideErrorMetadata;
    use aws_sdk_s3::Client as S3Client;
    use chrono::DateTime;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    #[test]
    fn test_factor_limits() {
        let backup_id = Uuid::new_v4().to_string();

        // Main Factors
        let mut metadata = BackupMetadata {
            id: backup_id.clone(),
            factors: (0..=10) // MAX_MAIN_FACTORS
                .map(|i| {
                    Factor::new_oidc_account(
                        OidcAccountKind::Google {
                            sub: format!("user_{i}"),
                            email: format!("user{i}@example.com"),
                        },
                        format!("provider_{i}"),
                    )
                })
                .collect(),
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };

        let result = BackupStorage::validate_factor_limits(&metadata);
        assert!(matches!(
            result,
            Err(BackupManagerError::LimitExceeded { .. })
        ));

        // Sync Factors
        metadata.factors = vec![];
        metadata.sync_factors =
            (0..=10) // MAX_SYNC_FACTORS
                .map(|i| Factor::new_ec_keypair(format!("public_key_{i}")))
                .collect();

        let result = BackupStorage::validate_factor_limits(&metadata);
        assert!(matches!(
            result,
            Err(BackupManagerError::LimitExceeded { .. })
        ));

        // Backup Encryption Keys
        metadata.sync_factors = vec![];
        metadata.keys = (0..=10) // MAX_BACKUP_ENCRYPTION_KEYS
            .map(|i| BackupEncryptionKey::Prf {
                encrypted_key: format!("key_{i}"),
            })
            .collect();

        let result = BackupStorage::validate_factor_limits(&metadata);
        assert!(matches!(
            result,
            Err(BackupManagerError::LimitExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_create_and_get_backup() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        let test_backup_id = Uuid::new_v4().to_string();
        let test_primary_factor_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let test_webauthn_credential = json!({
          "cred": {
            "cred_id": "g967rT-WLv033gKWfMVpfg",
            "cred": {
              "type_": "ES256",
              "key": {
                "EC_EC2": {
                  "curve": "SECP256R1",
                  "x": "JXxTIZGm00nLcAreAWVdxNRaXTtLHn574LZN54Ua9oU",
                  "y": "Excf9w7v519SL8eHA9H5n4V8BcheP59Jz9sHyWs3oDM"
                }
              }
            },
            "counter": 0,
            "transports": null,
            "user_verified": true,
            "backup_eligible": true,
            "backup_state": true,
            "registration_policy": "required",
            "extensions": {
              "cred_protect": "Ignored",
              "hmac_create_secret": "NotRequested",
              "appid": "NotRequested",
              "cred_props": "Ignored"
            },
            "attestation": {
              "data": "None",
              "metadata": "None"
            },
            "attestation_format": "none"
          }
        });
        let backup_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![Factor {
                id: test_primary_factor_id.clone(),
                kind: FactorKind::Passkey {
                    webauthn_credential: serde_json::from_value(test_webauthn_credential).unwrap(),
                    registration: json!({}),
                },
                created_at: DateTime::default(),
            }],
            sync_factors: vec![],
            keys: vec![BackupEncryptionKey::Prf {
                encrypted_key: "ENCRYPTED_KEY".to_string(),
            }],
            manifest_hash: hex::encode([1u8; 32]),
        };

        // Validate factor limits (asserting validate_factor_limits works as expected)
        BackupStorage::validate_factor_limits(&backup_metadata).unwrap();

        // Create a backup
        backup_storage
            .create(test_backup_data.clone(), &backup_metadata)
            .await
            .unwrap();

        // Get the backup
        let found_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");
        assert_eq!(found_backup.backup, test_backup_data);
        assert_eq!(found_backup.metadata, backup_metadata);
        assert_eq!(found_backup.metadata.manifest_hash, hex::encode([1u8; 32]));

        // Try to get a non-existing backup - should return None
        let found_backup = backup_storage
            .get_by_backup_id("non_existing_id")
            .await
            .unwrap();
        assert!(found_backup.is_none());

        // Try to create a backup with the same ID - should return an error
        let result = backup_storage
            .create(test_backup_data.clone(), &backup_metadata)
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::PutObjectError(SdkError::ServiceError(err))) => {
                assert_eq!(err.err().code(), Some("PreconditionFailed"));
            }
            _ => panic!("Expected PutObjectError"),
        }

        // Clean up the test backup
        s3_client
            .delete_object()
            .bucket(environment.s3_bucket())
            .key(get_backup_key(&test_backup_id))
            .send()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_update_by_backup_id() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        let test_backup_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let updated_backup_data = vec![6, 7, 8, 9, 10];

        // Create a backup
        backup_storage
            .create(
                test_backup_data.clone(),
                &BackupMetadata {
                    id: test_backup_id.clone(),
                    factors: vec![],
                    sync_factors: vec![],
                    keys: vec![],
                    manifest_hash: hex::encode([1u8; 32]),
                },
            )
            .await
            .unwrap();

        // Update the backup
        backup_storage
            .update_backup(
                &test_backup_id,
                updated_backup_data.clone(),
                hex::encode([1u8; 32]),
                hex::encode([2u8; 32]),
            )
            .await
            .unwrap();

        // Get the updated backup
        let found_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");
        assert_eq!(found_backup.backup, updated_backup_data);
        assert_eq!(found_backup.metadata.manifest_hash, hex::encode([2u8; 32]));
    }

    #[tokio::test]
    async fn test_add_factor() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        // Create a test backup
        let test_backup_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };

        // Create a backup
        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Create a test factor
        let google_account = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "12345".to_string(),
                email: "test@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );

        // Add the factor
        backup_storage
            .add_factor(&test_backup_id, google_account.clone(), None)
            .await
            .unwrap();

        // Get the updated metadata and verify the factor was added
        let updated_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");

        assert_eq!(updated_backup.metadata.factors.len(), 1);
        assert_eq!(updated_backup.metadata.factors[0].kind, google_account.kind);
        assert_eq!(
            updated_backup.metadata.manifest_hash,
            hex::encode([1u8; 32])
        );

        // Try to add the same factor again - should fail with FactorAlreadyExists
        let result = backup_storage
            .add_factor(&test_backup_id, google_account.clone(), None)
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::FactorAlreadyExists) => {}
            _ => panic!("Expected FactorAlreadyExists"),
        }

        // Try to add a factor to a non-existent backup - should fail with BackupNotFound
        let result = backup_storage
            .add_factor("non_existent_backup", google_account.clone(), None)
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::BackupNotFound) => {}
            _ => panic!("Expected BackupNotFound"),
        }
    }

    #[tokio::test]
    async fn test_add_factor_with_encryption_key() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        // Create a test backup with initial encryption key
        let test_backup_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let initial_key = BackupEncryptionKey::Prf {
            encrypted_key: "INITIAL_KEY".to_string(),
        };
        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![initial_key],
            manifest_hash: hex::encode([1u8; 32]),
        };

        // Create a backup
        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Create a test factor and new encryption key
        let new_factor = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "67890".to_string(),
                email: "test2@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );

        let new_key = BackupEncryptionKey::Prf {
            encrypted_key: "NEW_KEY".to_string(),
        };

        // Add the factor with the new encryption key
        backup_storage
            .add_factor(&test_backup_id, new_factor.clone(), Some(new_key.clone()))
            .await
            .unwrap();

        // Get the updated metadata and verify both the factor and key were added
        let updated_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");

        assert_eq!(updated_backup.metadata.factors.len(), 1);
        assert_eq!(updated_backup.metadata.factors[0].kind, new_factor.kind);

        // Check that both keys are present
        assert_eq!(updated_backup.metadata.keys.len(), 2);
        match &updated_backup.metadata.keys[1] {
            BackupEncryptionKey::Prf { encrypted_key } => {
                assert_eq!(encrypted_key, "NEW_KEY");
            }
            _ => panic!("Expected Prf key"),
        }
    }

    #[tokio::test]
    async fn test_add_sync_factor() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        // Create a test backup
        let test_backup_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };

        // Create a backup
        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Add the sync factor
        let keypair_factor = Factor::new_ec_keypair("public-key".to_string());
        backup_storage
            .add_sync_factor(&test_backup_id, keypair_factor.clone())
            .await
            .unwrap();

        // Get the updated metadata and verify the sync factor was added
        let updated_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");

        assert_eq!(updated_backup.metadata.sync_factors.len(), 1);
        assert_eq!(
            updated_backup.metadata.sync_factors[0].kind,
            keypair_factor.kind
        );

        // Try to add the same sync factor again - should fail with FactorAlreadyExists
        let result = backup_storage
            .add_sync_factor(&test_backup_id, keypair_factor.clone())
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::FactorAlreadyExists) => {}
            _ => panic!("Expected FactorAlreadyExists"),
        }

        // Try to add an invalid factor type (OIDC account) as a sync factor - should fail
        let oidc_factor = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "12345".to_string(),
                email: "test@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );
        let result = backup_storage
            .add_sync_factor(&test_backup_id, oidc_factor)
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::SyncFactorMustBeKeypair) => {}
            _ => panic!("Expected SyncFactorMustBeKeypair"),
        }

        // Try to add a sync factor to a non-existent backup - should fail with BackupNotFound
        let result = backup_storage
            .add_sync_factor("non_existent_backup", keypair_factor.clone())
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::BackupNotFound) => {}
            _ => panic!("Expected BackupNotFound"),
        }
    }

    #[tokio::test]
    async fn test_remove_factor() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        // Create a test backup with two factors
        let test_backup_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let factor1 = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "12345".to_string(),
                email: "test1@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );
        let factor2 = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "67890".to_string(),
                email: "test2@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );
        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![factor1.clone(), factor2.clone()],
            sync_factors: vec![],
            keys: vec![],
            manifest_hash: hex::encode([1u8; 32]),
        };
        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Remove the first factor
        backup_storage
            .remove_factor(&test_backup_id, &factor1.id, None)
            .await
            .unwrap();

        // Get the updated metadata and verify the factor was removed
        let updated_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");

        assert_eq!(updated_backup.metadata.factors.len(), 1);
        assert_eq!(updated_backup.metadata.factors[0].id, factor2.id);

        // Try to remove a non-existent factor - should fail with FactorNotFound
        let result = backup_storage
            .remove_factor(&test_backup_id, "non_existent_factor", None)
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::FactorNotFound) => {}
            _ => panic!("Expected FactorNotFound"),
        }

        // Remove the last factor - should delete the backup
        backup_storage
            .remove_factor(&test_backup_id, &factor2.id, None)
            .await
            .unwrap();

        // Verify the backup was deleted
        let result = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
