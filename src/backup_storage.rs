use crate::types::backup_metadata::{BackupMetadata, Factor, FactorKind};
use crate::types::encryption_key::BackupEncryptionKey;
use crate::types::Environment;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use std::sync::Arc;

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

    /// Creates a backup and metadata in S3.
    ///
    /// # Errors
    /// * If the backup or metadata cannot be serialized to JSON, `BackupManagerError::SerdeJsonError` is returned.
    /// * If the backup or metadata cannot be uploaded to S3 (e.g. due to internal error or because
    ///   this backup ID is already used), `BackupManagerError::PutObjectError` is returned.
    ///   Note that if the backup already exists, this function will throw an error.
    pub async fn create(
        &self,
        backup: Vec<u8>,
        backup_metadata: &BackupMetadata,
    ) -> Result<(), BackupManagerError> {
        // Save encrypted backup to S3
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(&backup_metadata.id))
            .body(ByteStream::from(backup))
            .if_none_match("*")
            .send()
            .await?;

        // Save metadata to S3
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(&backup_metadata.id))
            .body(ByteStream::from(serde_json::to_vec(backup_metadata)?))
            .if_none_match("*")
            .send()
            .await?;

        Ok(())
    }

    /// Retrieves a backup and metadata from S3 by backup ID, which is linked to credential using
    /// separate `FactorLookup` service.
    ///
    /// If the backup or metadata does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, `BackupManagerError::SerdeJsonError` is returned.
    /// * If the backup or metadata cannot be downloaded from S3, `BackupManagerError::GetObjectError` is returned.
    /// * If the backup or metadata cannot be converted to bytes, `BackupManagerError::ByteStreamError` is returned.
    pub async fn get_by_backup_id(
        &self,
        backup_id: &str,
    ) -> Result<Option<FoundBackup>, BackupManagerError> {
        // Get encrypted backup from S3
        let backup = self.get_backup_by_backup_id(backup_id).await?;

        // Get metadata from S3
        let metadata = self.get_metadata_by_backup_id(backup_id).await?;

        match (backup, metadata) {
            // If both the backup and metadata exist, return them
            (Some(backup), Some((metadata, _))) => Ok(Some(FoundBackup { backup, metadata })),
            // If either the backup or metadata does not exist, return None
            _ => Ok(None),
        }
    }

    /// Retrieves metadata from S3 by backup ID, which is linked to credential using
    /// separate `FactorLookup` service.
    ///
    /// If the metadata does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, `BackupManagerError::SerdeJsonError` is returned.
    /// * If the metadata cannot be downloaded from S3, `BackupManagerError::GetObjectError` is returned.
    /// * If the metadata cannot be converted to bytes, `BackupManagerError::ByteStreamError` is returned.
    pub async fn get_metadata_by_backup_id(
        &self,
        backup_id: &str,
    ) -> Result<Option<(BackupMetadata, ETag)>, BackupManagerError> {
        let result = self
            .s3_client
            .get_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(backup_id))
            .send()
            .await;

        match result {
            Ok(result) => {
                let metadata = result.body.collect().await?.into_bytes().to_vec();
                let metadata: BackupMetadata = serde_json::from_slice(&metadata)?;
                Ok(Some((metadata, result.e_tag)))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(err) => Err(BackupManagerError::GetObjectError(err)),
        }
    }

    /// Retrieves a backup from S3 by backup ID, which is linked to credential using
    /// separate `FactorLookup` service.
    ///
    /// If the backup does not exist, None is returned.
    ///
    /// # Errors
    /// * If the backup cannot be deserialized from JSON, `BackupManagerError::SerdeJsonError` is returned.
    /// * If the backup cannot be downloaded from S3, `BackupManagerError::GetObjectError` is returned.
    /// * If the backup cannot be converted to bytes, `BackupManagerError::ByteStreamError` is returned.
    pub async fn get_backup_by_backup_id(
        &self,
        backup_id: &str,
    ) -> Result<Option<Vec<u8>>, BackupManagerError> {
        let backup = self
            .s3_client
            .get_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .send()
            .await;

        match backup {
            Ok(backup) => {
                let backup = backup.body.collect().await?.into_bytes().to_vec();
                Ok(Some(backup))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(err) => Err(BackupManagerError::GetObjectError(err)),
        }
    }

    /// Updates a backup in S3 by backup ID. Overwrites the existing backup with the new one.
    ///
    /// # Errors
    /// * If the backup cannot be uploaded to S3, `BackupManagerError::PutObjectError` is returned.
    /// * If the backup cannot be converted to bytes, `BackupManagerError::ByteStreamError` is returned.
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
            return Err(BackupManagerError::ManifestHashMismatch);
        }

        metadata.manifest_hash = new_manifest_hash;

        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .body(ByteStream::from(backup))
            .send()
            .await?;

        // Save the new metadata
        // NOTE: There's a possibility of a conflict here, where saving the metadata fails but the backup is updated.
        // For this case, the client will get an error on the update, and will be able to retry the update. Recovery is also possible from the previous state.
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(backup_id))
            .if_match(e_tag)
            .body(ByteStream::from(serde_json::to_vec(&metadata)?))
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

        // Save the updated metadata
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(backup_id))
            .if_match(e_tag)
            .body(ByteStream::from(serde_json::to_vec(&metadata)?))
            .send()
            .await?;

        Ok(())
    }

    /// Adds a sync factor to the backup metadata in S3.
    ///
    /// # Errors
    /// - `BackupManagerError::SyncFactorMustBeKeypair` - if the sync factor is not a keypair. Only keypairs are supported sync factors.
    /// - `BackupManagerError::BackupNotFound` - if the backup does not exist.
    /// - `BackupManagerError::FactorAlreadyExists` - if the sync factor already exists. Duplicates are prevented because it makes no sense and makes
    ///   maintenance harder (e.g. when deleting a factor)
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

        // Save the updated metadata
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(backup_id))
            .if_match(e_tag)
            .body(ByteStream::from(serde_json::to_vec(&metadata)?))
            .send()
            .await?;

        Ok(())
    }

    /// Removes a `Main` factor from the backup metadata in S3 by factor ID.
    /// If this is the last `Main` factor, the entire backup will be deleted, even if sync factors exist.
    ///
    /// `backup_encryption_key_to_delete` is optionally used to delete the provided backup encryption key from
    /// metadata if it is no longer needed. For example, if last OIDC factor is removed, the Turnkey
    /// account can no longer be used to decrypt the backup, so the key and reference to Turnkey IDs
    /// should be deleted.
    ///
    /// # Returns
    /// - `DeletionResult::BackupDeleted` if the backup was deleted (because it was the last Main factor).
    /// - `DeletionResult::OnlyFactorDeleted` if the backup was not deleted, and only the factor was deleted.
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
    ) -> Result<DeletionResult, BackupManagerError> {
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

        // If a backup encryption key is provided, remove it from the metadata, validating no orphans are left
        if let Some(encryption_key) = backup_encryption_key_to_delete {
            if let Some(key_index) = metadata.keys.iter().position(|k| k == encryption_key) {
                metadata.keys.remove(key_index);

                // Ensure we are not removing keys and leaving unusable factors
                match encryption_key {
                    BackupEncryptionKey::Prf { .. } => {
                        if !metadata
                            .keys
                            .iter()
                            .any(|k| matches!(k, BackupEncryptionKey::Prf { .. }))
                            && metadata
                                .factors
                                .iter()
                                .any(|f| matches!(f.kind, FactorKind::Passkey { .. }))
                        {
                            return Err(BackupManagerError::FactorOrphanedFromEncryptionKey);
                        }
                    }
                    BackupEncryptionKey::Icloud { .. } => {
                        if !metadata
                            .keys
                            .iter()
                            .any(|k| matches!(k, BackupEncryptionKey::Icloud { .. }))
                            && metadata
                                .factors
                                .iter()
                                .any(|f| matches!(f.kind, FactorKind::EcKeypair { .. }))
                        {
                            return Err(BackupManagerError::FactorOrphanedFromEncryptionKey);
                        }
                    }
                    BackupEncryptionKey::Turnkey { .. } => {
                        if !metadata
                            .keys
                            .iter()
                            .any(|k| matches!(k, BackupEncryptionKey::Turnkey { .. }))
                            && metadata
                                .factors
                                .iter()
                                .any(|f| matches!(f.kind, FactorKind::OidcAccount { .. }))
                        {
                            return Err(BackupManagerError::FactorOrphanedFromEncryptionKey);
                        }
                    }
                }
            } else {
                // return Err if the key is not found
                return Err(BackupManagerError::EncryptionKeyNotFound);
            }
        }

        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(backup_id))
            .if_match(e_tag)
            .body(ByteStream::from(serde_json::to_vec(&metadata)?))
            .send()
            .await?;

        Ok(DeletionResult::OnlyFactorDeleted)
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

        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(backup_id))
            .if_match(e_tag)
            .body(ByteStream::from(serde_json::to_vec(&metadata)?))
            .send()
            .await?;

        Ok(())
    }

    /// Deletes a backup and its metadata from S3.
    ///
    /// # Errors
    /// - Will return S3 errors if the backup or metadata does not exist or something else goes wrong deleting from S3.
    pub async fn delete_backup(
        &self,
        backup_id: &str,
    ) -> Result<DeletionResult, BackupManagerError> {
        self.s3_client
            .delete_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .send()
            .await?;

        self.s3_client
            .delete_object()
            .bucket(self.environment.s3_bucket())
            .key(get_metadata_key(backup_id))
            .send()
            .await?;

        Ok(DeletionResult::BackupDeleted)
    }

    /// Checks whether a backup exists for a specific ID.
    ///
    /// # Errors
    /// Will error if something goes unexpectedly wrong calling the S3 API.
    pub async fn does_backup_exist(&self, backup_id: &str) -> Result<bool, BackupManagerError> {
        let result = self
            .s3_client
            .head_object()
            .bucket(self.environment.s3_bucket())
            .key(get_backup_key(backup_id))
            .send()
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(err)) if err.err().is_not_found() => Ok(false),
            Err(err) => Err(err.into()),
        }
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
    format!("{backup_id}/backup")
}

fn get_metadata_key(backup_id: &str) -> String {
    format!("{backup_id}/metadata")
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeletionResult {
    BackupDeleted,
    OnlyFactorDeleted,
}

#[derive(thiserror::Error, Debug)]
pub enum BackupManagerError {
    #[error("Failed to HeadObject: {0:?}")]
    HeadObjectError(#[from] SdkError<aws_sdk_s3::operation::head_object::HeadObjectError>),
    #[error("Failed to upload object to S3: {0:?}")]
    PutObjectError(#[from] SdkError<aws_sdk_s3::operation::put_object::PutObjectError>),
    #[error("Failed to download object from S3: {0:?}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Failed to download object from S3: {0:?}")]
    GetObjectError(#[from] SdkError<aws_sdk_s3::operation::get_object::GetObjectError>),
    #[error("Failed to convert ByteStream to bytes: {0:?}")]
    ByteStreamError(#[from] aws_sdk_s3::primitives::ByteStreamError),
    #[error("Sync factor must be a keypair")]
    SyncFactorMustBeKeypair,
    #[error("Backup not found")]
    BackupNotFound,
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
    ManifestHashMismatch,
    #[error("A factor would be orphaned by removing the specific encryption key.")]
    FactorOrphanedFromEncryptionKey,
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
    use rand::rngs::OsRng;
    use rand::RngCore;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    fn gen_backup_id() -> String {
        let mut test_backup_id: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut test_backup_id);
        format!("backup_account_{}", hex::encode(test_backup_id))
    }

    #[tokio::test]
    async fn test_create_and_get_backup() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        let test_backup_id = gen_backup_id();
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

        // Try to create a backup with the same ID, when only one of the files exists -
        // should still return an error
        s3_client
            .delete_object()
            .bucket(environment.s3_bucket())
            .key(get_metadata_key(&test_backup_id))
            .send()
            .await
            .unwrap();
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
    }

    #[tokio::test]
    async fn test_update_by_backup_id() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        let test_backup_id = gen_backup_id();
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
        let test_backup_id = gen_backup_id();
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
                masked_email: "t****@example.com".to_string(),
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
        let test_backup_id = gen_backup_id();
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
                masked_email: "t2****@example.com".to_string(),
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
        let test_backup_id = gen_backup_id();
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
                masked_email: "t****@example.com".to_string(),
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
        let test_backup_id = gen_backup_id();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let factor1 = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "12345".to_string(),
                masked_email: "t****@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );
        let factor2 = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "67890".to_string(),
                masked_email: "t2****@example.com".to_string(),
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

    /// OIDC factors (Google or Apple for example) share the same underlying backup encryption key stored in Turnkey,
    /// when removing one of the factors it's important to verify that the backup encryption key is not removed if there is another
    /// OIDC factor remaining. Otherwise, even though the user will be able to authenticate to the backup remote services, they won't
    /// be able to actually decrypt their backup.
    #[tokio::test]
    async fn test_cannot_remove_turnkey_key_with_oidc_factor_remaining() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        // Create a test backup with two OIDC factors and one Turnkey key
        let test_backup_id = gen_backup_id();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let turnkey_key = BackupEncryptionKey::Turnkey {
            encrypted_key: "TURNKEY_KEY".to_string(),
            turnkey_account_id: "org_123".to_string(),
            turnkey_user_id: "user_456".to_string(),
            turnkey_private_key_id: "key_789".to_string(),
        };

        let google_factor = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "12345".to_string(),
                masked_email: "t****@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );

        let apple_factor = Factor::new_oidc_account(
            OidcAccountKind::Apple {
                sub: "67890".to_string(),
                masked_email: "t2****@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );

        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![google_factor.clone(), apple_factor.clone()],
            sync_factors: vec![],
            keys: vec![turnkey_key.clone()],
            manifest_hash: hex::encode([1u8; 32]),
        };

        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Try to remove the first OIDC factor and the Turnkey key while another OIDC factor remains
        // This should fail because the remaining OIDC factor needs the Turnkey key
        let result = backup_storage
            .remove_factor(&test_backup_id, &google_factor.id, Some(&turnkey_key))
            .await;

        assert!(result.is_err());
        match result {
            Err(BackupManagerError::FactorOrphanedFromEncryptionKey) => {
                // Expected error - we cannot remove the Turnkey key while an OIDC factor remains
            }
            _ => panic!("Expected FactorOrphanedFromEncryptionKey"),
        }

        // Verify the backup still has both factors and the key
        let updated_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");

        assert_eq!(updated_backup.metadata.factors.len(), 2);
        assert_eq!(updated_backup.metadata.keys.len(), 1);
    }

    #[tokio::test]
    async fn test_can_remove_turnkey_key_when_last_oidc_factor_removed() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment, s3_client.clone());

        // Create a test backup with one OIDC factor, one Passkey factor, and both Turnkey and PRF keys
        let test_backup_id = gen_backup_id();
        let test_backup_data = vec![1, 2, 3, 4, 5];

        let turnkey_key = BackupEncryptionKey::Turnkey {
            encrypted_key: "TURNKEY_KEY".to_string(),
            turnkey_account_id: "org_123".to_string(),
            turnkey_user_id: "user_456".to_string(),
            turnkey_private_key_id: "key_789".to_string(),
        };

        let prf_key = BackupEncryptionKey::Prf {
            encrypted_key: "PRF_KEY".to_string(),
        };

        let google_factor = Factor::new_oidc_account(
            OidcAccountKind::Google {
                sub: "12345".to_string(),
                masked_email: "t****@example.com".to_string(),
            },
            "turnkey_provider_id".to_string(),
        );

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

        let passkey_factor = Factor {
            id: Uuid::new_v4().to_string(),
            kind: FactorKind::Passkey {
                webauthn_credential: serde_json::from_value(test_webauthn_credential).unwrap(),
                registration: json!({}),
            },
            created_at: DateTime::default(),
        };

        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![google_factor.clone(), passkey_factor.clone()],
            sync_factors: vec![],
            keys: vec![turnkey_key.clone(), prf_key.clone()],
            manifest_hash: hex::encode([1u8; 32]),
        };

        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Remove the last OIDC factor along with the Turnkey key
        // This should succeed because no OIDC factors will remain
        let result = backup_storage
            .remove_factor(&test_backup_id, &google_factor.id, Some(&turnkey_key))
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DeletionResult::OnlyFactorDeleted);

        // Verify the backup now has only the Passkey factor and PRF key
        let updated_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");

        assert_eq!(updated_backup.metadata.factors.len(), 1);
        assert_eq!(updated_backup.metadata.factors[0].id, passkey_factor.id);
        assert_eq!(updated_backup.metadata.keys.len(), 1);
        match &updated_backup.metadata.keys[0] {
            BackupEncryptionKey::Prf { .. } => {
                // Expected - only PRF key should remain
            }
            _ => panic!("Expected only PRF key to remain"),
        }
    }
}
