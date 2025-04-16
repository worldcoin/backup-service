use crate::types::backup_metadata::BackupMetadata;
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

impl BackupStorage {
    pub fn new(environment: Environment, s3_client: Arc<S3Client>) -> Self {
        Self {
            environment,
            s3_client,
        }
    }

    /// Creates a backup and metadata in S3.
    ///
    /// # Errors
    /// * If the backup or metadata cannot be serialized to JSON, BackupManagerError::SerdeJsonError is returned.
    /// * If the backup or metadata cannot be uploaded to S3 (e.g. due to internal error or because
    ///   this primary factor ID is already used), BackupManagerError::PutObjectError is returned.
    ///   Note that if the backup already exists, this function will throw an error.
    pub async fn create(
        &self,
        backup: Vec<u8>,
        backup_metadata: &BackupMetadata,
    ) -> Result<(), BackupManagerError> {
        // Save encrypted backup to S3
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_backup_key(&backup_metadata.primary_factor.id))
            .body(ByteStream::from(backup))
            .if_none_match("*")
            .send()
            .await?;

        // Save metadata to S3
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_metadata_key(&backup_metadata.primary_factor.id))
            .body(ByteStream::from(serde_json::to_vec(backup_metadata)?))
            .if_none_match("*")
            .send()
            .await?;

        Ok(())
    }

    /// Retrieves a backup and metadata from S3 by primary factor ID, which is specified in metadata
    /// during creation. If the backup or metadata does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, BackupManagerError::SerdeJsonError is returned.
    /// * If the backup or metadata cannot be downloaded from S3, BackupManagerError::GetObjectError is returned.
    /// * If the backup or metadata cannot be converted to bytes, BackupManagerError::ByteStreamError is returned.
    pub async fn get_by_primary_factor_id(
        &self,
        primary_factor_id: &str,
    ) -> Result<Option<FoundBackup>, BackupManagerError> {
        // Get encrypted backup from S3
        let backup = self
            .get_backup_by_primary_factor_id(primary_factor_id)
            .await?;

        // Get metadata from S3
        let metadata = self
            .get_metadata_by_primary_factor_id(primary_factor_id)
            .await?;

        match (backup, metadata) {
            // If both the backup and metadata exist, return them
            (Some(backup), Some(metadata)) => Ok(Some(FoundBackup { backup, metadata })),
            // If either the backup or metadata does not exist, return None
            _ => Ok(None),
        }
    }

    /// Retrieves metadata from S3 by primary factor ID, which is specified in metadata during
    /// creation. If the metadata does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, BackupManagerError::SerdeJsonError is returned.
    /// * If the metadata cannot be downloaded from S3, BackupManagerError::GetObjectError is returned.
    /// * If the metadata cannot be converted to bytes, BackupManagerError::ByteStreamError is returned.
    pub async fn get_metadata_by_primary_factor_id(
        &self,
        primary_factor_id: &str,
    ) -> Result<Option<BackupMetadata>, BackupManagerError> {
        let metadata = self
            .s3_client
            .get_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_metadata_key(primary_factor_id))
            .send()
            .await;

        match metadata {
            Ok(metadata) => {
                let metadata = metadata.body.collect().await?.into_bytes().to_vec();
                let metadata: BackupMetadata = serde_json::from_slice(&metadata)?;
                Ok(Some(metadata))
            }
            Err(SdkError::ServiceError(err)) if err.err().is_no_such_key() => Ok(None),
            Err(err) => Err(BackupManagerError::GetObjectError(err)),
        }
    }

    /// Retrieves a backup from S3 by primary factor ID, which is specified in metadata during
    /// creation. If the backup does not exist, None is returned.
    ///
    /// # Errors
    /// * If the backup cannot be deserialized from JSON, BackupManagerError::SerdeJsonError is returned.
    /// * If the backup cannot be downloaded from S3, BackupManagerError::GetObjectError is returned.
    /// * If the backup cannot be converted to bytes, BackupManagerError::ByteStreamError is returned.
    pub async fn get_backup_by_primary_factor_id(
        &self,
        primary_factor_id: &str,
    ) -> Result<Option<Vec<u8>>, BackupManagerError> {
        let backup = self
            .s3_client
            .get_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_backup_key(primary_factor_id))
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
}

pub struct FoundBackup {
    pub backup: Vec<u8>,
    pub metadata: BackupMetadata,
}

fn get_backup_key(primary_factor_id: &str) -> String {
    format!("{}/backup", primary_factor_id)
}

fn get_metadata_key(primary_factor_id: &str) -> String {
    format!("{}/metadata", primary_factor_id)
}

#[derive(thiserror::Error, Debug)]
pub enum BackupManagerError {
    #[error("Failed to upload object to S3: {0:?}")]
    PutObjectError(#[from] SdkError<aws_sdk_s3::operation::put_object::PutObjectError>),
    #[error("Failed to download object from S3: {0:?}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Failed to download object from S3: {0:?}")]
    GetObjectError(#[from] SdkError<aws_sdk_s3::operation::get_object::GetObjectError>),
    #[error("Failed to convert ByteStream to bytes: {0:?}")]
    ByteStreamError(#[from] aws_sdk_s3::primitives::ByteStreamError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::backup_metadata::{BackupMetadata, PrimaryFactor, PrimaryFactorKind};
    use crate::types::encryption_key::BackupEncryptionKey;
    use crate::types::Environment;
    use aws_sdk_s3::error::ProvideErrorMetadata;
    use aws_sdk_s3::Client as S3Client;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_create_and_get_backup() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::Development;
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment.clone(), s3_client.clone());

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
            primary_factor: PrimaryFactor {
                id: test_primary_factor_id.clone(),
                kind: PrimaryFactorKind::Passkey {
                    webauthn_credential: serde_json::from_value(test_webauthn_credential).unwrap(),
                },
            },
            keys: vec![BackupEncryptionKey::Prf {
                encrypted_key: "ENCRYPTED_KEY".to_string(),
            }],
            oidc_accounts: vec![],
        };

        // Create a backup
        backup_storage
            .create(test_backup_data.clone(), &backup_metadata)
            .await
            .unwrap();

        // Get the backup
        let found_backup = backup_storage
            .get_by_primary_factor_id(&test_primary_factor_id)
            .await
            .unwrap()
            .expect("Backup not found");
        assert_eq!(found_backup.backup, test_backup_data);
        assert_eq!(found_backup.metadata, backup_metadata);

        // Try to get a non-existing backup - should return None
        let found_backup = backup_storage
            .get_by_primary_factor_id("non_existing_id")
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
            .bucket(environment.s3_bucket_arn())
            .key(get_metadata_key(&test_primary_factor_id))
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
}
