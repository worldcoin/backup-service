use crate::types::backup_metadata::{BackupMetadata, Factor, FactorKind};
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
    ///   this backup ID is already used), BackupManagerError::PutObjectError is returned.
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
            .key(get_backup_key(&backup_metadata.id))
            .body(ByteStream::from(backup))
            .if_none_match("*")
            .send()
            .await?;

        // Save metadata to S3
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_metadata_key(&backup_metadata.id))
            .body(ByteStream::from(serde_json::to_vec(backup_metadata)?))
            .if_none_match("*")
            .send()
            .await?;

        Ok(())
    }

    /// Retrieves a backup and metadata from S3 by backup ID, which is linked to credential using
    /// separate FactorLookup service.
    ///
    /// If the backup or metadata does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, BackupManagerError::SerdeJsonError is returned.
    /// * If the backup or metadata cannot be downloaded from S3, BackupManagerError::GetObjectError is returned.
    /// * If the backup or metadata cannot be converted to bytes, BackupManagerError::ByteStreamError is returned.
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
            (Some(backup), Some(metadata)) => Ok(Some(FoundBackup { backup, metadata })),
            // If either the backup or metadata does not exist, return None
            _ => Ok(None),
        }
    }

    /// Retrieves metadata from S3 by backup ID, which is linked to credential using
    /// separate FactorLookup service.
    ///
    /// If the metadata does not exist, None is returned.
    ///
    /// # Errors
    /// * If the metadata cannot be deserialized from JSON, BackupManagerError::SerdeJsonError is returned.
    /// * If the metadata cannot be downloaded from S3, BackupManagerError::GetObjectError is returned.
    /// * If the metadata cannot be converted to bytes, BackupManagerError::ByteStreamError is returned.
    pub async fn get_metadata_by_backup_id(
        &self,
        backup_id: &str,
    ) -> Result<Option<BackupMetadata>, BackupManagerError> {
        let metadata = self
            .s3_client
            .get_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_metadata_key(backup_id))
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

    /// Retrieves a backup from S3 by backup ID, which is linked to credential using
    /// separate FactorLookup service.
    ///
    /// If the backup does not exist, None is returned.
    ///
    /// # Errors
    /// * If the backup cannot be deserialized from JSON, BackupManagerError::SerdeJsonError is returned.
    /// * If the backup cannot be downloaded from S3, BackupManagerError::GetObjectError is returned.
    /// * If the backup cannot be converted to bytes, BackupManagerError::ByteStreamError is returned.
    pub async fn get_backup_by_backup_id(
        &self,
        backup_id: &str,
    ) -> Result<Option<Vec<u8>>, BackupManagerError> {
        let backup = self
            .s3_client
            .get_object()
            .bucket(self.environment.s3_bucket_arn())
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
    /// * If the backup cannot be uploaded to S3, BackupManagerError::PutObjectError is returned.
    /// * If the backup cannot be converted to bytes, BackupManagerError::ByteStreamError is returned.
    pub async fn update_backup(
        &self,
        backup_id: &str,
        backup: Vec<u8>,
    ) -> Result<(), BackupManagerError> {
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_backup_key(backup_id))
            .body(ByteStream::from(backup))
            .send()
            .await?;

        Ok(())
    }

    /// Adds a regular factor to the backup metadata in S3.
    /// TODO/FIXME: Make this atomic.
    pub async fn add_factor(
        &self,
        backup_id: &str,
        factor: Factor,
    ) -> Result<(), BackupManagerError> {
        // Get the current metadata
        let Some(mut metadata) = self.get_metadata_by_backup_id(backup_id).await? else {
            return Err(BackupManagerError::BackupNotFound);
        };

        // Check if this factor already exists by comparing kinds
        if metadata.factors.iter().any(|f| f.kind == factor.kind)
            || metadata.sync_factors.iter().any(|f| f.kind == factor.kind)
        {
            return Err(BackupManagerError::FactorAlreadyExists);
        }

        // Add the factor to the metadata
        metadata.factors.push(factor);

        // Save the updated metadata
        self.s3_client
            .put_object()
            .bucket(self.environment.s3_bucket_arn())
            .key(get_metadata_key(backup_id))
            .body(ByteStream::from(serde_json::to_vec(&metadata)?))
            .send()
            .await?;

        Ok(())
    }

    /// Adds a sync factor to the backup metadata in S3.
    /// TODO/FIXME: Make this atomic.
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
        let Some(mut metadata) = self.get_metadata_by_backup_id(backup_id).await? else {
            return Err(BackupManagerError::BackupNotFound);
        };

        // Check if this factor already exists by comparing kinds
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
            .bucket(self.environment.s3_bucket_arn())
            .key(get_metadata_key(backup_id))
            .body(ByteStream::from(serde_json::to_vec(&metadata)?))
            .send()
            .await?;

        Ok(())
    }
}

pub struct FoundBackup {
    pub backup: Vec<u8>,
    pub metadata: BackupMetadata,
}

fn get_backup_key(backup_id: &str) -> String {
    format!("{}/backup", backup_id)
}

fn get_metadata_key(backup_id: &str) -> String {
    format!("{}/metadata", backup_id)
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
    #[error("Sync factor must be a keypair")]
    SyncFactorMustBeKeypair,
    #[error("Backup not found")]
    BackupNotFound,
    #[error("Factor already exists")]
    FactorAlreadyExists,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::backup_metadata::{BackupMetadata, Factor, FactorKind, OidcAccountKind};
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
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment.clone(), s3_client.clone());

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
            }],
            sync_factors: vec![],
            keys: vec![BackupEncryptionKey::Prf {
                encrypted_key: "ENCRYPTED_KEY".to_string(),
            }],
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
            .bucket(environment.s3_bucket_arn())
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
        let backup_storage = BackupStorage::new(environment.clone(), s3_client.clone());

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
                },
            )
            .await
            .unwrap();

        // Update the backup
        backup_storage
            .update_backup(&test_backup_id, updated_backup_data.clone())
            .await
            .unwrap();

        // Get the updated backup
        let found_backup = backup_storage
            .get_by_backup_id(&test_backup_id)
            .await
            .unwrap()
            .expect("Backup not found");
        assert_eq!(found_backup.backup, updated_backup_data);
    }

    #[tokio::test]
    async fn test_add_factor() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment.clone(), s3_client.clone());

        // Create a test backup
        let test_backup_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![],
        };

        // Create a backup
        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Create a test factor
        let google_account = Factor::new_oidc_account(OidcAccountKind::Google {
            sub: "12345".to_string(),
            email: "test@example.com".to_string(),
        });

        // Add the factor
        backup_storage
            .add_factor(&test_backup_id, google_account.clone())
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

        // Try to add the same factor again - should fail with FactorAlreadyExists
        let result = backup_storage
            .add_factor(&test_backup_id, google_account.clone())
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::FactorAlreadyExists) => {}
            _ => panic!("Expected FactorAlreadyExists"),
        }

        // Try to add a factor to a non-existent backup - should fail with BackupNotFound
        let result = backup_storage
            .add_factor("non_existent_backup", google_account.clone())
            .await;
        assert!(result.is_err());
        match result {
            Err(BackupManagerError::BackupNotFound) => {}
            _ => panic!("Expected BackupNotFound"),
        }
    }

    #[tokio::test]
    async fn test_add_sync_factor() {
        dotenvy::from_filename(".env.example").unwrap();
        let environment = Environment::development(None);
        let s3_client = Arc::new(S3Client::from_conf(environment.s3_client_config().await));
        let backup_storage = BackupStorage::new(environment.clone(), s3_client.clone());

        // Create a test backup
        let test_backup_id = Uuid::new_v4().to_string();
        let test_backup_data = vec![1, 2, 3, 4, 5];
        let initial_metadata = BackupMetadata {
            id: test_backup_id.clone(),
            factors: vec![],
            sync_factors: vec![],
            keys: vec![],
        };

        // Create a backup
        backup_storage
            .create(test_backup_data.clone(), &initial_metadata)
            .await
            .unwrap();

        // Create a keypair factor (valid for sync)
        let keypair_factor = Factor::new_ec_keypair("public-key".to_string());

        // Add the sync factor
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
        let oidc_factor = Factor::new_oidc_account(OidcAccountKind::Google {
            sub: "12345".to_string(),
            email: "test@example.com".to_string(),
        });
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
}
