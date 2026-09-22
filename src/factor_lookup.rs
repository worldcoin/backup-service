use crate::backup_metadata::BackupMetadata;
use crate::environment::Environment;
use aws_sdk_dynamodb::operation::get_item::GetItemError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::{error::SdkError, types::TableStatus};
use std::collections::BTreeSet;
use std::sync::Arc;
use types::FactorScope;

/// Redis lock prefix for coordinating `FactorLookup` insert/delete with metadata writes.
///
/// Writers hold this while Dynamo may be ahead of S3; auth stale-delete skips when locked.
pub const FACTOR_LOOKUP_MUTATE_LOCK_PREFIX: &str = "factor_lookup_mutate:";

/// Fallback TTL for [`FACTOR_LOOKUP_MUTATE_LOCK_PREFIX`] (should exceed a normal put + retries).
pub const FACTOR_LOOKUP_MUTATE_LOCK_TTL_SECS: u64 = 120;

/// Lock identifier for a factor primary key (scope is already encoded in the Dynamo/factor id).
#[must_use]
pub fn factor_lookup_mutate_lock_id(factor: &FactorToLookup) -> String {
    factor.primary_key()
}

/// Factor Lookup allows to store the mapping between factor key (e.g., credential ID for a passkey,
/// keypair public key, iss + sub for OIDC) and the backup ID.
///
/// It used during recovery to find the backup corresponding to the provided factor. When a user is restoring
/// their backup, they only have their factor. Hence a lookup to get the `backup_id` is needed.
///
/// To reiterate, the `FactorLookup` is used only to lookup the `backup_id` for a given factor. It cannot authorize access
/// to a backup. Only factors registered in the backup metadata are considered valid and allowed for authentication.
#[derive(Clone, Debug)]
pub struct FactorLookup {
    environment: Environment,
    dynamodb_client: Arc<aws_sdk_dynamodb::Client>,
}

pub struct FactorLookupDeletion {
    backup_id: String,
    records: Vec<(String, AttributeValue)>,
}

impl FactorLookup {
    pub fn new(environment: Environment, dynamodb_client: Arc<aws_sdk_dynamodb::Client>) -> Self {
        Self {
            environment,
            dynamodb_client,
        }
    }

    /// Inserts the factor into the `DynamoDB` table.
    ///
    /// It will fail if the factor already exists in the table.
    ///
    /// # Errors
    /// * `FactorLookupError::DynamoDbPutError` - if the factor cannot be inserted into the `DynamoDB` table,
    ///   or if the factor already exists in the table.
    pub async fn insert(
        &self,
        scope: FactorScope,
        factor: &FactorToLookup,
        backup_id: String,
    ) -> Result<(), FactorLookupError> {
        self.dynamodb_client
            .put_item()
            .table_name(self.environment.factor_lookup_dynamodb_table_name())
            .item(
                DocumentAttribute::Pk.to_string(),
                factor_primary_key(scope, factor),
            )
            .item(
                DocumentAttribute::BackupId.to_string(),
                aws_sdk_dynamodb::types::AttributeValue::S(backup_id.clone()),
            )
            .item(
                DocumentAttribute::CreatedAt.to_string(),
                aws_sdk_dynamodb::types::AttributeValue::N(
                    chrono::Utc::now().timestamp_millis().to_string(),
                ),
            )
            .condition_expression("attribute_not_exists(#pk)")
            .expression_attribute_names("#pk", DocumentAttribute::Pk.to_string())
            .send()
            .await?;

        tracing::info!(
            message = "Inserted factor into DynamoDB",
            scope = scope.to_string(),
            pk = factor.primary_key(),
            backup_id = backup_id,
        );

        Ok(())
    }

    /// Looks up the backup ID for the given factor (eventually consistent `GetItem`).
    ///
    /// # Errors
    /// * `FactorLookupError::DynamoDbGetError` - if the factor cannot be fetched from the `DynamoDB` table.
    /// * `FactorLookupError::ParseBackupIdError` - if the backup ID cannot be parsed from the `DynamoDB` item.
    pub async fn lookup(
        &self,
        scope: FactorScope,
        factor: &FactorToLookup,
    ) -> Result<Option<String>, FactorLookupError> {
        self.lookup_inner(scope, factor, false).await
    }

    /// Strongly consistent `GetItem` — use after write races where an eventually consistent read
    /// might miss a just-written mapping.
    ///
    /// # Errors
    /// Same as [`Self::lookup`].
    pub async fn lookup_consistent(
        &self,
        scope: FactorScope,
        factor: &FactorToLookup,
    ) -> Result<Option<String>, FactorLookupError> {
        self.lookup_inner(scope, factor, true).await
    }

    async fn lookup_inner(
        &self,
        scope: FactorScope,
        factor: &FactorToLookup,
        consistent_read: bool,
    ) -> Result<Option<String>, FactorLookupError> {
        let result = self
            .dynamodb_client
            .get_item()
            .table_name(self.environment.factor_lookup_dynamodb_table_name())
            .key(
                DocumentAttribute::Pk.to_string(),
                factor_primary_key(scope, factor),
            )
            .consistent_read(consistent_read)
            .send()
            .await?;

        let Some(result) = result.item() else {
            return Ok(None);
        };

        // Check if the item has the backup ID attribute
        let Some(backup_id) = result.get(&DocumentAttribute::BackupId.to_string()) else {
            return Err(FactorLookupError::ParseBackupIdError);
        };

        // Check if the backup ID is a string
        let Ok(backup_id) = backup_id.as_s() else {
            return Err(FactorLookupError::ParseBackupIdError);
        };

        // Return the backup ID as a string
        Ok(Some(backup_id.clone()))
    }

    /// Deletes a factor from the lookup table.
    ///
    /// # Errors
    /// * `FactorLookupError::DynamoDbDeleteError` - if the factor cannot be deleted from the `DynamoDB` table.
    pub async fn delete(
        &self,
        scope: FactorScope,
        factor: &FactorToLookup,
    ) -> Result<(), FactorLookupError> {
        self.dynamodb_client
            .delete_item()
            .table_name(self.environment.factor_lookup_dynamodb_table_name())
            .key(
                DocumentAttribute::Pk.to_string(),
                factor_primary_key(scope, factor),
            )
            .send()
            .await?;

        tracing::info!(
            message = "Deleted factor from DynamoDB",
            pk = factor.primary_key(),
        );

        Ok(())
    }

    async fn backup_factor_keys(
        &self,
        backup_id: &str,
    ) -> Result<BTreeSet<String>, FactorLookupError> {
        let mut keys = BTreeSet::new();
        let mut exclusive_start_key = None;
        loop {
            let query_result = self
                .dynamodb_client
                .query()
                .table_name(self.environment.factor_lookup_dynamodb_table_name())
                .index_name(self.environment.factor_lookup_dynamodb_gsi_name())
                .key_condition_expression("#backup_id = :backup_id")
                .expression_attribute_names("#backup_id", DocumentAttribute::BackupId.to_string())
                .expression_attribute_values(":backup_id", AttributeValue::S(backup_id.to_owned()))
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await?;

            for item in query_result.items() {
                let key = item
                    .get(&DocumentAttribute::Pk.to_string())
                    .and_then(|value| value.as_s().ok())
                    .ok_or(FactorLookupError::InvalidDeletionRecord)?;
                keys.insert(key.clone());
            }

            match query_result.last_evaluated_key() {
                Some(key) if !key.is_empty() => exclusive_start_key = Some(key.clone()),
                _ => break,
            }
        }

        Ok(keys)
    }

    /// Captures factor records before unpublishing a backup, including recently committed factors.
    ///
    /// # Errors
    /// Returns `DynamoDB` read errors or an error for malformed lookup records.
    pub async fn prepare_deletion(
        &self,
        metadata: &BackupMetadata,
    ) -> Result<FactorLookupDeletion, FactorLookupError> {
        let mut keys = self.backup_factor_keys(&metadata.id).await?;
        // The account index is eventually consistent, so committed membership supplies missing keys.
        for (scope, factors) in [
            (FactorScope::Main, &metadata.factors),
            (FactorScope::Sync, &metadata.sync_factors),
        ] {
            for factor in factors {
                keys.insert(format!(
                    "{scope}#{}",
                    factor.as_factor_to_lookup(&self.environment).primary_key()
                ));
            }
        }

        self.capture_records(&metadata.id, keys).await
    }

    /// Captures a single lookup record before removing its metadata membership.
    ///
    /// # Errors
    /// Returns `DynamoDB` read errors or an error for a malformed lookup record.
    pub async fn prepare_factor_deletion(
        &self,
        backup_id: &str,
        scope: FactorScope,
        factor: &FactorToLookup,
    ) -> Result<FactorLookupDeletion, FactorLookupError> {
        self.capture_records(
            backup_id,
            BTreeSet::from([format!("{scope}#{}", factor.primary_key())]),
        )
        .await
    }

    async fn capture_records(
        &self,
        backup_id: &str,
        keys: BTreeSet<String>,
    ) -> Result<FactorLookupDeletion, FactorLookupError> {
        let owner = AttributeValue::S(backup_id.to_owned());
        let mut records = Vec::new();
        for key in keys {
            let result = self
                .dynamodb_client
                .get_item()
                .table_name(self.environment.factor_lookup_dynamodb_table_name())
                .key(
                    DocumentAttribute::Pk.to_string(),
                    AttributeValue::S(key.clone()),
                )
                .consistent_read(true)
                .send()
                .await?;
            let Some(mut item) = result.item else {
                continue;
            };
            if item.get(&DocumentAttribute::BackupId.to_string()) != Some(&owner) {
                continue;
            }
            let created_at = item
                .remove(&DocumentAttribute::CreatedAt.to_string())
                .ok_or(FactorLookupError::InvalidDeletionRecord)?;
            records.push((key, created_at));
        }
        Ok(FactorLookupDeletion {
            backup_id: backup_id.to_owned(),
            records,
        })
    }

    /// Deletes captured records only if they have not been replaced or reassigned.
    ///
    /// # Errors
    /// Propagates any `DynamoDB` deletion failure other than a changed or missing record.
    pub async fn delete_captured(
        &self,
        deletion: FactorLookupDeletion,
    ) -> Result<(), FactorLookupError> {
        for (key, created_at) in deletion.records {
            let result = self
                .dynamodb_client
                .delete_item()
                .table_name(self.environment.factor_lookup_dynamodb_table_name())
                .key(DocumentAttribute::Pk.to_string(), AttributeValue::S(key))
                .condition_expression("#owner = :owner AND #created = :created")
                .expression_attribute_names("#owner", DocumentAttribute::BackupId.to_string())
                .expression_attribute_names("#created", DocumentAttribute::CreatedAt.to_string())
                .expression_attribute_values(
                    ":owner",
                    AttributeValue::S(deletion.backup_id.clone()),
                )
                .expression_attribute_values(":created", created_at)
                .send()
                .await;
            match result {
                Ok(_) => {}
                Err(SdkError::ServiceError(error))
                    if error.err().is_conditional_check_failed_exception() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        let result = self
            .dynamodb_client
            .describe_table()
            .table_name(self.environment.factor_lookup_dynamodb_table_name())
            .send()
            .await;

        if let Ok(result) = result {
            let table_active =
                result.table().and_then(|t| t.table_status()).cloned() == Some(TableStatus::Active);

            let gsi_name = self.environment.factor_lookup_dynamodb_gsi_name();
            let gsi_exists = result.table().is_some_and(|t| {
                t.global_secondary_indexes()
                    .iter()
                    .any(|gsi| gsi.index_name().is_some_and(|name| name == gsi_name))
            });

            if !(table_active && gsi_exists) {
                tracing::error!(
                    message =
                        "FactorLookup is not ready. Table is not active or GSI does not exist.",
                    table_active = table_active,
                    gsi_exists = gsi_exists,
                );
            }
            table_active && gsi_exists
        } else {
            tracing::error!(
                "System is not ready. FactorLookup (DescribeTable): {:?}",
                result.err()
            );
            false
        }
    }
}

fn factor_primary_key(
    scope: FactorScope,
    factor: &FactorToLookup,
) -> aws_sdk_dynamodb::types::AttributeValue {
    aws_sdk_dynamodb::types::AttributeValue::S(format!("{scope}#{}", factor.primary_key()))
}

#[derive(thiserror::Error, Debug)]
pub enum FactorLookupError {
    #[error("Failed to insert factor into DynamoDB: {0}")]
    DynamoDbPutError(#[from] SdkError<PutItemError>),
    #[error("Failed to fetch factor from DynamoDB: {0}")]
    DynamoDbGetError(#[from] SdkError<GetItemError>),
    #[error("Failed to delete factor from DynamoDB: {0}")]
    DynamoDbDeleteError(
        #[from] SdkError<aws_sdk_dynamodb::operation::delete_item::DeleteItemError>,
    ),
    #[error("Failed to query factors from DynamoDB: {0}")]
    DynamoDbQueryError(#[from] SdkError<aws_sdk_dynamodb::operation::query::QueryError>),
    #[error("Failed to parse backup ID from DynamoDB row")]
    ParseBackupIdError,
    #[error("Cannot safely delete a malformed factor lookup record")]
    InvalidDeletionRecord,
}

#[derive(Clone, Debug)]
pub enum FactorToLookup {
    Passkey { credential_id: String },
    OidcAccount { iss: String, sub: String },
    EcKeypair { public_key: String },
}

impl FactorToLookup {
    pub fn from_passkey(credential_id: String) -> Self {
        Self::Passkey { credential_id }
    }

    pub fn from_oidc_account(iss: String, sub: String) -> Self {
        Self::OidcAccount { iss, sub }
    }

    pub fn from_ec_keypair(public_key: String) -> Self {
        Self::EcKeypair { public_key }
    }

    /// Returns the primary key for the factor that we use for `DynamoDB`.
    pub fn primary_key(&self) -> String {
        // we use | as a separator as this character is not allowed in the issuer URL or other
        // identifiers
        match self {
            FactorToLookup::Passkey { credential_id } => format!("PK|{credential_id}"),
            FactorToLookup::OidcAccount { iss, sub } => format!("OIDC|{iss}|{sub}"),
            FactorToLookup::EcKeypair { public_key } => format!("EC_KEYPAIR|{public_key}"),
        }
    }
}

#[derive(Debug, Clone, strum_macros::Display, strum_macros::EnumString)]
pub enum DocumentAttribute {
    // Primary key for the factor
    #[strum(serialize = "PK")]
    Pk,
    // Backup ID that factor is associated with
    BackupId,
    // Creation timestamp for debugging
    CreatedAt,
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn captured_deletion_preserves_a_recreated_lookup() {
        let client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let lookup = FactorLookup::new(environment, client.clone());
        let id = uuid::Uuid::new_v4().to_string();
        let factor = FactorToLookup::from_passkey(uuid::Uuid::new_v4().to_string());
        lookup
            .insert(FactorScope::Main, &factor, id.clone())
            .await
            .unwrap();
        let deletion = lookup
            .prepare_factor_deletion(&id, FactorScope::Main, &factor)
            .await
            .unwrap();
        client
            .update_item()
            .table_name(environment.factor_lookup_dynamodb_table_name())
            .key("PK", factor_primary_key(FactorScope::Main, &factor))
            .update_expression("SET CreatedAt = CreatedAt + :one")
            .expression_attribute_values(":one", AttributeValue::N("1".into()))
            .send()
            .await
            .unwrap();
        lookup.delete_captured(deletion).await.unwrap();
        assert_eq!(
            lookup
                .lookup_consistent(FactorScope::Main, &factor)
                .await
                .unwrap(),
            Some(id.clone())
        );
        let deletion = lookup
            .prepare_factor_deletion(&id, FactorScope::Main, &factor)
            .await
            .unwrap();
        lookup.delete_captured(deletion).await.unwrap();
        assert!(lookup
            .lookup_consistent(FactorScope::Main, &factor)
            .await
            .unwrap()
            .is_none());
    }

    async fn get_test_dynamodb_client() -> Arc<aws_sdk_dynamodb::Client> {
        dotenvy::from_filename(".env.example").unwrap();
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let aws_config = aws_config
            .into_builder()
            .endpoint_url("http://localhost:4566")
            .build();
        Arc::new(aws_sdk_dynamodb::Client::new(&aws_config))
    }

    #[tokio::test]
    async fn test_factor_lookup() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let factor_lookup = FactorLookup::new(environment, dynamodb_client);

        let mock_factor_id = uuid::Uuid::new_v4().to_string();

        // Insert a factor
        let factor = FactorToLookup::from_passkey(mock_factor_id);
        let backup_id = "test_backup_id".to_string();
        factor_lookup
            .insert(FactorScope::Main, &factor, backup_id.clone())
            .await
            .unwrap();

        // Lookup the factor
        let result = factor_lookup
            .lookup(FactorScope::Main, &factor)
            .await
            .unwrap();
        assert_eq!(result, Some(backup_id));

        // Should not find the factor in sync scope
        let result = factor_lookup
            .lookup(FactorScope::Sync, &factor)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_factor_lookup_with_invalid_factor() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let factor_lookup = FactorLookup::new(environment, dynamodb_client);

        // Lookup a non-existent factor
        let factor = FactorToLookup::from_passkey("non_existent_credential_id".to_string());
        let result = factor_lookup
            .lookup(FactorScope::Main, &factor)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_factor_lookup_with_duplicate_insert() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let factor_lookup = FactorLookup::new(environment, dynamodb_client);

        let mock_factor_id = uuid::Uuid::new_v4().to_string();

        // Insert a factor
        let factor = FactorToLookup::from_passkey(mock_factor_id);
        let backup_id = "test_backup_id".to_string();
        factor_lookup
            .insert(FactorScope::Sync, &factor, backup_id.clone())
            .await
            .unwrap();

        // Attempt to insert the same factor again
        let result = factor_lookup
            .insert(FactorScope::Sync, &factor, "test_backup_id_2".to_string())
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to insert factor into DynamoDB: service error"
        );
    }

    #[tokio::test]
    async fn test_factor_delete() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let factor_lookup = FactorLookup::new(environment, dynamodb_client);

        let mock_factor_id = uuid::Uuid::new_v4().to_string();

        // Insert a factor
        let factor = FactorToLookup::from_passkey(mock_factor_id);
        let backup_id = "test_backup_id".to_string();
        factor_lookup
            .insert(FactorScope::Sync, &factor, backup_id.clone())
            .await
            .unwrap();

        // Verify the factor exists
        let result = factor_lookup
            .lookup(FactorScope::Sync, &factor)
            .await
            .unwrap();
        assert_eq!(result, Some(backup_id));

        // Delete the factor
        factor_lookup
            .delete(FactorScope::Sync, &factor)
            .await
            .unwrap();

        // Verify the factor no longer exists
        let result = factor_lookup
            .lookup(FactorScope::Sync, &factor)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_delete_all_by_backup_id() {
        let dynamodb_client = get_test_dynamodb_client().await;
        let environment = Environment::development(None);
        let factor_lookup = FactorLookup::new(environment, dynamodb_client);

        let backup_id = format!("test_backup_id_{}", uuid::Uuid::new_v4());

        // Insert multiple factors with the same backup_id
        let factor1 = FactorToLookup::from_passkey(uuid::Uuid::new_v4().to_string());
        let factor2 = FactorToLookup::from_passkey(uuid::Uuid::new_v4().to_string());
        let factor3 = FactorToLookup::from_ec_keypair(uuid::Uuid::new_v4().to_string());

        factor_lookup
            .insert(FactorScope::Main, &factor1, backup_id.clone())
            .await
            .unwrap();
        factor_lookup
            .insert(FactorScope::Sync, &factor2, backup_id.clone())
            .await
            .unwrap();
        factor_lookup
            .insert(FactorScope::Sync, &factor3, backup_id.clone())
            .await
            .unwrap();

        // Verify all factors exist
        assert_eq!(
            factor_lookup
                .lookup(FactorScope::Main, &factor1)
                .await
                .unwrap(),
            Some(backup_id.clone())
        );
        assert_eq!(
            factor_lookup
                .lookup(FactorScope::Sync, &factor2)
                .await
                .unwrap(),
            Some(backup_id.clone())
        );
        assert_eq!(
            factor_lookup
                .lookup(FactorScope::Sync, &factor3)
                .await
                .unwrap(),
            Some(backup_id.clone())
        );

        // Delete all factors for the backup_id
        let deletion = factor_lookup
            .prepare_deletion(&BackupMetadata {
                id: backup_id,
                factors: vec![],
                sync_factors: vec![],
                keys: vec![],
                manifest_hash: String::new(),
                archive_id: None,
                encryption_public_key: None,
            })
            .await
            .unwrap();
        factor_lookup.delete_captured(deletion).await.unwrap();

        // Verify all factors no longer exist
        assert_eq!(
            factor_lookup
                .lookup(FactorScope::Main, &factor1)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            factor_lookup
                .lookup(FactorScope::Sync, &factor2)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            factor_lookup
                .lookup(FactorScope::Sync, &factor3)
                .await
                .unwrap(),
            None
        );
    }
}
