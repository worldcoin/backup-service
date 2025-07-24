use crate::types::Environment;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::get_item::GetItemError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{str::FromStr, sync::Arc};
use strum_macros::{Display, EnumString};

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

/// Some factors are used as main factors for recovery, while others are used for just syncing.
/// This enum is used to distinguish between the two types of factors and only query the specific
/// type of factor.
#[derive(Debug, Clone, Copy, Display, EnumString, PartialEq, Eq, JsonSchema)]
#[strum(serialize_all = "UPPERCASE")]
pub enum FactorScope {
    /// Main factors (e.g. passkeys, iCloud Keychain, OIDC accounts) can be used to recover the backup
    /// or add new factors.
    Main,
    /// Sync factors (e.g. EC keypairs stored on enclaves) are used to update the backup with
    /// new data, view metadata and delete factors. Sync factors cannot be used to recover the backup
    /// or add new factors.
    Sync,
}

// Serde serialization implementation for `FactorScope` (to use strum serialization)
impl Serialize for FactorScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FactorScope {
    fn deserialize<D>(deserializer: D) -> Result<FactorScope, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FactorScope::from_str(&s).map_err(<D::Error as serde::de::Error>::custom)
    }
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

    /// Looks up the backup ID for the given factor.
    ///
    /// # Errors
    /// * `FactorLookupError::DynamoDbGetError` - if the factor cannot be fetched from the `DynamoDB` table.
    /// * `FactorLookupError::ParseBackupIdError` - if the backup ID cannot be parsed from the `DynamoDB` item.
    pub async fn lookup(
        &self,
        scope: FactorScope,
        factor: &FactorToLookup,
    ) -> Result<Option<String>, FactorLookupError> {
        let result = self
            .dynamodb_client
            .get_item()
            .table_name(self.environment.factor_lookup_dynamodb_table_name())
            .key(
                DocumentAttribute::Pk.to_string(),
                factor_primary_key(scope, factor),
            )
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
        Ok(Some(backup_id.to_string()))
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

    pub async fn is_ready(&self) -> bool {
        let result = self
            .dynamodb_client
            .describe_table()
            .table_name(self.environment.factor_lookup_dynamodb_table_name())
            .send()
            .await;

        if let Ok(result) = result {
            result.table().is_some()
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
    #[error("Failed to parse backup ID from DynamoDB row")]
    ParseBackupIdError,
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
}
