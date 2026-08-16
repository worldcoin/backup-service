//! The error body returned on every non-2xx response, and the codes it can carry.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use strum_macros::{EnumIter, EnumString, IntoStaticStr};

/// The body returned by the service for every non-2xx response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    /// Whether retrying the exact same request could succeed. Always `false` today; clients
    /// should treat a missing or `false` value as "do not retry".
    #[serde(default)]
    pub allow_retry: bool
    /// The error itself.
    pub error: ErrorObject,
}

/// The `error` object nested in [`ErrorBody`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ErrorObject {
    /// Machine-readable code. Clients branch on this.
    pub code: ErrorCode,
    /// Human-readable message. Intended for logs and debugging, not for display to users, and
    /// not stable across releases.
    pub message: String,
}

/// Every error code the service can return.
///
/// Codes are stable: renaming one is a breaking API change. Unrecognized codes deserialize into
/// [`ErrorCode::Unknown`] rather than failing, so a client built against an older release keeps
/// working when the service adds a code.
#[derive(Debug, Clone, PartialEq, Eq, EnumString, IntoStaticStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    // SECTION: Generic
    /// An unexpected server-side failure. Not actionable by the client.
    InternalServerError,
    /// The requested resource does not exist.
    NotFound,
    /// The request was not authorized.
    Unauthorized,
    /// Another request holds a lock on the same resource. Safe to retry after a short delay.
    ConflictingLock,
    /// The request body exceeded the maximum allowed size.
    ContentTooLarge,
    /// The multipart form data could not be read.
    MultipartError,
    /// The request payload could not be deserialized.
    InvalidPayload,
    /// The multipart request is missing its `payload` field.
    MissingPayloadField,
    /// The multipart request is missing its `backup` field.
    MissingBackupField,
    /// The uploaded backup file is empty.
    EmptyBackupFile,
    /// The requested operation is not supported for this factor or backup.
    NotSupported,

    // SECTION: Challenges and tokens
    /// The challenge token is malformed, expired, or could not be decrypted.
    JwtError,
    /// The challenge token was issued for a different challenge type.
    UnexpectedChallengeType,
    /// The token does not exist.
    TokenNotFound,
    /// The token has expired.
    TokenExpired,
    /// The token has already been used. Challenge tokens are single-use.
    AlreadyUsed,
    /// The solved challenge does not match the one that was issued.
    InvalidChallenge,
    /// The challenge token was issued for a different operation than the one being performed.
    InvalidChallengeContext,

    // SECTION: Backups and factors
    /// A backup ID was resolved from the factor, but the backup is missing from storage.
    BackupMissing,
    /// No backup could be resolved from the provided factor.
    BackupUntraceable,
    /// The explicitly provided backup ID does not exist.
    BackupDoesNotExist,
    /// The explicitly provided backup ID does not match the one resolved from the factor.
    BackupIdMismatch,
    /// The backup was not found.
    BackupNotFound,
    /// The factor was not found on this backup.
    FactorNotFound,
    /// The factor is already registered on a backup.
    FactorAlreadyExists,
    /// The backup already has the maximum number of factors.
    TooManyFactors,
    /// The factor exists but is no longer authorized for the backup.
    UnauthorizedFactor,
    /// The authorization kind is not accepted by this endpoint.
    InvalidAuthorizationType,
    /// The sync factor is not of an accepted kind.
    InvalidSyncFactorType,
    /// Sync factors must be EC keypairs.
    SyncFactorMustBeKeypair,
    /// An OIDC factor was submitted without its Turnkey provider ID.
    MissingTurnkeyProviderId,
    /// The OIDC token does not carry an email claim.
    MissingEmail,
    /// The new factor kind is not accepted by this endpoint.
    InvalidNewFactorType,
    /// The new factor's authorization kind does not match the requested new factor kind.
    InvalidNewFactorAuthorizationType,

    // SECTION: Encryption keys
    /// The encryption key was not found on the backup.
    EncryptionKeyNotFound,
    /// An encryption key may not be removed by this request.
    EncryptionKeyNotAllowed,
    /// Removing the encryption key would leave an existing factor unable to decrypt the backup.
    FactorOrphanedFromEncryptionKey,
    /// The backup already holds an encryption key of this kind.
    OnlyOneEncryptionKeyPerTypeAllowed,

    // SECTION: Backup lifecycle
    /// The submitted manifest hash does not match the stored one; the client is not operating on
    /// the latest state of the backup.
    ManifestHashMismatch,
    /// A backup already exists for this backup account ID.
    BackupAccountIdAlreadyExists,
    /// The backup account ID is malformed.
    InvalidBackupAccountId,
    /// The signature is malformed.
    InvalidSignature,
    /// The signature did not verify against the challenge.
    SignatureVerificationError,

    // SECTION: Passkeys
    /// A `WebAuthn` operation failed.
    WebauthnError,
    /// The `WebAuthn` payload is malformed.
    WebauthnInvalidPayload,
    /// PRF results were supplied where they are not permitted.
    WebauthnPrfResultsNotAllowed,

    // SECTION: OIDC
    /// The OIDC token could not be parsed, or is missing a required claim.
    OidcTokenParseError,
    /// The OIDC token failed verification against the provider's keys.
    OidcTokenVerificationError,
    /// The OIDC token nonce does not commit to the submitted public key.
    OidcTokenInvalidNonce,
    /// The OIDC token audience is not in the allowlist.
    OidcTokenInvalidAud,
    /// The OIDC token does not match the one the challenge was issued for.
    OidcTokenMismatch,

    // SECTION: Turnkey
    /// The Turnkey activity could not be verified.
    TurnkeyActivityError,
    /// The request requires a Turnkey activity but none was supplied.
    MissingTurnkeyActivity,
    /// The Turnkey activity is malformed or of an unexpected type.
    InvalidTurnkeyActivity,

    // SECTION: Attestation gateway
    /// The attestation token is invalid.
    InvalidAttestationToken,
    /// A claim in the attestation token is invalid.
    InvalidAttestationTokenClaim,
    /// The attestation token header is missing or malformed.
    InvalidAttestationTokenHeader,

    /// A code this build does not know about. Only produced when deserializing a response from a
    /// newer service; never produced by the service itself.
    #[strum(default)]
    Unknown(String),
}

impl ErrorCode {
    /// The code exactly as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unknown(code) => code,
            known => known.into(),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        // `FromStr` cannot fail: unknown codes fall through to `Unknown`.
        Ok(Self::from_str(&raw).unwrap_or(Self::Unknown(raw)))
    }
}

#[cfg(feature = "openapi")]
impl schemars::JsonSchema for ErrorCode {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "String".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}
