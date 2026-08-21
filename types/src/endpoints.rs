//! Every endpoint the service exposes, with the request and response body that belongs to it.
//!
//! Each request type implements [`Endpoint`], which binds it to its path, its HTTP method and the
//! response it produces.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{Authorization, BackupEncryptionKey, ExportedBackupMetadata, FactorScope};

/// Header carrying the attestation gateway token, required by attestation-gated endpoints.
pub const ATTESTATION_TOKEN_HEADER: &str = "attestation-token";

/// Header carrying the client's application version. Optional, used for telemetry (e.g.
/// detecting a bug in specific client versions)
pub const CLIENT_VERSION_HEADER: &str = "client-version";

/// Multipart field holding the JSON request body on [`BodyKind::Multipart`] endpoints.
pub const MULTIPART_PAYLOAD_FIELD: &str = "payload";

/// Multipart field holding the sealed backup bytes on [`BodyKind::Multipart`] endpoints.
pub const MULTIPART_BACKUP_FIELD: &str = "backup";

/// Path of the liveness probe.
pub const HEALTH_PATH: &str = "/health";

/// Path of the readiness probe.
pub const READY_PATH: &str = "/ready";

/// Path of the passkey challenge used to start a recovery.
///
/// Takes no request body and answers with [`RetrieveChallengePasskeyResponse`], so it has no
/// [`Endpoint`] impl.
pub const RETRIEVE_CHALLENGE_PASSKEY_PATH: &str = "/v1/retrieve/challenge/passkey";

/// Path of the passkey challenge used to verify a main factor.
///
/// Takes no request body and answers with [`VerifyFactorChallengePasskeyResponse`], so it has no
/// [`Endpoint`] impl.
pub const VERIFY_FACTOR_CHALLENGE_PASSKEY_PATH: &str = "/v1/verify-factor/challenge/passkey";

/// HTTP method of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
}

/// How an endpoint's request body is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// No request body.
    Empty,
    /// A JSON body.
    Json,
    /// A multipart body: the JSON request in [`MULTIPART_PAYLOAD_FIELD`], the sealed backup
    /// bytes in [`MULTIPART_BACKUP_FIELD`].
    Multipart,
}

/// Binds a request body to the endpoint that accepts it.
pub trait Endpoint: Serialize {
    /// The response body on success. `()` for endpoints that return `204 No Content`.
    type Response: DeserializeOwned;

    /// Path, including the API version prefix.
    const PATH: &'static str;

    /// HTTP method.
    const METHOD: Method = Method::Post;

    /// Whether the request must carry an [`ATTESTATION_TOKEN_HEADER`].
    const REQUIRES_ATTESTATION: bool = false;

    /// How the request body is encoded.
    const BODY: BodyKind = BodyKind::Json;
}

/// The routing facts of one endpoint, in a form that can be iterated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointInfo {
    /// Path, including the API version prefix.
    pub path: &'static str,
    /// HTTP method.
    pub method: Method,
    /// Whether the request must carry an [`ATTESTATION_TOKEN_HEADER`].
    pub requires_attestation: bool,
    /// How the request body is encoded.
    pub body: BodyKind,
}

impl EndpointInfo {
    /// The routing facts of `E`.
    #[must_use]
    pub const fn of<E: Endpoint>() -> Self {
        Self {
            path: E::PATH,
            method: E::METHOD,
            requires_attestation: E::REQUIRES_ATTESTATION,
            body: E::BODY,
        }
    }

    const fn probe(path: &'static str) -> Self {
        Self {
            path,
            method: Method::Get,
            requires_attestation: false,
            body: BodyKind::Empty,
        }
    }

    const fn passkey_challenge(path: &'static str) -> Self {
        Self {
            path,
            method: Method::Post,
            requires_attestation: false,
            body: BodyKind::Empty,
        }
    }
}

/// Every endpoint the service exposes.
pub const ALL_ENDPOINTS: &[EndpointInfo] = &[
    EndpointInfo::probe(HEALTH_PATH),
    EndpointInfo::probe(READY_PATH),
    EndpointInfo::of::<BackupStatusRequest>(),
    EndpointInfo::of::<CreateChallengePasskeyRequest>(),
    EndpointInfo::of::<CreateChallengeKeypairRequest>(),
    EndpointInfo::of::<CreateBackupRequest>(),
    EndpointInfo::passkey_challenge(RETRIEVE_CHALLENGE_PASSKEY_PATH),
    EndpointInfo::of::<RetrieveChallengeKeypairRequest>(),
    EndpointInfo::of::<RetrieveBackupFromChallengeRequest>(),
    EndpointInfo::passkey_challenge(VERIFY_FACTOR_CHALLENGE_PASSKEY_PATH),
    EndpointInfo::of::<VerifyFactorChallengeKeypairRequest>(),
    EndpointInfo::of::<VerifyFactorRequest>(),
    EndpointInfo::of::<AddSyncFactorChallengeKeypairRequest>(),
    EndpointInfo::of::<AddSyncFactorRequest>(),
    EndpointInfo::of::<AddFactorChallengeRequest>(),
    EndpointInfo::of::<AddFactorRequest>(),
    EndpointInfo::of::<SyncChallengeKeypairRequest>(),
    EndpointInfo::of::<SyncBackupRequest>(),
    EndpointInfo::of::<RetrieveMetadataChallengeKeypairRequest>(),
    EndpointInfo::of::<RetrieveMetadataRequest>(),
    EndpointInfo::of::<DeleteFactorChallengeKeypairRequest>(),
    EndpointInfo::of::<DeleteFactorRequest>(),
    EndpointInfo::of::<DeleteBackupChallengeKeypairRequest>(),
    EndpointInfo::of::<DeleteBackupRequest>(),
    EndpointInfo::of::<ResetChallengeKeypairRequest>(),
    EndpointInfo::of::<ResetRequest>(),
];

// SECTION: Shared challenge response

/// Response of every `.../challenge/keypair` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ChallengeKeypairResponse {
    /// Base64-encoded 32 random bytes to sign with the keypair.
    pub challenge: String,
    /// Opaque token echoed back on the follow-up request. Single use.
    pub token: String,
}

// SECTION: Backup status

/// Request body of `POST /v1/backup/status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct BackupStatusRequest {
    /// The ID of the backup.
    pub backup_id: String,
}

impl Endpoint for BackupStatusRequest {
    type Response = BackupStatusResponse;
    const PATH: &'static str = "/v1/backup/status";
}

/// Response body of `POST /v1/backup/status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct BackupStatusResponse {
    /// The ID of the backup.
    pub backup_id: String,
    /// The factors associated with the backup.
    pub factors: Vec<ExportedFactorSlim>,
}

/// A factor as reported by `POST /v1/backup/status`, without any identifying detail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ExportedFactorSlim {
    /// The kind of factor: `"PASSKEY"`, `"EC_KEYPAIR"` or `"OIDC_ACCOUNT"`.
    pub kind: String,
    /// The provider, when the factor is an OIDC account: `"GOOGLE"` or `"APPLE"`.
    pub account_kind: Option<String>,
}

// SECTION: Create backup

/// Request body of `POST /v1/create/challenge/passkey`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateChallengePasskeyRequest {
    /// The `WebAuthn` user name.
    pub name: String,
    /// The `WebAuthn` user display name.
    pub display_name: String,
    /// The platform of the device registering the passkey.
    pub platform: Platform,
}

impl Endpoint for CreateChallengePasskeyRequest {
    type Response = CreateChallengePasskeyResponse;
    const PATH: &'static str = "/v1/create/challenge/passkey";
}

/// The mobile platform registering a passkey. Determines which `WebAuthn` registration flow the
/// service starts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Platform {
    /// Android, which registers into Google Password Manager only.
    Android,
    /// iOS.
    Ios,
}

/// Response body of `POST /v1/create/challenge/passkey`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateChallengePasskeyResponse {
    /// The `WebAuthn` creation options, opaque to this service and passed to the platform
    /// authenticator as-is.
    pub challenge: serde_json::Value,
    /// Opaque token echoed back on the follow-up request. Single use.
    pub token: String,
    /// Base64-encoded 32 random bytes to sign with the Backup Account Key, proving ownership of
    /// the `backup_account_id` claimed on `POST /v1/create`.
    pub backup_account_challenge: String,
    /// Opaque token accompanying `backup_account_challenge`. Single use.
    pub backup_account_challenge_token: String,
}

/// Request body of `POST /v1/create/challenge/keypair`.
///
/// The challenge is signed by the keypair that will become the first sync factor of a new
/// backup.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateChallengeKeypairRequest {}

impl Endpoint for CreateChallengeKeypairRequest {
    type Response = CreateChallengeKeypairResponse;
    const PATH: &'static str = "/v1/create/challenge/keypair";
}

/// Response body of `POST /v1/create/challenge/keypair`.
///
/// Unlike the other `.../challenge/keypair` endpoints, this one also mints the Backup Account
/// challenge, so that creating a backup does not need an extra round trip to prove ownership of
/// the `backup_account_id`. Callers fetching a challenge for the initial sync factor ignore it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateChallengeKeypairResponse {
    /// Base64-encoded 32 random bytes to sign with the keypair.
    pub challenge: String,
    /// Opaque token echoed back on the follow-up request. Single use.
    pub token: String,
    /// Base64-encoded 32 random bytes to sign with the Backup Account Key, proving ownership of
    /// the `backup_account_id` claimed on `POST /v1/create`.
    pub backup_account_challenge: String,
    /// Opaque token accompanying `backup_account_challenge`. Single use.
    pub backup_account_challenge_token: String,
}

/// The JSON payload of `POST /v1/create`, sent in the multipart `payload` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupRequest {
    /// Main factor that will be used to manage the backup.
    pub authorization: Authorization,
    /// Token from the challenge the `authorization` solves.
    pub challenge_token: String,
    /// The first encrypted copy of the backup encryption key.
    pub initial_encryption_key: BackupEncryptionKey,
    /// First sync factor registered for this backup.
    pub initial_sync_factor: Authorization,
    /// Token from the challenge the `initial_sync_factor` solves.
    pub initial_sync_challenge_token: String,
    /// Provider ID from Turnkey. Only applicable if `initial_sync_factor` is
    /// [`Authorization::OidcAccount`].
    ///
    /// To avoid confusion, this is NOT the Turnkey account ID, it is specifically the provider ID.
    /// <https://docs.turnkey.com/api-reference/activities/create-oauth-providers>.
    pub turnkey_provider_id: Option<String>,
    /// The initial manifest hash of the backup, hex-encoded (32 bytes).
    #[serde(deserialize_with = "crate::normalize_hex_32")]
    pub manifest_hash: String,
    /// The unique identifier for the backup account, derived deterministically by the client.
    ///
    /// This is the Backup Account public key. Ownership is proven with
    /// `backup_account_challenge_token` and `backup_account_signature`.
    #[serde(deserialize_with = "crate::validate_backup_account_id")]
    pub backup_account_id: String,
    /// Token from the Backup Account challenge issued alongside the factor challenge.
    pub backup_account_challenge_token: Option<String>,
    /// Base64-encoded DER `secp256k1` signature over the Backup Account challenge, made with the
    /// secret key of `backup_account_id`.
    pub backup_account_signature: Option<String>,
}

impl Endpoint for CreateBackupRequest {
    type Response = CreateBackupResponse;
    const PATH: &'static str = "/v1/create";
    const BODY: BodyKind = BodyKind::Multipart;
}

/// Response body of `POST /v1/create`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupResponse {
    /// DEPRECATED. Use `backup_metadata.id` instead.
    pub backup_id: String,
    /// The metadata of the newly created backup.
    pub backup_metadata: ExportedBackupMetadata,
}

// SECTION: Recovery

/// Response body of `POST /v1/retrieve/challenge/passkey`. The endpoint takes no request body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetrieveChallengePasskeyResponse {
    /// The `WebAuthn` request options, opaque to this service and passed to the platform
    /// authenticator as-is.
    pub challenge: serde_json::Value,
    /// Opaque token echoed back on the follow-up request. Single use.
    pub token: String,
}

/// Request body of `POST /v1/retrieve/challenge/keypair`.
///
/// Starts the recovery process for a backup. The challenge is signed by a main factor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetrieveChallengeKeypairRequest {}

impl Endpoint for RetrieveChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/retrieve/challenge/keypair";
}

/// Request body of `POST /v1/retrieve/from-challenge`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeRequest {
    /// Authorization from a main factor.
    pub authorization: Authorization,
    /// Token from the challenge the `authorization` solves.
    pub challenge_token: String,
}

impl Endpoint for RetrieveBackupFromChallengeRequest {
    type Response = RetrieveBackupFromChallengeResponse;
    const PATH: &'static str = "/v1/retrieve/from-challenge";
    const REQUIRES_ATTESTATION: bool = true;
}

/// Response body of `POST /v1/retrieve/from-challenge`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetrieveBackupFromChallengeResponse {
    /// The sealed backup, base64-encoded.
    pub backup: String,
    /// Metadata about the backup, including the encryption keys.
    pub metadata: ExportedBackupMetadata,
    /// Single-use token for registering a sync factor on this backup afterwards.
    pub sync_factor_token: String,
}

// SECTION: Verify factor

/// Response body of `POST /v1/verify-factor/challenge/passkey`. The endpoint takes no request
/// body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorChallengePasskeyResponse {
    /// The `WebAuthn` request options, opaque to this service and passed to the platform
    /// authenticator as-is.
    pub challenge: serde_json::Value,
    /// Opaque token echoed back on the follow-up request. Single use.
    pub token: String,
}

/// Request body of `POST /v1/verify-factor/challenge/keypair`.
///
/// The challenge is signed by a main factor, to prove the user still controls it without
/// retrieving the backup.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorChallengeKeypairRequest {}

impl Endpoint for VerifyFactorChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/verify-factor/challenge/keypair";
}

/// Request body of `POST /v1/verify-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorRequest {
    /// Authorization from a main factor.
    pub authorization: Authorization,
    /// Token from the challenge the `authorization` solves.
    pub challenge_token: String,
}

impl Endpoint for VerifyFactorRequest {
    type Response = VerifyFactorResponse;
    const PATH: &'static str = "/v1/verify-factor";
    const REQUIRES_ATTESTATION: bool = true;
}

/// Response body of `POST /v1/verify-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorResponse {
    /// The backup the verified factor belongs to.
    pub backup_id: String,
}

// SECTION: Add sync factor

/// Request body of `POST /v1/add-sync-factor/challenge/keypair`.
///
/// Used to add a new sync factor after recovery. The challenge is signed by the EC keypair being
/// added, proving the client holds its private key.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddSyncFactorChallengeKeypairRequest {}

impl Endpoint for AddSyncFactorChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/add-sync-factor/challenge/keypair";
}

/// Request body of `POST /v1/add-sync-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddSyncFactorRequest {
    /// Token from the challenge the `sync_factor` solves.
    pub challenge_token: String,
    /// New sync factor to add. Must be an EC keypair.
    pub sync_factor: Authorization,
    /// The `sync_factor_token` from [`RetrieveBackupFromChallengeResponse`], which authorizes the
    /// request against a specific backup.
    pub sync_factor_token: String,
}

impl Endpoint for AddSyncFactorRequest {
    type Response = AddSyncFactorResponse;
    const PATH: &'static str = "/v1/add-sync-factor";
}

/// Response body of `POST /v1/add-sync-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddSyncFactorResponse {
    /// The ID of the backup that was modified.
    pub backup_id: String,
}

// SECTION: Add factor

/// The factor being added, as declared when requesting the challenge pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NewFactor {
    /// An OIDC account.
    #[serde(rename_all = "camelCase")]
    OidcAccount {
        /// The raw OIDC token of the account being added.
        oidc_token: String,
    },
    /// A new passkey being registered.
    #[serde(rename_all = "camelCase")]
    PasskeyRegistration {
        /// The platform requesting the passkey registration ceremony.
        platform: Platform,
    },
}

/// The kind of the existing factor that will sign over the new factor being added.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExistingFactorKind {
    /// A passkey.
    Passkey,
    /// An OIDC account.
    OidcAccount,
}

/// Request body of `POST /v1/add-factor/challenge`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeRequest {
    /// The factor the client intends to add. Bound into the challenge issued for the existing
    /// factor, so the existing factor signs over the new one.
    pub new_factor: NewFactor,
    /// The kind of the existing factor that will sign the challenge. Optional; defaults to
    /// `PASSKEY` to preserve existing clients that predate non-passkey existing factors.
    #[serde(default)]
    pub existing_factor_kind: Option<ExistingFactorKind>,
}

impl Endpoint for AddFactorChallengeRequest {
    type Response = AddFactorChallengeResponse;
    const PATH: &'static str = "/v1/add-factor/challenge";
}

/// Challenge to be solved by the new factor: a base64-encoded string for a keypair/OIDC factor,
/// or `WebAuthn` registration options for a passkey factor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum NewFactorChallenge {
    /// Base64-encoded raw challenge bytes, for a keypair/OIDC new factor.
    Keypair(String),
    /// `WebAuthn` registration ("create credential") options, for a passkey new factor.
    PasskeyRegistration(Box<PasskeyCreationChallenge>),
}

/// Mirrors `webauthn-rs`'s `CreationChallengeResponse`: the value passed as the `publicKey`
/// argument to `navigator.credentials.create()`. Defined locally because `webauthn-rs-proto`
/// does not derive `JsonSchema`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreationChallenge {
    /// The registration options.
    pub public_key: PublicKeyCredentialCreationOptions,
}

/// The `publicKey` options object of a `WebAuthn` credential-creation request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    /// The relying party.
    pub rp: RelyingParty,
    /// The user account being registered.
    pub user: UserEntity,
    /// Base64url-encoded registration challenge.
    pub challenge: String,
    /// Acceptable public key algorithms, in preference order.
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// How long, in milliseconds, the client should wait for the ceremony.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// Credentials that must not be allowed to fulfil this registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<serde_json::Value>>,
    /// Constraints on the authenticator that may fulfil this registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// UI hints for the client about the expected authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<String>>,
    /// Whether an attestation statement is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    /// `WebAuthn` extension inputs. Left untyped: extensions are open-ended and vary by client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Identifies the relying party (the service) in a registration request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct RelyingParty {
    /// Human-readable relying party name.
    pub name: String,
    /// Relying party ID (typically the domain).
    pub id: String,
}

/// Identifies the user account being registered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserEntity {
    /// Base64url-encoded user handle.
    pub id: String,
    /// Account name.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
}

/// One acceptable public key algorithm for the new credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct PubKeyCredParam {
    /// Always `"public-key"` per the `WebAuthn` spec.
    #[serde(rename = "type")]
    pub kind: String,
    /// COSE algorithm identifier (e.g. -7 for ES256).
    pub alg: i64,
}

/// Constraints on which authenticator may fulfil a registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    /// Restricts to a platform or cross-platform authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    /// Whether the resulting credential must be resident/discoverable: `"required"`,
    /// `"preferred"` or `"discouraged"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    /// Legacy boolean form of `resident_key`, kept for older clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    /// Whether user verification is required, preferred or discouraged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

/// Response body of `POST /v1/add-factor/challenge`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddFactorChallengeResponse {
    /// Challenge to be solved by the existing factor.
    pub existing_factor_challenge: String,
    /// Token for the existing factor's challenge.
    pub existing_factor_token: String,
    /// Challenge to be solved by the new factor.
    pub new_factor_challenge: NewFactorChallenge,
    /// Token for the new factor's challenge.
    pub new_factor_token: String,
}

/// Request body of `POST /v1/add-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddFactorRequest {
    /// Authorization for the existing factor.
    pub existing_factor_authorization: Authorization,
    /// Token from the challenge the existing factor solves.
    pub existing_factor_challenge_token: String,
    /// Activity used by Turnkey to create a session using the existing factor. It must also
    /// include the backup service challenge as one of its fields.
    pub existing_factor_turnkey_activity: Option<String>,
    /// Authorization for the new factor.
    pub new_factor_authorization: Authorization,
    /// Token from the challenge the new factor solves.
    pub new_factor_challenge_token: String,
    /// Optional encrypted copy of the backup encryption key, for the new factor.
    pub encrypted_backup_key: Option<BackupEncryptionKey>,
    /// Provider ID from Turnkey. Only applicable if `new_factor_authorization` is
    /// [`Authorization::OidcAccount`].
    pub turnkey_provider_id: Option<String>,
}

impl Endpoint for AddFactorRequest {
    type Response = AddFactorResponse;
    const PATH: &'static str = "/v1/add-factor";
}

/// Response body of `POST /v1/add-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddFactorResponse {
    /// The ID of the factor that was added.
    pub factor_id: String,
    /// The metadata of the backup after the factor was added.
    pub backup_metadata: ExportedBackupMetadata,
}

// SECTION: Sync

/// Request body of `POST /v1/sync/challenge/keypair`.
///
/// Used to update the sealed backup content while leaving the metadata alone. The challenge is
/// signed by a keypair registered as a sync factor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct SyncChallengeKeypairRequest {}

impl Endpoint for SyncChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/sync/challenge/keypair";
}

/// The JSON payload of `POST /v1/sync`, sent in the multipart `payload` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupRequest {
    /// Authorization from a sync factor.
    pub authorization: Authorization,
    /// Token from the challenge the `authorization` solves.
    pub challenge_token: String,
    /// The hex-encoded manifest hash of the backup as the client last saw it.
    ///
    /// A sync declares that it updates the backup from this state, which ensures updates are
    /// always applied to the latest state. In particular this prevents accidental data loss where
    /// a client drops a file from the backup without knowing it should have been included. A
    /// client that is not on the latest state must fetch the current backup and update from there.
    ///
    /// More details on <https://github.com/toolsforhumanity/docs/tree/main/world-app/backup>.
    #[serde(deserialize_with = "crate::normalize_hex_32")]
    pub current_manifest_hash: String,
    /// The hex-encoded manifest hash of the backup after this update.
    #[serde(deserialize_with = "crate::normalize_hex_32")]
    pub new_manifest_hash: String,
}

impl Endpoint for SyncBackupRequest {
    type Response = SyncBackupResponse;
    const PATH: &'static str = "/v1/sync";
    const BODY: BodyKind = BodyKind::Multipart;
}

/// Response body of `POST /v1/sync`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupResponse {
    /// The ID of the backup that was updated.
    pub backup_id: String,
}

// SECTION: Retrieve metadata

/// Request body of `POST /v1/retrieve-metadata/challenge/keypair`.
///
/// Used to view the backup metadata. The challenge is signed by a keypair registered as a sync
/// factor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataChallengeKeypairRequest {}

impl Endpoint for RetrieveMetadataChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/retrieve-metadata/challenge/keypair";
}

/// Request body of `POST /v1/retrieve-metadata`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetrieveMetadataRequest {
    /// Authorization from a sync factor.
    pub authorization: Authorization,
    /// Token from the challenge the `authorization` solves.
    pub challenge_token: String,
    /// Optional. When provided, the service verifies it matches the backup resolved from the
    /// factor.
    ///
    /// It also returns a specific error if the backup no longer exists, which lets multi-device
    /// setups tell "this device was revoked" apart from "the backup is gone".
    pub backup_id: Option<String>,
}

impl Endpoint for RetrieveMetadataRequest {
    type Response = ExportedBackupMetadata;
    const PATH: &'static str = "/v1/retrieve-metadata";
}

// SECTION: Delete factor

/// Request body of `POST /v1/delete-factor/challenge/keypair`.
///
/// The challenge is signed by a keypair registered as a sync factor, and is bound to the factor
/// being deleted so a token issued for one factor cannot delete another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorChallengeKeypairRequest {
    /// The factor the follow-up request will delete. Bound into the challenge.
    pub factor_id: String,
}

impl Endpoint for DeleteFactorChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/delete-factor/challenge/keypair";
}

/// Request body of `POST /v1/delete-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorRequest {
    /// Authorization from a sync factor.
    pub authorization: Authorization,
    /// Token from the challenge issued for `factor_id`.
    pub challenge_token: String,
    /// The ID of the factor to delete.
    pub factor_id: String,
    /// Encryption key to drop from the metadata as part of this request. Only allowed when
    /// deleting a main factor.
    pub encryption_key: Option<BackupEncryptionKey>,
    /// The scope of the factor to delete.
    pub scope: FactorScope,
}

impl Endpoint for DeleteFactorRequest {
    type Response = DeleteFactorResponse;
    const PATH: &'static str = "/v1/delete-factor";
    const REQUIRES_ATTESTATION: bool = true;
}

/// Response body of `POST /v1/delete-factor`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorResponse {
    /// Whether removing the factor deleted the entire backup, which happens when it was the last
    /// main factor.
    pub backup_deleted: bool,
    /// The metadata after the deletion. Absent when the backup itself was deleted.
    pub backup_metadata: Option<ExportedBackupMetadata>,
}

// SECTION: Delete backup

/// Request body of `POST /v1/delete-backup/challenge/keypair`.
///
/// The challenge is signed by a keypair registered as a sync factor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteBackupChallengeKeypairRequest {}

impl Endpoint for DeleteBackupChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/delete-backup/challenge/keypair";
}

/// Request body of `POST /v1/delete-backup`. Returns `204 No Content` on success.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteBackupRequest {
    /// Authorization from a sync factor.
    pub authorization: Authorization,
    /// Token from the challenge the `authorization` solves.
    pub challenge_token: String,
}

impl Endpoint for DeleteBackupRequest {
    type Response = ();
    const PATH: &'static str = "/v1/delete-backup";
}

// SECTION: Reset

/// Request body of `POST /v1/reset/challenge/keypair`.
///
/// Used when access to all main and sync factors is lost. The challenge is signed by the keypair
/// the `backup_account_id` was derived from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ResetChallengeKeypairRequest {
    /// The backup account whose keypair will sign the challenge.
    #[serde(deserialize_with = "crate::validate_backup_account_id")]
    pub backup_account_id: String,
}

impl Endpoint for ResetChallengeKeypairRequest {
    type Response = ChallengeKeypairResponse;
    const PATH: &'static str = "/v1/reset/challenge/keypair";
}

/// Request body of `POST /v1/reset`. Returns `204 No Content` on success.
///
/// Disaster recovery: used when all main and sync factors are lost but the user still holds the
/// secret key behind their backup account ID. On success the existing backup is removed entirely
/// and the user can initialize a fresh one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ResetRequest {
    /// The backup account being reset.
    #[serde(deserialize_with = "crate::validate_backup_account_id")]
    pub backup_account_id: String,
    /// Base64-encoded DER signature of the challenge, from the backup account keypair.
    pub signature: String,
    /// Token from the challenge the `signature` solves.
    pub challenge_token: String,
}

impl Endpoint for ResetRequest {
    type Response = ();
    const PATH: &'static str = "/v1/reset";
}
