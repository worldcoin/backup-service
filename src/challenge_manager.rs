use crate::kms_jwe::{Aes256GcmKwJweEncrypter, KmsJwe};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use josekit::jwe::JweHeader;
use josekit::jwt::{decode_with_decrypter, encode_with_encrypter, JwtPayload};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::ops::Add;
use std::time::{Duration, SystemTime};
use strum_macros::{Display, EnumString};

/// Checks authenticity of each challenge for keypair and passkeys during the verification
/// using tokens signed with AWS KMS. Note that it does not generate challenges or verify
/// challenge response correctness — that's a job for the factor-specific code.
///
/// Each challenge token can store a payload, which is a byte array. The payload is
/// encrypted with AWS KMS and stored in the token. The client can then send the token back
/// to the server, which can decrypt the payload and verify token authenticity.
///
/// The payload can store:
/// - Raw challenge for keypair challenges
/// - "PasskeyRegistration" object for passkey challenges
///
/// We're using encrypting tokens to minimize amount of state we need to store on the server.
#[derive(Clone)]
pub struct ChallengeManager {
    expires_in: Duration,
    /// AWS KMS + JWT client for encrypting and decrypting challenge tokens
    kms_jwe: KmsJwe,
}

impl ChallengeManager {
    #[must_use]
    pub fn new(expires_in: Duration, kms_jwe: KmsJwe) -> Self {
        Self {
            expires_in,
            kms_jwe,
        }
    }

    pub async fn create_challenge_token(
        &self,
        challenge_type: ChallengeType,
        payload: &[u8],
        challenge_context: ChallengeContext,
    ) -> Result<ChallengeToken, ChallengeManagerError> {
        let encoded_payload = STANDARD.encode(payload);

        // Do not put any sensitive information in the header, as it's not encrypted
        let mut jwt_header = JweHeader::new();
        jwt_header.set_content_encryption(Aes256GcmKwJweEncrypter::get_encryption_content().name());

        let mut jwt_payload = JwtPayload::new();
        jwt_payload
            .set_claim("payload", Some(json!(encoded_payload)))
            .map_err(ChallengeManagerError::SetClaim)?;
        jwt_payload
            .set_claim("challenge_type", Some(json!(challenge_type.to_string())))
            .map_err(ChallengeManagerError::SetClaim)?;
        jwt_payload
            .set_claim("challenge_context", Some(json!(challenge_context)))
            .map_err(ChallengeManagerError::SetClaim)?;

        jwt_payload.set_issued_at(&SystemTime::now());
        jwt_payload.set_not_before(&SystemTime::now());
        jwt_payload.set_expires_at(&SystemTime::now().add(self.expires_in));

        let encrypter = self.kms_jwe.encrypter.clone();

        let jwe = tokio::task::spawn_blocking(move || {
            encode_with_encrypter(&jwt_payload, &jwt_header, &*encrypter)
                .map_err(ChallengeManagerError::EncryptToken)
        })
        .await
        .map_err(ChallengeManagerError::TokioError)??;

        Ok(jwe)
    }

    pub async fn extract_token_payload(
        &self,
        expected_challenge_type: ChallengeType,
        challenge_token: ChallengeToken,
    ) -> Result<(TokenPayload, ChallengeContext), ChallengeManagerError> {
        let decrypter = self.kms_jwe.decrypter.clone();
        let (jwt_payload, _header) = tokio::task::spawn_blocking(move || {
            decode_with_decrypter(challenge_token, &*decrypter)
                .map_err(ChallengeManagerError::FailedToDecryptToken)
        })
        .await
        .map_err(ChallengeManagerError::TokioError)??;

        let actual_challenge_type = jwt_payload
            .claim("challenge_type")
            .ok_or(ChallengeManagerError::NoValidChallengeTypeClaim)?
            .as_str()
            .ok_or(ChallengeManagerError::NoValidChallengeTypeClaim)?;
        if actual_challenge_type != expected_challenge_type.to_string() {
            return Err(ChallengeManagerError::NoValidChallengeTypeClaim);
        }

        let encoded_payload = jwt_payload
            .claim("payload")
            .ok_or(ChallengeManagerError::NoValidPayloadClaim)?
            .as_str()
            .ok_or(ChallengeManagerError::NoValidPayloadClaim)?;
        let payload = STANDARD
            .decode(encoded_payload.as_bytes())
            .map_err(|_| ChallengeManagerError::NoValidPayloadClaim)?;
        let challenge_context = jwt_payload
            .claim("challenge_context")
            .ok_or(ChallengeManagerError::NoValidChallengeContextClaim)?;
        let challenge_context: ChallengeContext = serde_json::from_value(challenge_context.clone())
            .map_err(|_| ChallengeManagerError::NoValidChallengeContextClaim)?;

        // Check expiration
        let now = SystemTime::now();
        let not_before = jwt_payload
            .not_before()
            .ok_or(ChallengeManagerError::TokenExpiredOrNoExpiration)?;
        let expires_at = jwt_payload
            .expires_at()
            .ok_or(ChallengeManagerError::TokenExpiredOrNoExpiration)?;
        if now < not_before || now > expires_at {
            return Err(ChallengeManagerError::TokenExpiredOrNoExpiration);
        }

        Ok((payload, challenge_context))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ChallengeManagerError {
    #[error("Error setting claim: {0}")]
    SetClaim(josekit::JoseError),
    #[error("Error encrypting token: {0}")]
    EncryptToken(josekit::JoseError),
    #[error("Failed to decrypt token: {0}")]
    FailedToDecryptToken(josekit::JoseError),
    #[error("Tokio error: {0}")]
    TokioError(#[from] tokio::task::JoinError),
    #[error("No valid payload claim in token")]
    NoValidPayloadClaim,
    #[error("No valid challenge type claim in token")]
    NoValidChallengeTypeClaim,
    #[error("No valid challenge context claim in token")]
    NoValidChallengeContextClaim,
    #[error("No expiration / not before claim in token or token expired")]
    TokenExpiredOrNoExpiration,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum ChallengeType {
    Passkey,
    Keypair,
}

/// Represents the specific method that the challenge is used for. It can also include some
/// fields that user needs to commit. For instance, when deleting a factor challenge context
/// will include the factor ID to delete. This way, a token stolen to delete one factor cannot
/// be used to delete another factor (in addition to replay protection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "UPPERCASE")]
pub enum ChallengeContext {
    #[serde(rename_all = "camelCase")]
    AddSyncFactor {},
    #[serde(rename_all = "camelCase")]
    Create {},
    #[serde(rename_all = "camelCase")]
    Retrieve {},
    #[serde(rename_all = "camelCase")]
    RetrieveMetadata {},
    #[serde(rename_all = "camelCase")]
    Sync {},
}

pub type TokenPayload = Vec<u8>;
pub type ChallengeToken = String;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms_jwe::KmsKey;

    async fn get_aws_config() -> aws_config::SdkConfig {
        dotenvy::from_filename(".env.example").unwrap();
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        aws_config
            .into_builder()
            .endpoint_url("http://localhost:4566")
            .build()
    }

    async fn get_kms_jwe() -> KmsJwe {
        let kms_client = aws_sdk_kms::Client::new(&get_aws_config().await);
        KmsJwe::new(
            KmsKey {
                id: "01926dd6-f510-7227-9b63-da8e18607615".to_string(),
                arn: "arn:aws:kms:us-east-1:000000000000:key/01926dd6-f510-7227-9b63-da8e18607615"
                    .to_string(),
            },
            kms_client.clone(),
        )
    }

    #[tokio::test]
    async fn test_create_and_extract_challenge_token() {
        let kms_jwe = get_kms_jwe().await;
        let challenge_manager = ChallengeManager::new(Duration::from_secs(60), kms_jwe);

        let challenge_token = challenge_manager
            .create_challenge_token(
                ChallengeType::Passkey,
                &[1, 2, 3],
                ChallengeContext::AddSyncFactor {},
            )
            .await
            .unwrap();
        let (payload, context) = challenge_manager
            .extract_token_payload(ChallengeType::Passkey, challenge_token.clone())
            .await
            .unwrap();
        assert_eq!(payload, vec![1, 2, 3]);
        assert_eq!(context, ChallengeContext::AddSyncFactor {});

        let challenge_token = challenge_manager
            .create_challenge_token(
                ChallengeType::Keypair,
                &[4, 5, 6],
                ChallengeContext::Create {},
            )
            .await
            .unwrap();
        let (payload, context) = challenge_manager
            .extract_token_payload(ChallengeType::Keypair, challenge_token.clone())
            .await
            .unwrap();
        assert_eq!(payload, vec![4, 5, 6]);
        assert_eq!(context, ChallengeContext::Create {});
    }

    #[tokio::test]
    async fn test_extract_challenge_token_with_invalid_challenge_type() {
        let kms_jwe = get_kms_jwe().await;
        let challenge_manager = ChallengeManager::new(Duration::from_secs(60), kms_jwe);

        let challenge_token = challenge_manager
            .create_challenge_token(
                ChallengeType::Passkey,
                &[1, 2, 3],
                ChallengeContext::Retrieve {},
            )
            .await
            .unwrap();
        let result = challenge_manager
            .extract_token_payload(ChallengeType::Keypair, challenge_token.clone())
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "No valid challenge type claim in token"
        );
    }

    #[tokio::test]
    async fn test_extract_challenge_token_with_invalid_payload() {
        let kms_jwe = get_kms_jwe().await;
        let challenge_manager = ChallengeManager::new(Duration::from_secs(60), kms_jwe);

        let mut challenge_token = challenge_manager
            .create_challenge_token(
                ChallengeType::Passkey,
                &[1, 2, 3],
                ChallengeContext::Create {},
            )
            .await
            .unwrap();
        challenge_token.push_str("i");
        let result = challenge_manager
            .extract_token_payload(ChallengeType::Passkey, challenge_token)
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to decrypt token: Invalid JWE format: Invalid last symbol 105, offset 22."
        );
    }

    #[tokio::test]
    async fn test_extract_challenge_token_with_expired_token() {
        let kms_jwe = get_kms_jwe().await;
        let challenge_manager = ChallengeManager::new(Duration::from_secs(0), kms_jwe);
        let challenge_token = challenge_manager
            .create_challenge_token(
                ChallengeType::Passkey,
                &[1, 2, 3],
                ChallengeContext::RetrieveMetadata {},
            )
            .await
            .unwrap();
        let result = challenge_manager
            .extract_token_payload(ChallengeType::Passkey, challenge_token.clone())
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "No expiration / not before claim in token or token expired"
        );
    }
}
