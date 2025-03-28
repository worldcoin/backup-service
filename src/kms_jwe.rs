use aws_sdk_kms::primitives::Blob;
use josekit::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm;
use josekit::jwe::enc::aesgcm::AesgcmJweEncryption;
use josekit::jwe::{JweAlgorithm, JweContentEncryption, JweDecrypter, JweEncrypter, JweHeader};
use josekit::JoseError;
use std::borrow::Cow;
use std::sync::Arc;
use tokio::runtime::Handle;

/// Encrypts and decrypts JWE tokens using AWS KMS.
#[derive(Clone)]
pub struct KmsJwe {
    pub encrypter: Arc<Aes256GcmKwJweEncrypter>,
    pub decrypter: Arc<Aes256GcmKwJweDecrypter>,
}

impl KmsJwe {
    #[must_use]
    pub fn new(kms_key: KmsKey, kms_client: aws_sdk_kms::Client) -> Self {
        Self {
            encrypter: Arc::new(Aes256GcmKwJweEncrypter::new(
                kms_key.clone(),
                kms_client.clone(),
            )),
            decrypter: Arc::new(Aes256GcmKwJweDecrypter::new(kms_key, kms_client)),
        }
    }
}

/// Represents a KMS key that's used for encryption and decryption.
#[derive(Debug, Clone)]
pub struct KmsKey {
    /// For example, "01926dd6-f510-7227-9b63-da8e18607615".
    pub id: String,
    /// For example, "arn:aws:kms:us-east-1:000000000000:key/01926dd6-f510-7227-9b63-da8e18607615".
    pub arn: String,
}

impl KmsKey {
    #[must_use]
    pub fn from_arn(arn: &str) -> Self {
        let parts: Vec<&str> = arn.split('/').collect();
        assert!(
            !(!parts.len() == 2 && parts[1].contains('-')),
            "Unexpected key ARN."
        );
        Self {
            id: parts[1].to_string(),
            arn: arn.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Aes256GcmKwJweEncrypter {
    kms_key: KmsKey,
    native_encrypter: AesgcmkwJweAlgorithm,
    kms_client: aws_sdk_kms::Client,
}

impl Aes256GcmKwJweEncrypter {
    const fn new(kms_key: KmsKey, kms_client: aws_sdk_kms::Client) -> Self {
        Self {
            kms_key,
            native_encrypter: AesgcmkwJweAlgorithm::A256gcmkw,
            kms_client,
        }
    }

    pub const fn get_encryption_content() -> AesgcmJweEncryption {
        AesgcmJweEncryption::A256gcm
    }
}

impl JweEncrypter for Aes256GcmKwJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.native_encrypter
    }

    fn key_id(&self) -> Option<&str> {
        Some(&self.kms_key.id)
    }

    fn compute_content_encryption_key(
        &self,
        _content_encryption: &dyn JweContentEncryption,
        _merged: &JweHeader,
        _header: &mut JweHeader,
    ) -> Result<Option<Cow<[u8]>>, JoseError> {
        Ok(None)
    }

    fn encrypt(
        &self,
        key: &[u8],
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError> {
        let rt = Handle::current();

        let encrypted_key = rt.block_on(async {
            // NOTE: KMS signing is async, so we need to block the current thread
            kms_encrypt(&self.kms_client, self.kms_key.arn.clone(), key).await
        });

        match encrypted_key {
            Err(e) => Err(JoseError::InvalidKeyFormat(e)),
            Ok(encrypted_key) => Ok(Some(encrypted_key)),
        }
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

async fn kms_encrypt(
    client: &aws_sdk_kms::Client,
    key_id: String,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let response = client
        .encrypt()
        .key_id(key_id)
        .plaintext(Blob::new(plaintext))
        .send()
        .await?;

    response.ciphertext_blob.map_or_else(
        || Err(anyhow::anyhow!("no ciphertext_blob in response")),
        |cipher_text| Ok(cipher_text.as_ref().to_vec()),
    )
}

#[derive(Debug, Clone)]
pub struct Aes256GcmKwJweDecrypter {
    kms_key: KmsKey,
    native_decrypter: AesgcmkwJweAlgorithm,
    kms_client: aws_sdk_kms::Client,
}

impl Aes256GcmKwJweDecrypter {
    const fn new(kms_key: KmsKey, kms_client: aws_sdk_kms::Client) -> Self {
        Self {
            kms_key,
            native_decrypter: AesgcmkwJweAlgorithm::A256gcmkw,
            kms_client,
        }
    }
}

impl JweDecrypter for Aes256GcmKwJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.native_decrypter
    }

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }

    fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        _content_encryption: &dyn JweContentEncryption,
        header: &JweHeader,
    ) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let Some(encrypted_key) = encrypted_key else {
                anyhow::bail!("No encrypted key")
            };

            let kid = match header.claim("kid") {
                Some(josekit::Value::String(val)) => val,
                Some(_) => anyhow::bail!("The kid header claim must be string."),
                None => anyhow::bail!("The kid header claim is required."),
            };

            if kid != &self.kms_key.id {
                anyhow::bail!("The kid header is not valid.");
            }

            let rt = Handle::current();

            let decrypted_key = rt.block_on(async {
                // NOTE: KMS signing is async, so we need to block the current thread
                kms_decrypt(&self.kms_client, kid, encrypted_key).await
            })?;

            Ok(Cow::Owned(decrypted_key))
        })()
        .map_err(JoseError::InvalidJweFormat)
    }
}

async fn kms_decrypt(
    client: &aws_sdk_kms::Client,
    key_id: &str,
    cipher_text: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let response = client
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(Blob::new(cipher_text))
        .send()
        .await;

    // check if ciphertext decryption was successful

    match response {
        Ok(response) => response.plaintext.map_or_else(
            || Err(anyhow::anyhow!("error decrypting token")),
            |plain_text| Ok(plain_text.as_ref().to_vec()),
        ),
        Err(e) => {
            let err = e.into_service_error();
            if err.is_invalid_ciphertext_exception() {
                return Err(anyhow::anyhow!("Failed to unwrap key."));
            }
            Err(anyhow::anyhow!("KMS error decrypting token: {}", err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwt::{decode_with_decrypter, encode_with_encrypter, JwtPayload};

    async fn get_aws_config() -> aws_config::SdkConfig {
        dotenvy::from_filename(".env.example").unwrap();
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        aws_config
            .into_builder()
            .endpoint_url("http://localhost:4566")
            .build()
    }

    async fn get_kms_client() -> aws_sdk_kms::Client {
        aws_sdk_kms::Client::new(&get_aws_config().await)
    }

    #[tokio::test]
    async fn test_kms_encrypt_decrypt() {
        let kms_client = get_kms_client().await;

        let key_id = "01926dd6-f510-7227-9b63-da8e18607615".to_string();
        let key = b"my secret key";

        // happy path
        let ciphertext = kms_encrypt(&kms_client, key_id.clone(), key).await.unwrap();
        let decrypted_key = kms_decrypt(&kms_client, &key_id, &ciphertext)
            .await
            .unwrap();
        assert_eq!(key.to_vec(), decrypted_key);

        // flip a bit in ciphertext and expect decryption to fail
        let mut corrupted_ciphertext = ciphertext.clone();
        corrupted_ciphertext[50] ^= 1;
        assert_eq!(
            kms_decrypt(&kms_client, &key_id, &corrupted_ciphertext)
                .await
                .unwrap_err()
                .to_string(),
            "Failed to unwrap key."
        );

        // try to decrypt with non-existing key id
        assert_eq!(
            kms_decrypt(
                &kms_client,
                // last digit is different
                "01926dd6-f510-7227-9b63-da8e18607616",
                &ciphertext
            ).await.unwrap_err().to_string(),
            "KMS error decrypting token: NotFoundException: Key 'arn:aws:kms:us-east-1:000000000000:key/01926dd6-f510-7227-9b63-da8e18607616' does not exist"
        );

        // try to decrypt with existing, but wrong key id
        assert_eq!(
            kms_decrypt(
                &kms_client,
                // initialized in aws-seed.sh
                "01926dd6-f510-7227-9b63-da8e18607614",
                &ciphertext
            ).await.unwrap_err().to_string(),
            "KMS error decrypting token: IncorrectKeyException: The key ID in the request does not identify a CMK that can perform this operation."
        );
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_jwt_tokens() {
        let kms_client = get_kms_client().await;
        let kms_jwe = KmsJwe::new(
            KmsKey {
                id: "01926dd6-f510-7227-9b63-da8e18607615".to_string(),
                arn: "arn:aws:kms:us-east-1:000000000000:key/01926dd6-f510-7227-9b63-da8e18607615"
                    .to_string(),
            },
            kms_client,
        );

        let mut jwt_header = JweHeader::new();
        jwt_header.set_content_encryption(Aes256GcmKwJweEncrypter::get_encryption_content().name());

        let mut jwt_payload = JwtPayload::new();
        // just one claim for this test
        jwt_payload.set_issuer("https://example.com");

        let encrypter = kms_jwe.encrypter.clone();
        let jwe = tokio::task::spawn_blocking(move || {
            encode_with_encrypter(&jwt_payload, &jwt_header, &*encrypter).unwrap()
        })
        .await
        .unwrap();

        let decrypter = kms_jwe.decrypter.clone();
        let (decrypted_payload, decrypted_header) =
            tokio::task::spawn_blocking(move || decode_with_decrypter(jwe, &*decrypter).unwrap())
                .await
                .unwrap();

        assert_eq!(decrypted_header.to_string(), "{\"enc\":\"A256GCM\",\"kid\":\"01926dd6-f510-7227-9b63-da8e18607615\",\"alg\":\"A256GCMKW\"}");
        assert_eq!(
            decrypted_payload.to_string(),
            "{\"iss\":\"https://example.com\"}"
        );
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_with_wrong_key_id() {
        let kms_client = get_kms_client().await;
        let kms_jwe = KmsJwe::new(
            KmsKey {
                id: "01926dd6-f510-7227-9b63-da8e18607615".to_string(),
                arn: "arn:aws:kms:us-east-1:000000000000:key/01926dd6-f510-7227-9b63-da8e18607615"
                    .to_string(),
            },
            kms_client.clone(),
        );
        let wrong_kms_jwe = KmsJwe::new(
            KmsKey {
                id: "01926dd6-f510-7227-9b63-da8e18607616".to_string(),
                arn: "arn:aws:kms:us-east-1:000000000000:key/01926dd6-f510-7227-9b63-da8e18607614"
                    .to_string(),
            },
            kms_client,
        );

        let mut jwt_header = JweHeader::new();
        jwt_header.set_content_encryption(Aes256GcmKwJweEncrypter::get_encryption_content().name());

        let mut jwt_payload = JwtPayload::new();
        jwt_payload.set_issuer("https://example.com");

        let encrypter = kms_jwe.encrypter.clone();
        let jwe = tokio::task::spawn_blocking(move || {
            encode_with_encrypter(&jwt_payload, &jwt_header, &*encrypter).unwrap()
        })
        .await
        .unwrap();

        let decrypter = wrong_kms_jwe.decrypter.clone();
        assert_eq!(
            tokio::task::spawn_blocking(move || { decode_with_decrypter(jwe, &*decrypter) })
                .await
                .unwrap()
                .unwrap_err()
                .to_string(),
            "Invalid JWE format: The kid header is not valid."
        );
    }
}
