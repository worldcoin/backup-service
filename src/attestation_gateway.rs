use crate::types::{Environment, ErrorResponse};
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, Response},
    middleware::Next,
    Extension,
};
use http::{HeaderName, HeaderValue, Method};
use josekit::{jwk::JwkSet, jws::alg::ecdsa::EcdsaJwsAlgorithm, jwt, JoseError, Map};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{sync::RwLock, time::Instant};

const TTL: Duration = Duration::from_secs(60 * 60); // 1h
const STALE_AFTER: Duration = Duration::from_secs(60); // 1min
pub static ATTESTATION_GATEWAY_HEADER: &str = "attestation-token"; // consistency with other services which World App uses

#[derive(Debug, thiserror::Error)]
pub enum AttestationGatewayError {
    #[error("Failed to fetch JWK set from attestation gateway: {0}")]
    FetchJwkSet(reqwest::Error),
    #[error("JWK set is not an object")]
    JwkSetIsNotObject,
    #[error("Failed to parse JWK set from JSON: {0}")]
    ParseJwkSet(JoseError),
    #[error("Failed to decode header in JWS token: {0}")]
    DecodeHeader(JoseError),
    #[error("JWS token header does not have key ID claim")]
    NoKeyId,
    #[error("Key ID ({0}) is not known")]
    UnknownKeyId(String),
    #[error("Failed create verifier from JWK public key: {0}")]
    CreateVerifier(JoseError),
    #[error("Failed to decode & verify JWS token: {0}")]
    DecodeAndVerifyToken(JoseError),
    #[error("`pass` claim does not exist or is not true")]
    PassClaim,
    #[error("Token expired or expires at claim")]
    ExpiresAt,
    #[error("Token is not yet valid or issued at claim")]
    NotYetValid,
    #[error("Issuer claim is not valid")]
    IssuerClaim,
    #[error("Audience claim is not valid")]
    AudienceClaim,
    #[error("JTI claim (request hash) is not valid")]
    JtiClaim,
    #[error("Failed to serialize request payload for hashing: {0}")]
    SerializeRequestPayload(serde_json::Error),
}

struct CachedJwks {
    known_keys: Arc<JwkSet>,
    updated_at: Option<Instant>,
}

#[derive(Clone)]
pub struct AttestationGateway {
    base_url: String,
    cached_keys: Arc<RwLock<CachedJwks>>,
    bypass_token: Option<String>,
    reqwest_client: reqwest::Client,
    /// When set to `true`, the attestation gateway token will be verified if available, but any failures
    /// or if the token is not present will be logged and allowed to continue.
    do_not_enforce: bool,
}

#[derive(Debug)]
pub struct GenerateRequestHashInput {
    pub path_uri: String,
    pub method: Method,
    pub body: Option<String>,
}

impl AttestationGateway {
    #[must_use]
    fn jwks_url(base_url: &str) -> String {
        format!("{base_url}/.well-known/jwks.json")
    }

    /// Initializes an `AttestationGateway` validator
    ///
    /// # Panics
    /// Will panic if a bypass token is provided in production environment
    pub fn new(base_url: String, env: &Environment, do_not_enforce: bool) -> Self {
        let bypass_token = env::var("ATTESTATION_GATEWAY_BYPASS_TOKEN").ok();
        assert!(
            bypass_token.is_none() || env != &Environment::Production,
            "attestation gateway bypass token cannot be used in production environment"
        );
        if bypass_token.is_some() {
            tracing::warn!("🚨 Allowing attestation gateway bypass token");
        }
        if do_not_enforce {
            tracing::warn!("🚨 Currently not enforcing attestation failures");
        }
        Self {
            base_url,
            cached_keys: Arc::new(RwLock::new(CachedJwks {
                known_keys: JwkSet::new().into(),
                updated_at: None,
            })),
            reqwest_client: reqwest::Client::new(),
            bypass_token,
            do_not_enforce,
        }
    }

    /// Fetches the JWK Set from the Attestation Gateway's well known URL.
    ///
    /// # Errors
    /// Will return an error if fetching JWK set fails or parsing it fails
    async fn fetch_remote_jwk_set(&self) -> Result<Arc<JwkSet>, AttestationGatewayError> {
        let response = self
            .reqwest_client
            .get(Self::jwks_url(&self.base_url))
            .header(
                "User-Agent",
                format!("backup-service/{}", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await
            .map_err(AttestationGatewayError::FetchJwkSet)?;
        let jwks = response
            .json::<Map<String, Value>>()
            .await
            .map_err(AttestationGatewayError::FetchJwkSet)?;
        let jwk_set = JwkSet::from_map(jwks).map_err(AttestationGatewayError::ParseJwkSet)?;
        let arc = Arc::new(jwk_set);
        // Update cached keys
        {
            let mut cache = self.cached_keys.write().await;
            cache.known_keys = arc.clone();
            cache.updated_at = Some(Instant::now());
        }
        Ok(arc)
    }

    /// Retrieves the JWK Set for the given URL.
    ///
    /// First checks the in-memory cache. If the cached value exists and is within
    /// the TTL, it is returned immediately. If the cached value is
    /// stale but not expired, it is returned and a background task is spawned to
    /// revalidate and refresh it. If the cache is missing or expired, the key set
    /// is fetched synchronously from the source.
    ///
    /// Note: This method follows the same pattern as `OidcTokenVerifier::get_jwk_set`.
    async fn get_jwk_set(&self) -> Result<Arc<JwkSet>, AttestationGatewayError> {
        // Check cache
        let (keys, should_refresh) = {
            let cache = self.cached_keys.read().await;
            if let Some(updated_at) = cache.updated_at {
                let age = updated_at.elapsed();
                if age < TTL {
                    (Some(cache.known_keys.clone()), age >= STALE_AFTER)
                } else {
                    (None, false)
                }
            } else {
                (None, false)
            }
        };

        // Return cached keys if available
        if let Some(keys) = keys {
            if should_refresh {
                let this = self.clone();
                tokio::spawn(async move {
                    let _ = this.fetch_remote_jwk_set().await;
                });
            }
            return Ok(keys);
        }

        // Fetch fresh
        self.fetch_remote_jwk_set().await
    }

    /// Computes the expected request hash from the incoming request that should match the `jti` claim in the attestation-gateway-token
    ///
    /// This function is the same as the function running on World App (`oxide/attestation_gateway.rs`, function `generate_json_request_hash`).
    ///
    /// # Errors
    /// Will return an error if serializing the payload or computing the hash fails
    pub fn compute_request_hash(
        input: &GenerateRequestHashInput,
    ) -> Result<String, AttestationGatewayError> {
        let mut map = serde_json::Map::new();

        // Insert fields in the correct consistent alphabetical order
        if let Some(body_str) = &input.body {
            let body_json: Value = serde_json::from_str(body_str)
                .map_err(AttestationGatewayError::SerializeRequestPayload)?;
            map.insert("body".to_string(), sort_json(&body_json));
        }

        map.insert(
            "method".to_string(),
            serde_json::json!(input.method.as_str()),
        );
        map.insert("pathUri".to_string(), serde_json::json!(input.path_uri));

        // Serialize the ordered map into a JSON string
        let serialized = serde_json::to_string(&map)
            .map_err(AttestationGatewayError::SerializeRequestPayload)?;

        // Hash the serialized string using SHA-256 and return the hex-encoded hash
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Validates an attestation gateway token
    ///
    /// # Errors
    /// Will return an error if the token is invalid
    /// Will return an error if the token is incorrectly formed or cannot be parsed
    pub async fn validate_token(
        &self,
        token: String,
        request_hash_input: &GenerateRequestHashInput,
    ) -> Result<(), AttestationGatewayError> {
        // for local development and staging environment we allow a bypass token to be used
        if let Some(bypass_token) = &self.bypass_token {
            if &token == bypass_token {
                return Ok(());
            }
        }

        // decode jwt header to find which key to use
        let header = jwt::decode_header(&token).map_err(AttestationGatewayError::DecodeHeader)?;
        let key_id = header
            .claim("kid")
            .ok_or(AttestationGatewayError::NoKeyId)?
            .as_str()
            .ok_or(AttestationGatewayError::NoKeyId)?;
        let known_keys = self.get_jwk_set().await?;

        let jwks = known_keys.get(key_id);

        // we're not expecting to see >1 public key with same key ID from attestation gateway,
        // so we can check just first element

        let jwk = match jwks.first() {
            Some(jwk) => *jwk,
            None => {
                return Err(AttestationGatewayError::UnknownKeyId(key_id.to_string()));
            }
        };
        if jwks.len() > 1 {
            tracing::warn!(
                message = "More than one public key with the same key ID",
                key_id
            );
        }

        let verifier = EcdsaJwsAlgorithm::Es256
            .verifier_from_jwk(jwk)
            .map_err(AttestationGatewayError::CreateVerifier)?;
        let (payload, _header) = jwt::decode_with_verifier(&token, &verifier)
            .map_err(AttestationGatewayError::DecodeAndVerifyToken)?;

        drop(known_keys);

        let pass = payload
            .claim("pass")
            .ok_or(AttestationGatewayError::PassClaim)?
            .as_bool()
            .ok_or(AttestationGatewayError::PassClaim)?;
        if !pass {
            return Err(AttestationGatewayError::PassClaim);
        }

        let expires_at = payload
            .expires_at()
            .ok_or(AttestationGatewayError::ExpiresAt)?;
        if expires_at < SystemTime::now() {
            return Err(AttestationGatewayError::ExpiresAt);
        }

        let issued_at = payload
            .issued_at()
            .ok_or(AttestationGatewayError::NotYetValid)?;
        if issued_at > SystemTime::now() {
            return Err(AttestationGatewayError::NotYetValid);
        }

        let issuer = payload
            .issuer()
            .ok_or(AttestationGatewayError::IssuerClaim)?;
        if issuer != "attestation.worldcoin.org" {
            return Err(AttestationGatewayError::IssuerClaim);
        }

        let audience = payload
            .claim("aud")
            .ok_or(AttestationGatewayError::AudienceClaim)?
            .as_str()
            .ok_or(AttestationGatewayError::AudienceClaim)?;
        if audience != "toolsforhumanity.com" {
            return Err(AttestationGatewayError::AudienceClaim);
        }

        let request_hash_claim = payload
            .claim("jti")
            .ok_or(AttestationGatewayError::JtiClaim)?
            .as_str()
            .ok_or(AttestationGatewayError::JtiClaim)?;
        let request_hash = Self::compute_request_hash(request_hash_input)?;
        if request_hash_claim != request_hash {
            tracing::info!(
                message = "Request hash in token does not match computed request hash",
                request_hash_claim,
                request_hash
            );
            return Err(AttestationGatewayError::JtiClaim);
        }

        Ok(())
    }

    /// Middleware that validates attestation tokens using the `AttestationGateway`.
    ///
    /// This middleware extracts the attestation token from the request headers and
    /// verifies it against the attestation gateway. It computes the request hash
    /// based on the request path, method, and JSON body, and ensures the token's
    /// `jti` claim matches the computed hash.
    ///
    /// # Behavior
    /// - Rejects the request with an appropriate `ErrorResponse` if:
    ///   - The token is missing or malformed
    ///   - The token fails verification (e.g., expired, invalid signature, wrong audience, etc.)
    ///   - The request hash does not match the token's `jti`
    /// - If the token is valid, the request is forwarded to the next middleware or handler.
    ///
    /// # Errors
    /// Returns bad request errors depending on the failure.
    pub async fn validator(
        Extension(gateway): Extension<Arc<Self>>,
        req: Request<Body>,
        next: Next,
    ) -> Result<Response<Body>, ErrorResponse> {
        let (parts, body) = req.into_parts();

        let body_bytes = to_bytes(body, 1_048_576) // 1MB limit. Actual body size limit enforcement is done earlier by the WAF.
            .await
            .map_err(|_| {
                ErrorResponse::bad_request("invalid_payload", "Body payload is invalid")
            })?;

        let body_str = String::from_utf8(body_bytes.to_vec()).map_err(|_| {
            ErrorResponse::bad_request("invalid_payload", "Body payload is invalid")
        })?;

        // Verify the attestation token header and all relevant claims
        let attestation_result = match parts.headers.attestation_token() {
            None => {
                tracing::warn!("Attestation gateway token where expected is invalid or missing.");
                Some(ErrorResponse::bad_request(
                    "invalid_attestation_token_header",
                    "Attestation token header is invalid or not present.",
                ))
            }
            Some(attestation_token) => {
                let hash_input = GenerateRequestHashInput {
                    path_uri: parts.uri.path().to_string(),
                    method: parts.method.clone(),
                    body: if body_bytes.is_empty() {
                        None
                    } else {
                        Some(body_str)
                    },
                };
                match gateway
                    .validate_token(attestation_token.to_string(), &hash_input)
                    .await
                {
                    Ok(()) => None,
                    Err(err) => {
                        if gateway.do_not_enforce {
                            tracing::warn!(
                                error = %err,
                                "Attestation gateway token failed validation; allowing because do_not_enforce = true"
                            );
                        }
                        Some(err.into())
                    }
                }
            }
        };

        let req = Request::from_parts(parts, Body::from(body_bytes));

        match attestation_result {
            None => Ok(next.run(req).await),
            // Enforcement disabled: let the request through, but tell the client their
            // attestation would have been rejected.
            Some(error) if gateway.do_not_enforce => {
                let mut response = next.run(req).await;
                inform_attestation_failure(&mut response, &error);
                Ok(response)
            }
            Some(error) => Err(error),
        }
    }
}

/// Sends a response header with the attestation failure reason with the precise error
/// which the request would've been requested with if attestation enforcement wasn't temporarily disabled.
fn inform_attestation_failure(response: &mut Response<Body>, error: &ErrorResponse) {
    let headers = response.headers_mut();
    let value = HeaderValue::from_str(error.message()).ok().unwrap_or(
        HeaderValue::from_str(error.code())
            .ok()
            .unwrap_or(HeaderValue::from_static("generic-failure")),
    );
    headers.insert(HeaderName::from_static("attestation-failure"), value);
}

/// Helper function to recursively sort JSON objects by their keys
/// Lifted from Oxide's `AttestRequestHasher`
#[must_use]
fn sort_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted_map = serde_json::Map::new();
            let mut sorted_keys: Vec<_> = map.keys().collect();
            sorted_keys.sort();

            for key in sorted_keys {
                let val = &map[key];
                // Skip inserting if the value is null (because these values won't be present when generating in World App)
                if !val.is_null() {
                    sorted_map.insert(key.clone(), sort_json(val));
                }
            }
            serde_json::Value::Object(sorted_map)
        }
        serde_json::Value::Array(vec) => {
            serde_json::Value::Array(vec.iter().map(sort_json).collect())
        }
        _ => value.clone(),
    }
}

/// Extension trait for extracting the attestation token from HTTP headers.
///
/// Provides a convenience method to retrieve and validate the attestation gateway token
/// from the request's `HeaderMap`.
pub trait AttestationHeaderExt {
    /// Retrieves the attestation token from the request's `HeaderMap`.
    fn attestation_token(&self) -> Option<&str>;
}

impl AttestationHeaderExt for HeaderMap {
    fn attestation_token(&self) -> Option<&str> {
        let value = self.get(ATTESTATION_GATEWAY_HEADER)?.to_str().ok()?;

        if value.is_empty() {
            tracing::info!("Attestation gateway token is empty");
            return None;
        }

        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use dotenvy::dotenv;
    use http::Method;
    use josekit::{
        jwk::{
            alg::ec::{EcCurve, EcKeyPair},
            KeyPair,
        },
        jws::{alg::ecdsa::EcdsaJwsAlgorithm, JwsHeader},
        jwt::{encode_with_signer, JwtPayload},
    };
    use serde::Serialize;
    use serde_json::json;
    use std::time::{Duration, SystemTime};
    use tokio::time::sleep;

    fn test_generate_request_hash_input() -> GenerateRequestHashInput {
        GenerateRequestHashInput {
            path_uri: "retrieve/challenge/passkey".to_string(),
            method: Method::POST,
            body: None,
        }
    }

    fn generate_test_token(
        key_pair: &EcKeyPair,
        request_hash: String,
        pass: bool,
        out: String, // should "pass" or "fail",
        expires_at: Option<SystemTime>,
    ) -> String {
        let mut payload = JwtPayload::new();
        payload.set_issued_at(&SystemTime::now());
        payload.set_issuer("attestation.worldcoin.org");

        let expires_at = expires_at.unwrap_or_else(|| SystemTime::now() + Duration::from_secs(300));
        payload.set_expires_at(&expires_at);

        payload
            .set_claim(
                "aud",
                Some(josekit::Value::String("toolsforhumanity.com".to_string())),
            )
            .unwrap();
        payload
            .set_claim("jti", Some(josekit::Value::String(request_hash)))
            .unwrap();
        payload
            .set_claim("pass", Some(josekit::Value::Bool(pass)))
            .unwrap();
        payload
            .set_claim("out", Some(josekit::Value::String(out)))
            .unwrap();

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let signer = EcdsaJwsAlgorithm::Es256
            .signer_from_jwk(&key_pair.to_jwk_key_pair())
            .unwrap();

        encode_with_signer(&payload, &header, &signer).unwrap()
    }

    #[should_panic(
        expected = "attestation gateway bypass token cannot be used in production environment"
    )]
    #[tokio::test]
    async fn test_bypass_token_is_not_valid_in_production() {
        dotenvy::from_filename(".env.example").unwrap();
        let _ = AttestationGateway::new(
            "http://localhost:8000".to_string(),
            &Environment::Production,
            false,
        );
    }

    // testing the hash function by using the test payload and result hash from the `nfc-uniqueness-service` to ensure consistency
    #[test]
    fn test_compute_request_hash() {
        #[derive(Debug, Serialize, Clone)]
        #[serde(rename_all = "camelCase")]
        struct RegisterPayload {
            sod: String,
            session_key: Option<String>,
            command_responses: Option<Vec<String>>,
            batch_index: Option<u8>,
            signed_nonce: Option<String>,
            document_type: Option<String>,
            expiry_date: NaiveDate,
            identity_commitment: String,
            timestamp: i64,
            risk_meta: Map<String, Value>,
        }
        let payload = RegisterPayload {
            sod: String::new(),
            session_key: Some(String::new()),
            command_responses: Some(vec![]),
            signed_nonce: None,
            batch_index: Some(0),
            expiry_date: NaiveDate::default(),
            identity_commitment: String::new(),
            timestamp: 0,
            risk_meta: serde_json::Map::new(),
            document_type: None,
        };
        let v1_hash = AttestationGateway::compute_request_hash(&GenerateRequestHashInput {
            path_uri: "/v1/register".to_string(),
            method: Method::POST,
            body: Some(serde_json::to_string(&payload).unwrap()),
        })
        .unwrap();
        assert_eq!(
            v1_hash,
            "d1de628336fe9198b1f5ea2469512050c340abd0230ed9cf540eb0406da0bfb2"
        );
    }

    #[tokio::test]
    async fn test_validate_token() {
        let mut key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair.set_key_id(Some("test-key-id"));

        let jwk_set = JwkSet::from_map(
            json!({
                "keys": [key_pair.to_jwk_public_key()]
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .unwrap();

        let gateway = AttestationGateway {
            base_url: String::new(),
            cached_keys: Arc::new(RwLock::new(CachedJwks {
                known_keys: jwk_set.into(),
                updated_at: Some(Instant::now()),
            })),
            reqwest_client: reqwest::Client::new(),
            bypass_token: None,
            do_not_enforce: false,
        };
        let test_token = generate_test_token(
            &key_pair,
            "6913eb99b6fe89b6208f4f5c9ee4c1a2f02de139fb2afad2483fd82ccfb44d82".to_string(),
            true,
            "pass".to_string(),
            None,
        );

        gateway
            .validate_token(test_token, &test_generate_request_hash_input())
            .await
            .expect("failed to validate token");
    }

    #[tokio::test]
    async fn test_validate_token_fail() {
        let mut key_pair_1 = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair_1.set_key_id(Some("test-key-id-1"));

        let mut key_pair_2 = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair_2.set_key_id(Some("test-key-id-2"));

        let mut key_pair_2_with_wrong_id = key_pair_2.clone();
        key_pair_2_with_wrong_id.set_key_id(Some("test-key-id-1"));

        // Use key 1 to create gateway
        let jwk_set = JwkSet::from_map(
            json!({
                "keys": [key_pair_1.to_jwk_public_key()]
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .unwrap();

        let gateway = AttestationGateway {
            base_url: String::new(),
            cached_keys: Arc::new(RwLock::new(CachedJwks {
                known_keys: jwk_set.into(),
                updated_at: Some(Instant::now()),
            })),
            reqwest_client: reqwest::Client::new(),
            bypass_token: None,
            do_not_enforce: false,
        };

        // Generate token with key 2
        let test_token = generate_test_token(
            &key_pair_2,
            "request-hash".to_string(),
            true,
            "pass".to_string(),
            None,
        );

        // Token should fail validation
        assert_eq!(
            gateway
                .validate_token(test_token, &test_generate_request_hash_input())
                .await
                .unwrap_err()
                .to_string(),
            "Key ID (test-key-id-2) is not known"
        );

        // Generate token with key 2 but with key ID of key 1
        let test_token = generate_test_token(
            &key_pair_2_with_wrong_id,
            "request-hash".to_string(),
            true,
            "pass".to_string(),
            None,
        );

        // Token should fail validation
        assert_eq!(
            gateway
                .validate_token(test_token, &test_generate_request_hash_input())
                .await
                .unwrap_err()
                .to_string(),
            "Failed to decode & verify JWS token: Invalid signature: The signature does not match."
        );

        // Generate correct token, but with "pass" claim set to false
        let test_token = generate_test_token(
            &key_pair_1,
            "request-hash".to_string(),
            false,
            "fail".to_string(),
            None,
        );

        // Token should fail validation
        assert_eq!(
            gateway
                .validate_token(test_token, &test_generate_request_hash_input())
                .await
                .unwrap_err()
                .to_string(),
            "`pass` claim does not exist or is not true"
        );
    }

    #[tokio::test]
    async fn test_load_jwk_load_and_refresh() {
        dotenv().ok();
        let mut key_pair_1 = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair_1.set_key_id(Some("test-key-id-1"));

        let mut mock_server = mockito::Server::new_async().await;
        mock_server
            .mock("GET", "/.well-known/jwks.json")
            .with_status(200)
            .with_body(
                json!({
                    "keys": [
                        key_pair_1.to_jwk_public_key()
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let gateway = AttestationGateway::new(
            mock_server.url(),
            &Environment::Development {
                jwk_set_url_port_override: None,
            },
            false,
        );

        // Try to validate token with key from mock server
        let test_token = generate_test_token(
            &key_pair_1,
            "6913eb99b6fe89b6208f4f5c9ee4c1a2f02de139fb2afad2483fd82ccfb44d82".to_string(),
            true,
            "pass".to_string(),
            None,
        );
        gateway
            .validate_token(test_token, &test_generate_request_hash_input())
            .await
            .expect("failed to validate token");

        // Generate another keypair, update mock server response and refresh gateway
        let mut key_pair_2 = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair_2.set_key_id(Some("test-key-id-2"));
        mock_server
            .mock("GET", "/.well-known/jwks.json")
            .with_status(200)
            .with_body(
                json!({
                    "keys": [
                        key_pair_2.to_jwk_public_key()
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Refresh JWKS explicitly
        let _ = gateway.fetch_remote_jwk_set().await.unwrap();

        // Try to validate token with new key from mock server
        let test_token = generate_test_token(
            &key_pair_2,
            "6913eb99b6fe89b6208f4f5c9ee4c1a2f02de139fb2afad2483fd82ccfb44d82".to_string(),
            true,
            "pass".to_string(),
            None,
        );
        gateway
            .validate_token(test_token, &test_generate_request_hash_input())
            .await
            .expect("failed to validate token");

        // The old key should not be valid anymore
        let test_token = generate_test_token(
            &key_pair_1,
            "6913eb99b6fe89b6208f4f5c9ee4c1a2f02de139fb2afad2483fd82ccfb44d82".to_string(),
            true,
            "pass".to_string(),
            None,
        );
        assert_eq!(
            gateway
                .validate_token(test_token, &test_generate_request_hash_input())
                .await
                .unwrap_err()
                .to_string(),
            "Key ID (test-key-id-1) is not known"
        );

        drop(mock_server);
    }

    #[tokio::test]
    async fn test_expired_token() {
        let mut key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair.set_key_id(Some("test-key-id"));

        let jwk_set = JwkSet::from_map(
            json!({
                "keys": [key_pair.to_jwk_public_key()]
            })
            .as_object()
            .unwrap()
            .clone(),
        )
        .unwrap();

        let gateway = AttestationGateway {
            base_url: String::new(),
            cached_keys: Arc::new(RwLock::new(CachedJwks {
                known_keys: jwk_set.into(),
                updated_at: Some(Instant::now()),
            })),
            reqwest_client: reqwest::Client::new(),
            bypass_token: None,
            do_not_enforce: false,
        };

        let test_token = generate_test_token(
            &key_pair,
            "6913eb99b6fe89b6208f4f5c9ee4c1a2f02de139fb2afad2483fd82ccfb44d82".to_string(),
            true,
            "pass".to_string(),
            Some(SystemTime::now() + Duration::from_secs(1)),
        );

        sleep(Duration::from_secs(2)).await;

        assert_eq!(
            gateway
                .validate_token(test_token, &test_generate_request_hash_input())
                .await
                .unwrap_err()
                .to_string(),
            "Token expired or expires at claim"
        );
    }

    use tower::ServiceExt;

    /// A `tracing` writer that captures emitted log lines into an in-memory buffer
    /// so tests can assert on what was logged.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl LogCapture {
        fn dump(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    fn gateway_with_key(key_pair: &EcKeyPair, do_not_enforce: bool) -> AttestationGateway {
        let jwk_set = JwkSet::from_map(
            json!({ "keys": [key_pair.to_jwk_public_key()] })
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();

        AttestationGateway {
            base_url: String::new(),
            cached_keys: Arc::new(RwLock::new(CachedJwks {
                known_keys: jwk_set.into(),
                updated_at: Some(Instant::now()),
            })),
            reqwest_client: reqwest::Client::new(),
            bypass_token: None,
            do_not_enforce,
        }
    }

    /// Builds a router with the `validator` middleware in front of a handler that
    /// returns `ok`, so a `200 ok` response proves the request reached the handler.
    fn validator_app(gateway: AttestationGateway) -> axum::Router {
        axum::Router::new()
            .route(
                "/retrieve/challenge/passkey",
                axum::routing::post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn(AttestationGateway::validator))
            .layer(Extension(Arc::new(gateway)))
    }

    fn request_with_token(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/retrieve/challenge/passkey")
            .header(ATTESTATION_GATEWAY_HEADER, token)
            .body(Body::empty())
            .unwrap()
    }

    fn header_str<'a>(response: &'a Response<Body>, name: &str) -> Option<&'a str> {
        response.headers().get(name).and_then(|v| v.to_str().ok())
    }

    #[tokio::test]
    async fn test_validator_logs_and_continues_when_not_enforcing() {
        let mut key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair.set_key_id(Some("test-key-id"));
        let gateway = gateway_with_key(&key_pair, true);

        // Valid signature, but the `jti` will not match the computed request hash,
        // so token validation fails.
        let token = generate_test_token(
            &key_pair,
            "does-not-match-request-hash".to_string(),
            true,
            "pass".to_string(),
            None,
        );

        let logs = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();

        let response = {
            let _guard = tracing::subscriber::set_default(subscriber);
            validator_app(gateway)
                .oneshot(request_with_token(&token))
                .await
                .unwrap()
        };

        // The request continued to the handler despite the validation failure.
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        // but the client was informed their attestation would have been rejected.
        assert_eq!(
            header_str(&response, "attestation-failure"),
            Some("Invalid attestation token claim: JTI claim (request hash) is not valid.")
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"ok");

        // The failure was logged.
        let logged = logs.dump();
        assert!(
            logged.contains("do_not_enforce"),
            "expected a warning about bypassing the failure, captured logs: {logged}"
        );
    }

    #[tokio::test]
    async fn test_validator_signals_missing_token_when_not_enforcing() {
        let mut key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair.set_key_id(Some("test-key-id"));
        let gateway = gateway_with_key(&key_pair, true);

        // No attestation-token header at all.
        let request = Request::builder()
            .method("POST")
            .uri("/retrieve/challenge/passkey")
            .body(Body::empty())
            .unwrap();
        let response = validator_app(gateway).oneshot(request).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            header_str(&response, "attestation-failure"),
            Some("Attestation token header is invalid or not present.")
        );
    }

    #[tokio::test]
    async fn test_validator_sets_no_header_when_verified() {
        let mut key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair.set_key_id(Some("test-key-id"));
        let gateway = gateway_with_key(&key_pair, true);

        // A token whose `jti` matches the hash the middleware computes for this request.
        let request_hash = AttestationGateway::compute_request_hash(&GenerateRequestHashInput {
            path_uri: "/retrieve/challenge/passkey".to_string(),
            method: Method::POST,
            body: None,
        })
        .unwrap();
        let token = generate_test_token(&key_pair, request_hash, true, "pass".to_string(), None);

        let response = validator_app(gateway)
            .oneshot(request_with_token(&token))
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(header_str(&response, "attestation-failure"), None);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn test_validator_rejects_when_enforcing() {
        let mut key_pair = EcKeyPair::generate(EcCurve::P256).unwrap();
        key_pair.set_key_id(Some("test-key-id"));
        let gateway = gateway_with_key(&key_pair, false);

        let token = generate_test_token(
            &key_pair,
            "does-not-match-request-hash".to_string(),
            true,
            "pass".to_string(),
            None,
        );

        let response = validator_app(gateway)
            .oneshot(request_with_token(&token))
            .await
            .unwrap();

        // The request is rejected and never reaches the handler.
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_ne!(&body[..], b"ok");
    }
}
