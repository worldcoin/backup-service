#![allow(clippy::missing_panics_doc)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coset::cbor::value::Value as CborValue;
use coset::iana::{self, EnumI64 as _};
use coset::{Label, RegisteredLabel};
use passkey::authenticator::Authenticator;
use passkey::authenticator::{UserCheck, UserValidationMethod};
use passkey::client::Client;
use passkey::types::Passkey;
use passkey::types::ctap2::{Aaguid, Ctap2Error};
use passkey::types::webauthn::CredentialRequestOptions;
use serde_json::{Value, json};
use url::Url;

pub type MockPasskeyClient =
    Client<Option<Passkey>, MockUserValidationMethod, public_suffix::PublicSuffixList>;

/// Leading byte of a `SEC1` uncompressed elliptic-curve point (`0x04 || x || y`).
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

/// Length of a `SEC1` uncompressed P-256 point: tag byte plus two 32-byte coordinates.
const SEC1_P256_POINT_LEN: usize = 65;

/// DER prefix of a P-256 `SubjectPublicKeyInfo` (RFC 5480), everything before the `SEC1` point:
/// `SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING (0 unused bits) ... }`.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub struct MockUserValidationMethod {}

#[async_trait::async_trait]
impl UserValidationMethod for MockUserValidationMethod {
    type PasskeyItem = Passkey;

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }

    async fn check_user<'a>(
        &self,
        _credential: Option<&'a Self::PasskeyItem>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: true,
        })
    }
}

/// Initialize an authenticator with a mock user validation method
#[must_use]
pub fn get_mock_passkey_client() -> MockPasskeyClient {
    let store: Option<Passkey> = None;
    let user_validation_method = MockUserValidationMethod {};
    let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_validation_method);
    Client::new(authenticator)
}

/// Create a new passkey credential by solving a challenge. Returns the credential as a JSON value.
pub async fn make_credential_from_passkey_challenge(
    passkey_client: &mut MockPasskeyClient,
    challenge_response: &serde_json::Value,
) -> serde_json::Value {
    let credential_input: passkey::types::webauthn::CredentialCreationOptions =
        serde_json::from_value(challenge_response["challenge"].clone()).unwrap();

    let credential = passkey_client
        .register(
            Url::parse("https://keys.world.app").unwrap(),
            credential_input,
            passkey::client::DefaultClientData,
        )
        .await
        .unwrap();

    serde_json::to_value(credential).unwrap()
}

/// Authenticate using a passkey client with a retrieval challenge. Returns the credential as a JSON value.
pub async fn authenticate_with_passkey_challenge(
    passkey_client: &mut MockPasskeyClient,
    challenge_response: &serde_json::Value,
) -> serde_json::Value {
    let credential_request_options: passkey::types::webauthn::CredentialRequestOptions =
        serde_json::from_value(challenge_response["challenge"].clone()).unwrap();
    let credential = passkey_client
        .authenticate(
            &Url::parse("https://keys.world.app").unwrap(),
            credential_request_options,
            passkey::client::DefaultClientData,
        )
        .await
        .unwrap();
    serde_json::to_value(credential).unwrap()
}

/// Gets a passkey assertion for a Turnkey activity
pub async fn get_passkey_assertion(client: &mut MockPasskeyClient, challenge: &str) -> Value {
    let credential_request_options: CredentialRequestOptions = serde_json::from_value(json!({
        "publicKey": {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": "keys.world.app",
            "userVerification": "preferred"
        },
    }))
    .unwrap();

    serde_json::to_value(
        client
            .authenticate(
                &Url::parse("https://keys.world.app").unwrap(),
                credential_request_options,
                passkey::client::DefaultClientData,
            )
            .await
            .unwrap(),
    )
    .unwrap()
}

/// Returns the material of the passkey currently held by the mock client's store as
/// `(credential_id, sec1_public_key)`: the raw credential id bytes and the P-256 public key as a
/// 65-byte `SEC1` uncompressed point (`0x04 || x || y`).
///
/// The coordinates are read straight from the stored `COSE` key (labels `-2`/`-3`), independently
/// of the registration response, so callers can cross-check the two.
///
/// # Panics
/// Panics when no passkey has been registered yet, or when the stored key is not an `EC2` P-256
/// key with 32-byte coordinates.
#[must_use]
pub fn registered_passkey_material(passkey_client: &MockPasskeyClient) -> (Vec<u8>, [u8; 65]) {
    let passkey = passkey_client.authenticator().store().as_ref().expect(
        "mock passkey client has no registered passkey; \
         register one with make_credential_from_passkey_challenge first",
    );
    let key = &passkey.key;

    assert!(
        matches!(key.kty, RegisteredLabel::Assigned(iana::KeyType::EC2)),
        "registered passkey key type is {:?}, expected EC2",
        key.kty
    );

    let ec2_param = |param: iana::Ec2KeyParameter| {
        key.params.iter().find_map(|(label, value)| {
            matches!(label, Label::Int(i) if *i == param.to_i64()).then_some(value)
        })
    };

    let curve = ec2_param(iana::Ec2KeyParameter::Crv)
        .and_then(CborValue::as_integer)
        .map(i128::from);
    assert_eq!(
        curve,
        Some(i128::from(iana::EllipticCurve::P_256.to_i64())),
        "registered passkey curve is not P-256"
    );

    let coordinate = |param: iana::Ec2KeyParameter| -> [u8; 32] {
        let bytes = ec2_param(param)
            .and_then(|value| value.as_bytes())
            .unwrap_or_else(|| panic!("registered passkey key has no {param:?} coordinate"));
        bytes.as_slice().try_into().unwrap_or_else(|_| {
            panic!(
                "registered passkey {param:?} coordinate is {} bytes, expected 32",
                bytes.len()
            )
        })
    };

    let mut sec1 = [0u8; SEC1_P256_POINT_LEN];
    sec1[0] = SEC1_UNCOMPRESSED_TAG;
    sec1[1..33].copy_from_slice(&coordinate(iana::Ec2KeyParameter::X));
    sec1[33..].copy_from_slice(&coordinate(iana::Ec2KeyParameter::Y));

    (passkey.credential_id.to_vec(), sec1)
}

/// Decodes the registration response JSON's `rawId` into the raw credential id bytes.
///
/// # Panics
/// Panics when `rawId` is missing or is neither unpadded `base64url` nor a byte array.
#[must_use]
pub fn credential_id_from_credential(credential: &Value) -> Vec<u8> {
    let raw_id = &credential["rawId"];
    assert!(!raw_id.is_null(), "credential JSON has no `rawId` field");
    json_bytes(raw_id, "rawId")
}

/// Extracts the new credential's public key from the registration response JSON as a 65-byte
/// `SEC1` uncompressed point. Reads `response.publicKey` (`WebAuthn` L3 `getPublicKey()`), a
/// `base64url` DER `SubjectPublicKeyInfo`, of which the trailing 65 bytes are the point. Only
/// P-256 (ES256) keys are supported.
///
/// # Panics
/// Panics when the field is missing, or when the DER is not a P-256 `SubjectPublicKeyInfo`
/// carrying an uncompressed point.
#[must_use]
pub fn passkey_public_key_sec1_from_credential(credential: &Value) -> [u8; 65] {
    let public_key = &credential["response"]["publicKey"];
    assert!(
        !public_key.is_null(),
        "registration response JSON has no `response.publicKey` field"
    );
    let der = json_bytes(public_key, "response.publicKey");

    assert_eq!(
        der.len(),
        P256_SPKI_PREFIX.len() + SEC1_P256_POINT_LEN,
        "`response.publicKey` is {} bytes, expected a 91-byte P-256 SubjectPublicKeyInfo",
        der.len()
    );
    assert_eq!(
        der[..P256_SPKI_PREFIX.len()],
        P256_SPKI_PREFIX,
        "`response.publicKey` is not a P-256 SubjectPublicKeyInfo"
    );
    let point: [u8; SEC1_P256_POINT_LEN] = der[P256_SPKI_PREFIX.len()..]
        .try_into()
        .expect("length asserted above");
    assert_eq!(
        point[0], SEC1_UNCOMPRESSED_TAG,
        "`response.publicKey` does not carry an uncompressed SEC1 point"
    );
    point
}

/// Decodes a `WebAuthn` JSON byte field. Accepts the unpadded `base64url` string form mandated
/// by the `WebAuthn` JSON serialization, and the plain byte-array form that `passkey` 0.4 emits
/// for its `Bytes` type when the `serialize_bytes_as_base64_string` feature is off.
fn json_bytes(value: &Value, field: &str) -> Vec<u8> {
    match value {
        Value::String(encoded) => URL_SAFE_NO_PAD.decode(encoded).unwrap_or_else(|err| {
            panic!("credential field `{field}` is not unpadded base64url: {err}")
        }),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_u64()
                    .and_then(|byte| u8::try_from(byte).ok())
                    .unwrap_or_else(|| {
                        panic!("credential field `{field}` holds a non-byte element: {item}")
                    })
            })
            .collect(),
        other => panic!(
            "credential field `{field}` must be a base64url string or a byte array, got: {other}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{Signature, VerifyingKey};
    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Registers a fresh ES256 credential through the same path the integration tests use,
    /// with creation options shaped like the service's registration challenge.
    async fn register_passkey(client: &mut MockPasskeyClient) -> Value {
        let challenge_response = json!({
            "challenge": {
                "publicKey": {
                    "rp": { "id": "keys.world.app", "name": "World App" },
                    "user": {
                        "id": URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()),
                        "name": "MOCK USERNAME",
                        "displayName": "MOCK DISPLAY NAME"
                    },
                    "challenge": URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
                    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
                    "attestation": "none"
                }
            }
        });
        make_credential_from_passkey_challenge(client, &challenge_response).await
    }

    #[tokio::test]
    async fn registered_material_matches_registration_response() {
        let mut client = get_mock_passkey_client();
        let credential = register_passkey(&mut client).await;

        let (credential_id, sec1) = registered_passkey_material(&client);

        assert!(!credential_id.is_empty());
        assert_eq!(sec1[0], SEC1_UNCOMPRESSED_TAG);
        assert_eq!(credential_id_from_credential(&credential), credential_id);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(credential["id"].as_str().unwrap())
                .unwrap(),
            credential_id,
            "`id` must be the base64url form of `rawId`"
        );
        assert_eq!(passkey_public_key_sec1_from_credential(&credential), sec1);
    }

    #[tokio::test]
    async fn registered_material_public_key_verifies_assertions() {
        let mut client = get_mock_passkey_client();
        register_passkey(&mut client).await;
        let (_, sec1) = registered_passkey_material(&client);

        let challenge = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let assertion = get_passkey_assertion(&mut client, &challenge).await;
        let response = &assertion["response"];
        let client_data_json = json_bytes(&response["clientDataJSON"], "clientDataJSON");
        let mut signed = json_bytes(&response["authenticatorData"], "authenticatorData");
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature =
            Signature::from_der(&json_bytes(&response["signature"], "signature")).unwrap();

        VerifyingKey::from_sec1_bytes(&sec1)
            .unwrap()
            .verify(&signed, &signature)
            .expect("assertion must verify under the SEC1 key read from the store");
    }

    #[test]
    #[should_panic(expected = "has no registered passkey")]
    fn registered_passkey_material_panics_without_registration() {
        let client = get_mock_passkey_client();
        let _ = registered_passkey_material(&client);
    }

    #[test]
    fn credential_id_from_credential_decodes_base64url_and_byte_arrays() {
        assert_eq!(
            credential_id_from_credential(&json!({ "rawId": "AQID" })),
            vec![1, 2, 3]
        );
        assert_eq!(
            credential_id_from_credential(&json!({ "rawId": [1, 2, 3] })),
            vec![1, 2, 3]
        );
    }

    #[test]
    #[should_panic(expected = "has no `rawId` field")]
    fn credential_id_from_credential_panics_without_raw_id() {
        let _ = credential_id_from_credential(&json!({ "id": "AQID" }));
    }

    #[test]
    #[should_panic(expected = "is not a P-256 SubjectPublicKeyInfo")]
    fn passkey_public_key_sec1_from_credential_rejects_non_p256_spki() {
        let bogus_der = URL_SAFE_NO_PAD.encode([0u8; 91]);
        let _ = passkey_public_key_sec1_from_credential(
            &json!({ "response": { "publicKey": bogus_der } }),
        );
    }
}
