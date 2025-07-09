#![allow(clippy::missing_panics_doc)]

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
