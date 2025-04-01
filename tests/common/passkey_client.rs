use passkey::authenticator::Authenticator;
use passkey::authenticator::{UserCheck, UserValidationMethod};
use passkey::client::Client;
use passkey::types::ctap2::{Aaguid, Ctap2Error};
use passkey::types::Passkey;

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
#[allow(dead_code)]
pub fn get_mock_passkey_client() -> MockPasskeyClient {
    let store: Option<Passkey> = None;
    let user_validation_method = MockUserValidationMethod {};
    let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_validation_method);
    Client::new(authenticator)
}
