#![deny(clippy::all, dead_code, clippy::pedantic)]

mod mock_oidc_server;
mod passkey_client;

pub use mock_oidc_server::{MockOidcProvider, MockOidcServer};
pub use passkey_client::{
    MockPasskeyClient, authenticate_with_passkey_challenge, credential_id_from_credential,
    get_mock_passkey_client, get_passkey_assertion, make_credential_from_passkey_challenge,
    passkey_public_key_sec1_from_credential, registered_passkey_material,
};
