#![deny(clippy::all, dead_code, clippy::pedantic)]

mod mock_oidc_server;
mod passkey_client;

pub use mock_oidc_server::{MockOidcProvider, MockOidcServer};
pub use passkey_client::{MockPasskeyClient, get_mock_passkey_client};
