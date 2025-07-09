#![deny(clippy::all, dead_code, clippy::pedantic)]

mod mock_oidc_server;

pub use mock_oidc_server::{MockOidcProvider, MockOidcServer};
