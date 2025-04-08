use openidconnect::{Nonce, NonceVerifier};

#[derive(Debug, Clone, Default)]
pub struct OidcNonceVerifier {}

impl NonceVerifier for OidcNonceVerifier {
    fn verify(self, _nonce: Option<&Nonce>) -> Result<(), String> {
        // TODO/FIXME: Track used nonces for OIDC tokens
        Ok(())
    }
}
