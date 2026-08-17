use http::HeaderName;
use types::endpoints::CLIENT_VERSION_HEADER;

/// Typed form of [`CLIENT_VERSION_HEADER`], which is the client-facing definition.
pub static CLIENT_VERSION: HeaderName = HeaderName::from_static(CLIENT_VERSION_HEADER);
