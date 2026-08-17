//! Asserts the HTTP surface the service registers matches the endpoint table clients build
//! against.

use std::collections::BTreeSet;
use std::sync::Arc;

use aide::openapi::{OpenApi, ReferenceOr};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Extension;
use backup_service::attestation_gateway::AttestationGateway;
use backup_service::environment::Environment;
use backup_service::routes;
use http_body_util::BodyExt;
use tower::ServiceExt;
use types::endpoints::{EndpointInfo, Method, ALL_ENDPOINTS};
use types::{ErrorBody, ErrorCode};

/// The security scheme name attached to attestation-gated operations, from `server.rs`.
const ATTESTATION_SECURITY_SCHEME: &str = "AttestationToken";

/// Builds the real router and returns the `OpenAPI` document aide generates from it.
fn generated_api() -> OpenApi {
    let mut api = OpenApi::default();
    let _router = routes::handler(Environment::development(None)).finish_api(&mut api);
    api
}

/// Builds the real router with an `AttestationGateway` layered on, so a request can actually be
/// driven through `AttestationGateway::validator` instead of only through the `OpenAPI`
/// annotations `docs()` sets. Enforcement is on, so a missing/invalid token is rejected outright
/// rather than just reported via a header.
fn app_with_attestation_gateway() -> axum::Router {
    let environment = Environment::development(None);
    let gateway = AttestationGateway::new("http://127.0.0.1:0".to_string(), &environment, false);
    let mut api = OpenApi::default();
    routes::handler(environment)
        .finish_api(&mut api)
        .layer(Extension(Arc::new(gateway)))
}

#[test]
fn registered_paths_match_the_endpoint_table() {
    let api = generated_api();
    let registered: BTreeSet<&str> = api
        .paths
        .as_ref()
        .expect("router registered no paths")
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();

    let declared: BTreeSet<&str> = ALL_ENDPOINTS.iter().map(|endpoint| endpoint.path).collect();

    assert_eq!(
        registered, declared,
        "the router and `types::endpoints::ALL_ENDPOINTS` disagree"
    );
}

#[test]
fn attestation_gated_operations_match_the_endpoint_table() {
    let api = generated_api();
    let paths = api.paths.as_ref().expect("router registered no paths");

    for endpoint in ALL_ENDPOINTS {
        let EndpointInfo {
            path,
            requires_attestation,
            ..
        } = *endpoint;

        let item = match paths.paths.get(path).expect("path is registered") {
            ReferenceOr::Item(item) => item,
            ReferenceOr::Reference { .. } => panic!("{path} is a reference, not an operation"),
        };

        let gated = item
            .post
            .iter()
            .chain(item.get.iter())
            .flat_map(|operation| operation.security.iter())
            .any(|requirement| requirement.contains_key(ATTESTATION_SECURITY_SCHEME));

        assert_eq!(
            gated, requires_attestation,
            "{path}: the router {} the attestation gate, the endpoint table says {requires_attestation}",
            if gated { "applies" } else { "does not apply" },
        );
    }
}

/// `attestation_gated_operations_match_the_endpoint_table` only proves the `OpenAPI`
/// *documentation* agrees with the endpoint table: that annotation is set by hand in each
/// route's `docs()` fn and has no code-level link to whether
/// `.route_layer(middleware::from_fn(AttestationGateway::validator))` is actually attached in
/// `routes::handler`. This test drives real requests through the real router and middleware
/// instead, so a route that is documented as attestation-gated but not actually wired up fails
/// here rather than shipping unenforced.
#[tokio::test]
async fn attestation_gated_routes_reject_requests_without_a_token() {
    let app = app_with_attestation_gateway();

    for endpoint in ALL_ENDPOINTS
        .iter()
        .filter(|endpoint| endpoint.requires_attestation)
    {
        let EndpointInfo { path, method, .. } = *endpoint;
        let method = match method {
            Method::Get => "GET",
            Method::Post => "POST",
        };

        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .expect("request is well-formed");

        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("router does not fail outright");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{path}: a request without an attestation token should be rejected by \
             `AttestationGateway::validator`, got {} instead. If this fires, `{path}` is \
             declared `REQUIRES_ATTESTATION = true` but is missing \
             `.route_layer(middleware::from_fn(AttestationGateway::validator))` in \
             `src/routes.rs`.",
            response.status(),
        );

        let body = response
            .into_body()
            .collect()
            .await
            .expect("response body is readable")
            .to_bytes();
        let error: ErrorBody =
            serde_json::from_slice(&body).expect("error response is valid `ErrorBody` JSON");

        assert_eq!(
            error.error.code,
            ErrorCode::InvalidAttestationTokenHeader,
            "{path}: expected the attestation gate's rejection code, got {:?} instead — this \
             rejection did not come from `AttestationGateway::validator`",
            error.error.code,
        );
    }
}
