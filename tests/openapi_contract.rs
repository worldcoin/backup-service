//! Asserts the HTTP surface the service registers matches the endpoint table clients build
//! against.

use std::collections::BTreeSet;

use aide::openapi::{OpenApi, ReferenceOr};
use backup_service::environment::Environment;
use backup_service::routes;
use types::endpoints::{EndpointInfo, ALL_ENDPOINTS};

/// The security scheme name attached to attestation-gated operations, from `server.rs`.
const ATTESTATION_SECURITY_SCHEME: &str = "AttestationToken";

/// Builds the real router and returns the `OpenAPI` document aide generates from it.
fn generated_api() -> OpenApi {
    let mut api = OpenApi::default();
    let _router = routes::handler(Environment::development(None)).finish_api(&mut api);
    api
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
