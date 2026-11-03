//! Ensures the generated response schema describes both last-use representations.

#![cfg(feature = "openapi")]

use backup_service_types::ExportedFactor;
use schemars::schema::{InstanceType, SingleOrVec};

#[test]
fn exported_factor_last_use_fields_are_optional_with_matching_wire_types() {
    let schema = schemars::schema_for!(ExportedFactor);
    let object = schema.schema.object.expect("factor schema is an object");

    for (name, expected_type, expected_format) in [
        ("lastUsed", InstanceType::String, "date"),
        ("lastUsedAt", InstanceType::Integer, "int64"),
    ] {
        let property = object
            .properties
            .get(name)
            .unwrap_or_else(|| panic!("factor schema must document {name}"))
            .clone()
            .into_object();
        let types = property
            .instance_type
            .expect("last-use property has a JSON type");
        match types {
            SingleOrVec::Single(actual_type) => assert_eq!(*actual_type, expected_type, "{name}"),
            SingleOrVec::Vec(actual_types) => {
                assert!(actual_types.contains(&expected_type), "{name}");
            }
        }
        assert_eq!(property.format.as_deref(), Some(expected_format), "{name}");
        assert!(!object.required.contains(name), "{name} must be optional");
    }
}
