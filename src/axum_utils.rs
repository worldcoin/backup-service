use axum::body::Bytes;
use axum::extract::multipart::MultipartError;
use axum::extract::Multipart;
use std::collections::HashMap;

/// Extracts fields from a multipart request to a HashMap for easy access.
pub async fn extract_fields_from_multipart(
    multipart: &mut Multipart,
) -> Result<HashMap<String, Bytes>, MultipartError> {
    let mut fields = HashMap::new();
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or_default().to_string();
        let value = field.bytes().await?;
        fields.insert(name, value);
    }
    Ok(fields)
}
