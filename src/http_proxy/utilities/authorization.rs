use actix_web::http::header::AUTHORIZATION;
use actix_web::HttpRequest;

/// Extracts the bearer token from the `Authorization` header of an HTTP request.
///
/// This function looks for an `Authorization` header with the format:
/// `Bearer <token>`
///
/// # Arguments
///
/// * `request` - Reference to the incoming `HttpRequest`.
///
/// # Returns
///
/// * `Some(String)` containing the token if the header exists and is properly formatted.
/// * `None` if the header is missing, invalid UTF-8, or does not begin with `"Bearer "`.
pub fn extract_authorization_token(request: &HttpRequest) -> Option<String> {
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .map(str::to_owned)
}
