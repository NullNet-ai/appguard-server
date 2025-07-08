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

/// Extracts the proxy session token from the subdomain portion of the request's URL.
///
/// This function assumes that the session token is encoded as the first label (subdomain)
/// of the request's domain (e.g., `session123.example.com` → `session123`).
///
/// # Parameters
/// - `request`: The HTTP request containing the full URL.
///
/// # Returns
/// - `Some(String)` containing the extracted session token if the domain is valid and contains a subdomain.
/// - `None` if the domain is not present or does not contain a subdomain.
///
/// # Example
/// Given a URL like `https://abc123.example.com`, this will return `Some("abc123")`.
pub fn extract_proxy_session_token(request: &HttpRequest) -> Option<String> {
    request
        .full_url()
        .domain()
        .and_then(|domain| domain.split_once('.').map(|(session, _)| session))
        .map(|v| v.into())
}
