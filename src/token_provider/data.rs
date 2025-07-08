use nullnet_libtoken::Token;
use std::sync::Arc;

/// Stores authentication credentials and an optional JWT token.
#[derive(Debug)]
pub(crate) struct AuthData {
    pub app_id: String,
    pub app_secret: String,
    pub is_root: bool,
    pub token: Option<Arc<Token>>,
}

impl AuthData {
    /// Creates a new `AuthData` instance with the provided `app_id` and `app_secret`.
    ///
    /// The `token` field is initialized as `None`.
    pub fn new(app_id: impl Into<String>, app_secret: impl Into<String>, is_root: bool) -> Self {
        Self {
            app_id: app_id.into(),
            app_secret: app_secret.into(),
            is_root,
            token: None,
        }
    }

    /// Returns `true` if the token is either missing or expired,
    /// indicating that a login or token refresh is required.
    pub fn needs_refresh(&self) -> bool {
        self.token.as_ref().is_none_or(|token| token.is_expired())
    }
}
