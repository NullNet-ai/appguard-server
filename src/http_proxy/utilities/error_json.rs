use serde::Serialize;

/// Represents an error message in JSON serializable form.
///
/// This struct is designed to be serialized as JSON with a single
/// field `error` containing the error message string.
#[derive(Serialize)]
pub struct ErrorJson {
    error: String,
}

impl ErrorJson {
    /// Creates a new `ErrorJson` from any type that can be converted into a `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// let err = ErrorJson::new("something went wrong");
    /// ```
    pub fn new<S: Into<String>>(error: S) -> Self {
        let error = error.into();
        log::error!("ErrorJson: {}", error);
        Self { error }
    }
}

impl From<String> for ErrorJson {
    fn from(error: String) -> Self {
        Self::new(error)
    }
}

impl From<&str> for ErrorJson {
    fn from(error: &str) -> Self {
        Self::new(error)
    }
}

impl From<nullnet_liberror::Error> for ErrorJson {
    fn from(error: nullnet_liberror::Error) -> Self {
        Self::new(error.to_str())
    }
}
