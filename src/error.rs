use std::fmt::Display;

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn to_str(&self) -> &str {
        &self.message
    }
}

pub trait ErrorHandler<T, E> {
    fn handle_err(self, loc: Location) -> Result<T, Error>;
}

impl<T, E: Display> ErrorHandler<T, E> for Result<T, E> {
    fn handle_err(self, location: Location) -> Result<T, Error> {
        self.map_err(|e| {
            log::error!("[{}:{}] {e}", location.file, location.line);
            Error {
                message: e.to_string(),
            }
        })
    }
}

pub struct Location {
    pub file: &'static str,
    pub line: u32,
}

#[macro_export]
macro_rules! location {
    () => {
        Location {
            file: file!(),
            line: line!(),
        }
    };
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_error_handler() {
        let err_result: Result<usize, &str> = Err("test_error");
        let err_handled = err_result.handle_err(location!());
        assert_eq!(err_handled.unwrap_err().to_str(), "test_error");

        let ok_result: Result<usize, &str> = Ok(2);
        let ok_handled = ok_result.handle_err(location!());
        assert_eq!(ok_handled.unwrap(), 2);
    }
}
