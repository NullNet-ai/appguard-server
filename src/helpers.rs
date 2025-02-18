use std::collections::HashMap;
use std::convert::TryFrom;

use chrono::{DateTime, FixedOffset, Utc};

use nullnet_liberror::{location, Error, ErrorHandler, Location};

pub fn get_timestamp_string() -> String {
    Utc::now().to_rfc3339()
}

pub fn timestamp_str_diff_usec(timestamp1: &str, timestamp2: &str) -> Result<u64, Error> {
    let datetime1: DateTime<FixedOffset> =
        DateTime::parse_from_rfc3339(timestamp1).handle_err(location!())?;
    let datetime2: DateTime<FixedOffset> =
        DateTime::parse_from_rfc3339(timestamp2).handle_err(location!())?;
    let time_delta = datetime1.signed_duration_since(datetime2);
    let micros = time_delta
        .num_microseconds()
        .ok_or("Invalid time delta")
        .handle_err(location!())?;
    u64::try_from(micros).handle_err(location!())
}

pub fn get_header<'a, S: std::hash::BuildHasher>(
    headers: &'a HashMap<String, String, S>,
    key: &'a str,
) -> Option<&'a String> {
    let key = key.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == key)
        .map(|(_, v)| v)
}

pub fn get_env(key: Option<&'static str>, query: &'static str, info: &'static str) -> String {
    let mut env = String::new();
    if let Some(mut val) = key {
        val = val.trim();
        if !val.is_empty() {
            env = format!("?{query}={val}");
            log::info!("Loaded {info}");
        }
    }
    if env.is_empty() {
        log::warn!("{info} not found");
    }
    env
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_str_diff_usec() {
        let timestamp1 = "2024-08-01T00:00:00.000000000+00:00";
        let timestamp2 = "2024-08-01T00:00:00.000175000+00:00";
        let diff = timestamp_str_diff_usec(timestamp2, timestamp1).expect("Test");
        assert_eq!(diff, 175);
        let diff = timestamp_str_diff_usec(timestamp1, timestamp2);
        assert!(diff.is_err());

        let timestamp2 = "3024-08-01T00:00:00.000175000+00:00";
        let diff = timestamp_str_diff_usec(timestamp2, timestamp1).expect("Test");
        assert_eq!(diff, 31_556_908_800_000_175);
    }

    #[test]
    fn test_get_env_some() {
        let key = Some("this-is-a-sample_value");
        let query = "sample";
        let info = "print-me";
        let env = get_env(key, query, info);
        assert_eq!(env, "?sample=this-is-a-sample_value");
    }

    #[test]
    fn test_get_env_empty() {
        let key = Some(" \n \t ");
        let query = "sample";
        let info = "print-me";
        let env = get_env(key, query, info);
        assert_eq!(env, "");
    }

    #[test]
    fn test_get_env_none() {
        let key = None;
        let query = "sample";
        let info = "print-me";
        let env = get_env(key, query, info);
        assert_eq!(env, "");
    }
}
