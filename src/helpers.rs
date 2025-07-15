use std::collections::HashMap;

use chrono::{DateTime, FixedOffset, Utc};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libtoken::Token;
use rand::distr::Alphanumeric;
use rand::Rng;

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

pub(crate) fn authenticate(token: String) -> Result<(String, Token), Error> {
    let token_info = Token::from_jwt(&token).handle_err(location!())?;

    Ok((token, token_info))
}

// pub fn map_status_value_to_enum(status: &str) -> DeviceStatus {
//     let lowercase: String = status.to_lowercase();
//
//     if lowercase.starts_with("draft") {
//         DeviceStatus::Draft
//     } else if lowercase.starts_with("active") {
//         DeviceStatus::Active
//     } else if lowercase.starts_with("archive") {
//         DeviceStatus::Archived
//     } else if lowercase.starts_with("delete") {
//         DeviceStatus::Deleted
//     } else {
//         DeviceStatus::DsUnknown
//     }
// }

pub fn generate_random_string(length: usize) -> String {
    rand::rngs::ThreadRng::default()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
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
}
