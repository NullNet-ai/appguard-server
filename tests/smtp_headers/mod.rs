use std::collections::HashMap;

pub fn get_sample_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();

    headers.insert("uSeR-AgeNT".to_owned(), "Supa cool UA".to_string());
    headers.insert(
        "to".to_owned(),
        "bar@example.com, baz@example.com".to_string(),
    );

    headers
}

pub fn get_sample_headers_2() -> HashMap<String, String> {
    let mut headers = HashMap::new();

    headers.insert(
        "cc".to_owned(),
        "bar@example.com, baz@example.com".to_string(),
    );
    headers.insert("mime-version".to_owned(), "1.0".to_string());
    headers.insert("content-transfer-encoding".to_owned(), "7bit".to_string());

    headers
}
