use std::collections::HashMap;

pub fn get_sample_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();

    headers.insert("User-Agent".to_owned(), "Mozilla/5.0".to_string());
    headers.insert("Accept".to_owned(), "text/html".to_string());
    headers.insert("Cookie".to_owned(), "[\"bis\", \"quits\"".to_string());
    headers.insert("Content-Length".to_owned(), "123".to_string());
    headers.insert("Pi".to_owned(), "3.14".to_string());

    headers
}

pub fn get_sample_headers_2() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("uSeR-aGEnT".to_owned(), "appguard-1.0.0".to_string());
    headers.insert("aCCEpT".to_owned(), "xml/json/whatever".to_string());
    headers.insert("cOoKIe".to_owned(), "2.5".to_string());
    headers.insert("CoNTEnt-leNGtH".to_owned(), "256".to_string());

    headers
}

pub fn get_sample_queries() -> HashMap<String, String> {
    let mut queries = HashMap::new();

    queries.insert("name".to_owned(), "giuliano".to_string());
    queries.insert("age".to_owned(), "24".to_string());
    queries.insert("lunch".to_owned(), "[\"pasta\", \"pizza\"".to_string());
    queries.insert("weight".to_owned(), "64.0".to_string());

    queries
}

pub fn get_sample_queries_2() -> HashMap<String, String> {
    let mut queries = HashMap::new();

    queries.insert("e".to_owned(), "mc^2".to_string());
    queries.insert("pi".to_owned(), "3.1415".to_string());
    queries.insert("animals".to_owned(), "[\"cat\", \"dog\"".to_string());

    queries
}
