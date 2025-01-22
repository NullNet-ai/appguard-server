use std::collections::HashMap;

use appguard::db::views::DbView;
use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard::firewall::firewall::FirewallResult;
use appguard::proto::aiguard::AiGuardResponse;

pub struct StoredHttpRequestDataset {
    _id: u32,
    _timestamp: DateTime<Utc>,
    pub fw_res: FirewallResult,
    pub ai_res: AiGuardResponse,
    pub source: Option<String>,
    pub sport: Option<u32>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub blacklist: u32,
    pub original_url: String,
    pub user_agent: Option<String>,
    pub headers: HashMap<String, String>,
    pub method: String,
    pub query: HashMap<String, String>,
    pub cookies: Option<String>,
}

pub fn retrieve_stored_http_request_dataset(conn: &Connection) -> Vec<StoredHttpRequestDataset> {
    let table_name = DbView::HttpRequestDataset.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            let headers_string: String = row.get(12)?;
            let query_string: String = row.get(14)?;
            Ok(StoredHttpRequestDataset {
                _id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                fw_res: row.get(2)?,
                ai_res: row.get(3)?,
                source: row.get(4).ok(),
                sport: row.get(5).ok(),
                country: row.get(6)?,
                asn: row.get(7)?,
                org: row.get(8)?,
                blacklist: row.get(9)?,
                original_url: row.get(10)?,
                user_agent: row.get(11)?,
                headers: serde_json::from_str(&headers_string).unwrap(),
                method: row.get(13)?,
                query: serde_json::from_str(&query_string).unwrap(),
                cookies: row.get(15)?,
            })
        })
        .unwrap();

    let mut requests = Vec::new();
    for row in query_result {
        requests.push(row.unwrap());
    }
    requests
}
