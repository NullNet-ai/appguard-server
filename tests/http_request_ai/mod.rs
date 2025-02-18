use appguard_server::db::tables::DbTable;
use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard_server::proto::aiguard::AiGuardResponse;

pub struct StoredHttpRequestAi {
    _id: u32,
    _timestamp: DateTime<Utc>,
    pub ai_res: AiGuardResponse,
}

pub fn retrieve_stored_http_request_ai(conn: &Connection) -> Vec<StoredHttpRequestAi> {
    let table_name = DbTable::HttpRequestAi.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            Ok(StoredHttpRequestAi {
                _id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                ai_res: row.get(2)?,
            })
        })
        .unwrap();

    let mut requests = Vec::new();
    for row in query_result {
        requests.push(row.unwrap());
    }
    requests
}
