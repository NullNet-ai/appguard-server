use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard_server::db::tables::DbTable;
use appguard_server::firewall::firewall::FirewallResult;
use appguard_server::proto::appguard::{AppGuardHttpRequest, AppGuardTcpInfo};

use crate::http_headers::{
    get_sample_headers, get_sample_headers_2, get_sample_queries, get_sample_queries_2,
};
use crate::ip_info::{sample_ip_info, sample_ip_info_2};
use crate::tcp_connection::{sample_tcp_connection, sample_tcp_connection_2};

pub fn sample_http_request(tcp_id: u64, with_tcp_info: bool) -> AppGuardHttpRequest {
    let mut req = AppGuardHttpRequest {
        original_url: "https://example.com".to_owned(),
        method: "POST".to_owned(),
        headers: get_sample_headers(),
        query: get_sample_queries(),
        body: Some("Hello, world!".to_owned()),
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection("HTTP".to_string())),
            ip_info: Some(sample_ip_info()),
            tcp_id,
        };
        req.tcp_info = Some(tcp_info);
    }

    req
}

pub fn sample_http_request_2(tcp_id: u64, with_tcp_info: bool) -> AppGuardHttpRequest {
    let mut req = AppGuardHttpRequest {
        original_url: "localhost:3000/some-route".to_owned(),
        method: "GET".to_owned(),
        headers: get_sample_headers_2(),
        query: get_sample_queries_2(),
        body: Some("12345".to_owned()),
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection_2("HTTP".to_string())),
            ip_info: Some(sample_ip_info_2()),
            tcp_id,
        };
        req.tcp_info = Some(tcp_info);
    }

    req
}

pub struct StoredHttpRequest {
    _id: u32,
    _timestamp: DateTime<Utc>,
    pub fw_res: FirewallResult,
    _tcp_id: u64,
    pub ip: String,
    pub user_agent: Option<String>,
    pub cookies: Option<String>,
    pub app_guard_http_request: AppGuardHttpRequest,
}

pub fn retrieve_stored_http_requests(conn: &Connection) -> Vec<StoredHttpRequest> {
    let table_name = DbTable::HttpRequest.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            let mut request = AppGuardHttpRequest::default();
            request.original_url = row.get(5)?;
            let headers_string: String = row.get(7)?;
            request.headers = serde_json::from_str(&headers_string).unwrap();
            request.method = row.get(8)?;
            request.body = row.get(9).ok();
            let query_string: String = row.get(10)?;
            request.query = serde_json::from_str(&query_string).unwrap();
            Ok(StoredHttpRequest {
                _id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                fw_res: row.get(2)?,
                _tcp_id: row.get(3)?,
                ip: row.get(4)?,
                user_agent: row.get(6)?,
                cookies: row.get(11)?,
                app_guard_http_request: request,
            })
        })
        .unwrap();

    let mut requests = Vec::new();
    for row in query_result {
        requests.push(row.unwrap());
    }
    requests
}
