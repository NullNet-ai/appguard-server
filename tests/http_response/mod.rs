use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard_server::db::tables::DbTable;
use appguard_server::firewall::firewall::FirewallResult;
use appguard_server::proto::appguard::{AppGuardHttpResponse, AppGuardTcpInfo};

use crate::http_headers::{get_sample_headers, get_sample_headers_2};
use crate::ip_info::{sample_ip_info, sample_ip_info_2};
use crate::tcp_connection::{sample_tcp_connection, sample_tcp_connection_2};

pub fn sample_http_response(tcp_id: u64, with_tcp_info: bool) -> AppGuardHttpResponse {
    let mut res = AppGuardHttpResponse {
        headers: get_sample_headers(),
        code: 200,
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection("HTTP".to_string())),
            ip_info: Some(sample_ip_info()),
            tcp_id,
            ..Default::default()
        };
        res.tcp_info = Some(tcp_info);
    }

    res
}

pub fn sample_http_response_2(with_tcp_info: bool) -> AppGuardHttpResponse {
    let mut res = AppGuardHttpResponse {
        headers: get_sample_headers_2(),
        code: 404,
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection_2("HTTP".to_string())),
            ip_info: Some(sample_ip_info_2()),
            tcp_id: u32::MAX as u64,
            ..Default::default()
        };
        res.tcp_info = Some(tcp_info);
    }

    res
}

pub struct StoredHttpResponse {
    _id: u32,
    _timestamp: DateTime<Utc>,
    pub fw_res: FirewallResult,
    _tcp_id: u64,
    pub ip: String,
    pub time_usec: Option<u64>,
    pub size: Option<u64>,
    pub headers: HashMap<String, String>,
    pub code: u32,
}

pub fn retrieve_stored_http_responses(conn: &Connection) -> Vec<StoredHttpResponse> {
    let table_name = DbTable::HttpResponse.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            let headers_string: String = row.get(6)?;
            Ok(StoredHttpResponse {
                _id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                fw_res: row.get(2)?,
                _tcp_id: row.get(3)?,
                ip: row.get(4)?,
                time_usec: row.get(7)?,
                size: row.get(8)?,
                headers: serde_json::from_str(&headers_string).unwrap(),
                code: row.get(5)?,
            })
        })
        .unwrap();

    let mut responses = Vec::new();
    for row in query_result {
        responses.push(row.unwrap());
    }
    responses
}
