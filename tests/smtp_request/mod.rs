use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard_server::db::tables::DbTable;
use appguard_server::firewall::firewall::FirewallResult;
use appguard_server::proto::appguard::{AppGuardSmtpRequest, AppGuardTcpInfo};

use crate::ip_info::{sample_ip_info, sample_ip_info_2};
use crate::smtp_headers::{get_sample_headers, get_sample_headers_2};
use crate::tcp_connection::{sample_tcp_connection, sample_tcp_connection_2};

pub fn sample_smtp_request(tcp_id: u64, with_tcp_info: bool) -> AppGuardSmtpRequest {
    let mut req = AppGuardSmtpRequest {
        headers: get_sample_headers(),
        body: Some("Hello, world!".to_owned()),
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection("SMTP".to_string())),
            ip_info: Some(sample_ip_info()),
            tcp_id,
        };

        req.tcp_info = Some(tcp_info);
    }

    req
}

pub fn sample_smtp_request_2(with_tcp_info: bool) -> AppGuardSmtpRequest {
    let mut req = AppGuardSmtpRequest {
        headers: get_sample_headers_2(),
        body: Some("12345".to_owned()),
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection_2("SMTP".to_string())),
            ip_info: Some(sample_ip_info_2()),
            ..Default::default()
        };
        req.tcp_info = Some(tcp_info);
    }

    req
}

pub struct StoredSmtpRequest {
    _id: u32,
    _timestamp: DateTime<Utc>,
    pub fw_res: FirewallResult,
    _tcp_id: u64,
    pub ip: String,
    pub user_agent: Option<String>,
    pub app_guard_smtp_request: AppGuardSmtpRequest,
}

pub fn retrieve_stored_smtp_requests(conn: &Connection) -> Vec<StoredSmtpRequest> {
    let table_name = DbTable::SmtpRequest.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            let mut request = AppGuardSmtpRequest::default();
            let headers_string: String = row.get(6)?;
            request.headers = serde_json::from_str(&headers_string).unwrap();
            request.body = row.get(7)?;
            Ok(StoredSmtpRequest {
                _id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                fw_res: row.get(2)?,
                _tcp_id: row.get(3)?,
                ip: row.get(4)?,
                user_agent: row.get(5)?,
                app_guard_smtp_request: request,
            })
        })
        .unwrap();

    let mut requests = Vec::new();
    for row in query_result {
        requests.push(row.unwrap());
    }
    requests
}
