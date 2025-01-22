use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard::db::tables::DbTable;
use appguard::firewall::firewall::FirewallResult;
use appguard::proto::appguard::{AppGuardSmtpResponse, AppGuardTcpInfo};

use crate::ip_info::{sample_ip_info, sample_ip_info_2};
use crate::tcp_connection::{sample_tcp_connection, sample_tcp_connection_2};

pub fn sample_smtp_response(tcp_id: u64, with_tcp_info: bool) -> AppGuardSmtpResponse {
    let mut res = AppGuardSmtpResponse {
        code: Some(250),
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection("SMTP".to_string())),
            ip_info: Some(sample_ip_info()),
            tcp_id,
            ..Default::default()
        };
        res.tcp_info = Some(tcp_info);
    }

    res
}

pub fn sample_smtp_response_2(with_tcp_info: bool) -> AppGuardSmtpResponse {
    let mut res = AppGuardSmtpResponse {
        code: Some(204),
        ..Default::default()
    };

    if with_tcp_info {
        let tcp_info = AppGuardTcpInfo {
            connection: Some(sample_tcp_connection_2("SMTP".to_string())),
            ip_info: Some(sample_ip_info_2()),
            ..Default::default()
        };
        res.tcp_info = Some(tcp_info);
    }

    res
}

pub struct StoredSmtpResponse {
    _id: u32,
    _timestamp: DateTime<Utc>,
    pub fw_res: FirewallResult,
    _tcp_id: u64,
    pub ip: String,
    pub time_usec: Option<u64>,
    pub app_guard_smtp_response: AppGuardSmtpResponse,
}

pub fn retrieve_stored_smtp_responses(conn: &Connection) -> Vec<StoredSmtpResponse> {
    let table_name = DbTable::SmtpResponse.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            let response = AppGuardSmtpResponse {
                code: row.get(5).ok(),
                ..Default::default()
            };
            Ok(StoredSmtpResponse {
                _id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                fw_res: row.get(2)?,
                _tcp_id: row.get(3)?,
                ip: row.get(4)?,
                time_usec: row.get(6)?,
                app_guard_smtp_response: response,
            })
        })
        .unwrap();

    let mut responses = Vec::new();
    for row in query_result {
        responses.push(row.unwrap());
    }
    responses
}
