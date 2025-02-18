use chrono::{DateTime, Utc};
use rusqlite::Connection;

use appguard_server::db::tables::DbTable;
use appguard_server::proto::appguard::AppGuardTcpConnection;

pub fn sample_tcp_connection(protocol: String) -> AppGuardTcpConnection {
    AppGuardTcpConnection {
        source_ip: Some("::1".to_owned()),
        source_port: Some(12345),
        destination_ip: Some("8.8.8.8".to_owned()),
        destination_port: Some(3000),
        protocol,
    }
}

pub fn sample_tcp_connection_2(protocol: String) -> AppGuardTcpConnection {
    AppGuardTcpConnection {
        source_ip: Some("8.8.8.8".to_owned()),
        source_port: Some(443),
        destination_ip: Some("::1".to_owned()),
        destination_port: Some(54321),
        protocol,
    }
}

#[allow(dead_code)]
pub struct StoredTcpConnection {
    _id: u32,
    _timestamp: DateTime<Utc>,
    pub appguard_tcp_connection: AppGuardTcpConnection,
}

#[allow(dead_code)]
pub fn retrieve_stored_tcp_connections(conn: &Connection) -> Vec<StoredTcpConnection> {
    let table_name = DbTable::TcpConnection.to_str();
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM {table_name}"))
        .unwrap();
    let query_result = stmt
        .query_map([], |row| {
            let timestamp_string: String = row.get(1)?;
            let connection = AppGuardTcpConnection {
                source_ip: row.get(2).ok(),
                source_port: row.get(3).ok(),
                destination_ip: row.get(4).ok(),
                destination_port: row.get(5).ok(),
                protocol: row.get(6)?,
            };
            Ok(StoredTcpConnection {
                _id: row.get(0)?,
                _timestamp: DateTime::from(
                    DateTime::parse_from_rfc3339(&timestamp_string).unwrap(),
                ),
                appguard_tcp_connection: connection,
            })
        })
        .unwrap();

    let mut connections = Vec::new();
    for row in query_result {
        connections.push(row.unwrap());
    }
    connections
}
