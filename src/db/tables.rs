use std::sync::{Arc, Mutex};

use crate::error::{Error, ErrorHandler, Location};
use crate::location;

#[derive(Copy, Clone)]
pub enum DbTable {
    // main tables
    TcpConnection,
    HttpRequest,
    HttpResponse,
    IpInfo,
    SmtpRequest,
    SmtpResponse,
    // AI tables
    HttpRequestAi,
}

impl DbTable {
    pub const ALL: [DbTable; 7] = [
        DbTable::TcpConnection,
        DbTable::HttpRequest,
        DbTable::HttpResponse,
        DbTable::IpInfo,
        DbTable::SmtpRequest,
        DbTable::SmtpResponse,
        DbTable::HttpRequestAi,
    ];

    pub fn to_str(&self) -> &'static str {
        match self {
            DbTable::TcpConnection => "tcp_connection",
            DbTable::HttpRequest => "http_request",
            DbTable::HttpResponse => "http_response",
            DbTable::IpInfo => "ip_info",
            DbTable::SmtpRequest => "smtp_request",
            DbTable::SmtpResponse => "smtp_response",
            DbTable::HttpRequestAi => "http_request_ai",
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn sql_create(self) -> String {
        let table_name = self.to_str();
        match self {
            DbTable::TcpConnection => format!(
                "
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source TEXT,
                    sport INTEGER,
                    dest TEXT,
                    dport INTEGER,
                    proto TEXT NOT NULL
                );
            "
            ),
            DbTable::HttpRequest => format!(
                "
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    fw_res TEXT NOT NULL,
                    tcp_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    original_url TEXT NOT NULL,
                    user_agent TEXT,
                    headers TEXT NOT NULL,
                    method TEXT NOT NULL,
                    body TEXT,
                    query TEXT NOT NULL,
                    cookies TEXT
                );
            "
            ),
            DbTable::HttpResponse => format!(
                "
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    fw_res TEXT NOT NULL,
                    tcp_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    code INTEGER NOT NULL,
                    headers TEXT NOT NULL,
                    time INTEGER,
                    size INTEGER
                );
            "
            ),
            DbTable::IpInfo => format!(
                "
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    country TEXT,
                    asn TEXT,
                    org TEXT,
                    continent_code TEXT,
                    city TEXT,
                    region TEXT,
                    postal TEXT,
                    timezone TEXT,
                    blacklist INTEGER NOT NULL
                );
            "
            ),
            DbTable::SmtpRequest => format!(
                "
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    fw_res TEXT NOT NULL,
                    tcp_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    user_agent TEXT,
                    headers TEXT NOT NULL,
                    body TEXT
                );
            "
            ),
            DbTable::SmtpResponse => format!(
                "
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    fw_res TEXT NOT NULL,
                    tcp_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    code INTEGER,
                    time INTEGER
                );
            "
            ),
            DbTable::HttpRequestAi => format!(
                "
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ai_res TEXT NOT NULL
                );
            "
            ),
        }
    }
}

#[derive(Default)]
pub struct TableIds {
    pub tcp_connection: Arc<Mutex<u64>>,
    pub http_request: Arc<Mutex<u64>>,
    pub http_response: Arc<Mutex<u64>>,
    pub smtp_request: Arc<Mutex<u64>>,
    pub smtp_response: Arc<Mutex<u64>>,
}

impl TableIds {
    pub fn get_next(&self, table: DbTable) -> Result<u64, Error> {
        let mut id = match table {
            DbTable::TcpConnection => &self.tcp_connection,
            DbTable::HttpRequest => &self.http_request,
            DbTable::HttpResponse => &self.http_response,
            DbTable::SmtpRequest => &self.smtp_request,
            DbTable::SmtpResponse => &self.smtp_response,
            DbTable::IpInfo => {
                return Err("IpInfo table IDs are automatically generated").handle_err(location!())
            }
            DbTable::HttpRequestAi => {
                return Err("AI tables IDs are inherited from the corresponding table")
                    .handle_err(location!())
            }
        }
        .lock()
        .handle_err(location!())?;
        *id += 1;
        Ok(*id)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_table_ids_get_next() {
        let table_ids = TableIds::default();
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).unwrap(), 2);
        assert_eq!(table_ids.get_next(DbTable::HttpRequest).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::HttpResponse).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::SmtpRequest).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::SmtpResponse).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).unwrap(), 3);
        assert_eq!(table_ids.get_next(DbTable::SmtpResponse).unwrap(), 2);
        assert!(table_ids.get_next(DbTable::IpInfo).is_err());
        assert!(table_ids.get_next(DbTable::HttpRequestAi).is_err());
    }
}
