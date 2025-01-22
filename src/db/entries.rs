use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::constants::SQLITE_PATH;
use crate::db::store::store::{StoreUnique, StoreWithDetails, StoreWithId};
use crate::error::Error;
use crate::firewall::firewall::FirewallResult;
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
};

pub enum DbEntry {
    HttpRequest((AppGuardHttpRequest, DbDetails)),
    HttpResponse((AppGuardHttpResponse, DbDetails)),
    SmtpRequest((AppGuardSmtpRequest, DbDetails)),
    SmtpResponse((AppGuardSmtpResponse, DbDetails)),
    IpInfo(AppGuardIpInfo),
    TcpConnection((AppGuardTcpConnection, u64)),
}

impl DbEntry {
    pub fn store(&self, conn: &Arc<Mutex<Connection>>) -> Result<(), Error> {
        match self {
            DbEntry::HttpRequest((e, d)) => {
                e.store_with_details(conn, d)?;
                log::info!("HTTP request #{} stored at {}", d.id, SQLITE_PATH.as_str());
            }
            DbEntry::HttpResponse((e, d)) => {
                e.store_with_details(conn, d)?;
                log::info!("HTTP response #{} stored at {}", d.id, SQLITE_PATH.as_str());
            }
            DbEntry::SmtpRequest((e, d)) => {
                e.store_with_details(conn, d)?;
                log::info!("SMTP request #{} stored at {}", d.id, SQLITE_PATH.as_str());
            }
            DbEntry::SmtpResponse((e, d)) => {
                e.store_with_details(conn, d)?;
                log::info!("SMTP response #{} stored at {}", d.id, SQLITE_PATH.as_str());
            }
            DbEntry::IpInfo(e) => {
                if let Some(id) = e.store_unique(conn)? {
                    log::info!("IP info #{id} stored at {}", SQLITE_PATH.as_str());
                }
            }
            DbEntry::TcpConnection((e, id)) => {
                e.store_with_id(conn, id)?;
                log::info!("TCP connection #{id} stored at {}", SQLITE_PATH.as_str());
            }
        }
        Ok(())
    }
}

pub struct DbDetails {
    pub id: u64,
    pub fw_res: FirewallResult,
    pub ip: String,
    pub tcp_id: u64,
    pub response_time: Option<u64>,
}

impl DbDetails {
    pub fn new(
        id: u64,
        fw_res: FirewallResult,
        tcp_info: &Option<AppGuardTcpInfo>,
        response_time: Option<u64>,
    ) -> Self {
        Self {
            id,
            fw_res,
            ip: tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .connection
                .as_ref()
                .unwrap_or(&AppGuardTcpConnection::default())
                .source_ip
                .as_ref()
                .unwrap_or(&String::default())
                .to_owned(),
            tcp_id: tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .tcp_id,
            response_time,
        }
    }
}
