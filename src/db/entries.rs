use crate::constants::SQLITE_PATH;
use crate::db::store::store::{DatastoreWrapper};
use crate::firewall::firewall::FirewallResult;
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
};
use nullnet_liberror::Error;

pub enum DbEntry {
    HttpRequest((AppGuardHttpRequest, DbDetails)),
    HttpResponse((AppGuardHttpResponse, DbDetails)),
    SmtpRequest((AppGuardSmtpRequest, DbDetails)),
    SmtpResponse((AppGuardSmtpResponse, DbDetails)),
    IpInfo(AppGuardIpInfo),
    TcpConnection((AppGuardTcpConnection, u64)),
}

impl DbEntry {
    pub async fn store(&self, ds: &DatastoreWrapper) -> Result<(), Error> {
        match self {
            DbEntry::HttpRequest((_, d)) => {
                &mut ds.clone().insert(&self, "").await?;
                log::info!("HTTP request #{} inserted in datastore", d.id);
            }
            DbEntry::HttpResponse((_, d)) => {
                &mut ds.clone().insert(&self, "").await?;
                log::info!("HTTP response #{} stored at {}", d.id, SQLITE_PATH.as_str());
            }
            DbEntry::SmtpRequest((_, d)) => {
                &mut ds.clone().insert(&self, "").await?;
                log::info!("SMTP request #{} stored at {}", d.id, SQLITE_PATH.as_str());
            }
            DbEntry::SmtpResponse((_, d)) => {
                &mut ds.clone().insert(&self, "").await?;
                log::info!("SMTP response #{} stored at {}", d.id, SQLITE_PATH.as_str());
            }
            DbEntry::IpInfo(_) => {
                &mut ds.clone().insert(&self, "").await?;
                // todo: assert store unique!
                // log::info!("IP info #{id} stored at {}", SQLITE_PATH.as_str());
            }
            DbEntry::TcpConnection((_, id)) => {
                &mut ds.clone().insert(&self, "").await?;
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
        tcp_info: Option<&AppGuardTcpInfo>,
        response_time: Option<u64>,
    ) -> Self {
        Self {
            id,
            fw_res,
            ip: tcp_info
                .unwrap_or(&AppGuardTcpInfo::default())
                .connection
                .as_ref()
                .unwrap_or(&AppGuardTcpConnection::default())
                .source_ip
                .as_ref()
                .unwrap_or(&String::default())
                .to_owned(),
            tcp_id: tcp_info.unwrap_or(&AppGuardTcpInfo::default()).tcp_id,
            response_time,
        }
    }
}
