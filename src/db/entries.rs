use crate::db::store::store::DatastoreWrapper;
use crate::db::tables::DbTable;
use crate::firewall::firewall::FirewallResult;
use crate::helpers::authenticate;
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo, Authentication,
};
use nullnet_liberror::Error;

pub enum DbEntry {
    HttpRequest((AppGuardHttpRequest, DbDetails)),
    HttpResponse((AppGuardHttpResponse, DbDetails)),
    SmtpRequest((AppGuardSmtpRequest, DbDetails)),
    SmtpResponse((AppGuardSmtpResponse, DbDetails)),
    IpInfo((AppGuardIpInfo, Option<Authentication>)),
    TcpConnection((AppGuardTcpConnection, u64)),
}

impl DbEntry {
    pub async fn store(&self, ds: &DatastoreWrapper) -> Result<(), Error> {
        let (token, _) = authenticate(self.get_auth())?;

        match self {
            DbEntry::HttpRequest((_, d)) => {
                let _ = &mut ds.clone().insert(self, token.as_str()).await?;
                log::info!("HTTP request #{} inserted in datastore", d.id);
            }
            DbEntry::HttpResponse((_, d)) => {
                let _ = &mut ds.clone().insert(self, token.as_str()).await?;
                log::info!("HTTP response #{} inserted in datastore", d.id);
            }
            DbEntry::SmtpRequest((_, d)) => {
                let _ = &mut ds.clone().insert(self, token.as_str()).await?;
                log::info!("SMTP request #{} inserted in datastore", d.id);
            }
            DbEntry::SmtpResponse((_, d)) => {
                let _ = &mut ds.clone().insert(self, token.as_str()).await?;
                log::info!("SMTP response #{} inserted in datastore", d.id);
            }
            DbEntry::IpInfo((i, _)) => {
                let _ = &mut ds.clone().insert(self, token.as_str()).await?;
                // todo: assert store unique!
                log::info!("IP info for {} inserted in datastore", i.ip);
            }
            DbEntry::TcpConnection((_, id)) => {
                let _ = &mut ds.clone().insert(self, token.as_str()).await?;
                log::info!("TCP connection #{id} stored in datastore");
            }
        }
        Ok(())
    }

    pub(crate) fn to_json(&self) -> Result<String, Error> {
        match self {
            DbEntry::HttpRequest((r, d)) => r.to_json(d),
            DbEntry::HttpResponse((r, d)) => r.to_json(d),
            DbEntry::SmtpRequest((r, d)) => r.to_json(d),
            DbEntry::SmtpResponse((r, d)) => r.to_json(d),
            DbEntry::IpInfo((i, _)) => Ok(i.to_json()),
            DbEntry::TcpConnection((c, _)) => Ok(c.to_json()),
        }
    }

    pub(crate) fn table(&self) -> DbTable {
        match self {
            DbEntry::HttpRequest(_) => DbTable::HttpRequest,
            DbEntry::HttpResponse(_) => DbTable::HttpResponse,
            DbEntry::SmtpRequest(_) => DbTable::SmtpRequest,
            DbEntry::SmtpResponse(_) => DbTable::SmtpResponse,
            DbEntry::IpInfo(_) => DbTable::IpInfo,
            DbEntry::TcpConnection(_) => DbTable::TcpConnection,
        }
    }

    fn get_auth(&self) -> Option<Authentication> {
        match self {
            DbEntry::HttpRequest((r, _)) => r.auth.clone(),
            DbEntry::HttpResponse((r, _)) => r.auth.clone(),
            DbEntry::SmtpRequest((r, _)) => r.auth.clone(),
            DbEntry::SmtpResponse((r, _)) => r.auth.clone(),
            DbEntry::IpInfo((_, a)) => a.clone(),
            DbEntry::TcpConnection((c, _)) => c.auth.clone(),
        }
    }
}

pub struct DbDetails {
    pub id: u64,
    pub fw_res: FirewallResult,
    pub ip: String,
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
            response_time,
        }
    }
}
