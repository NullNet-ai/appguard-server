use crate::db::store::store::DatastoreWrapper;
use crate::db::tables::DbTable;
use crate::firewall::firewall::FirewallResult;
use crate::helpers::authenticate;
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo, Authentication,
};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use std::sync::{Arc, Mutex};

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
                // todo: assert store unique IP info
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

#[derive(Default)]
pub struct EntryIds {
    pub tcp_connection: Arc<Mutex<u64>>,
    pub http_request: Arc<Mutex<u64>>,
    pub http_response: Arc<Mutex<u64>>,
    pub smtp_request: Arc<Mutex<u64>>,
    pub smtp_response: Arc<Mutex<u64>>,
}

impl EntryIds {
    pub fn get_next(&self, table: DbTable) -> Result<u64, Error> {
        let mut id = match table {
            DbTable::TcpConnection => &self.tcp_connection,
            DbTable::HttpRequest => &self.http_request,
            DbTable::HttpResponse => &self.http_response,
            DbTable::SmtpRequest => &self.smtp_request,
            DbTable::SmtpResponse => &self.smtp_response,
            DbTable::IpInfo => return Err("Not applicable").handle_err(location!()),
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
        let table_ids = EntryIds::default();
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).unwrap(), 2);
        assert_eq!(table_ids.get_next(DbTable::HttpRequest).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::HttpResponse).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::SmtpRequest).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::SmtpResponse).unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).unwrap(), 3);
        assert_eq!(table_ids.get_next(DbTable::SmtpResponse).unwrap(), 2);
        assert!(table_ids.get_next(DbTable::IpInfo).is_err());
    }
}
