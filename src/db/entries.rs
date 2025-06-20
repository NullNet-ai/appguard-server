use crate::db::datastore_wrapper::DatastoreWrapper;
use crate::db::tables::DbTable;
use crate::firewall::denied_ip::DeniedIp;
use crate::firewall::firewall::{Firewall, FirewallResult};
use crate::helpers::{authenticate, get_timestamp_string};
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use std::fmt::Write;
use std::sync::Arc;
use tokio::sync::Mutex;

pub enum DbEntry {
    HttpRequest((AppGuardHttpRequest, DbDetails)),
    HttpResponse((AppGuardHttpResponse, DbDetails)),
    SmtpRequest((AppGuardSmtpRequest, DbDetails)),
    SmtpResponse((AppGuardSmtpResponse, DbDetails)),
    IpInfo((AppGuardIpInfo, String)),
    TcpConnection((AppGuardTcpConnection, u64)),
    Blacklist((Vec<String>, String)),
    Firewall((String, Firewall, String)),
    DeniedIp((String, DeniedIp, String)),
}

impl DbEntry {
    pub async fn store(&self, mut ds: DatastoreWrapper) -> Result<(), Error> {
        let (token, _) = authenticate(self.get_token())?;

        match self {
            DbEntry::HttpRequest((_, d)) => {
                let _ = ds.insert(self, token.as_str()).await?;
                log::info!("HTTP request #{} inserted in datastore", d.id);
            }
            DbEntry::HttpResponse((_, d)) => {
                let _ = ds.insert(self, token.as_str()).await?;
                log::info!("HTTP response #{} inserted in datastore", d.id);
            }
            DbEntry::SmtpRequest((_, d)) => {
                let _ = ds.insert(self, token.as_str()).await?;
                log::info!("SMTP request #{} inserted in datastore", d.id);
            }
            DbEntry::SmtpResponse((_, d)) => {
                let _ = ds.insert(self, token.as_str()).await?;
                log::info!("SMTP response #{} inserted in datastore", d.id);
            }
            DbEntry::IpInfo((i, _)) => {
                let _ = ds
                    .upsert(self, vec!["ip".to_string()], token.as_str())
                    .await?;
                log::info!("IP info for {} inserted in datastore", i.ip);
            }
            DbEntry::TcpConnection((_, id)) => {
                let _ = ds.insert(self, token.as_str()).await?;
                log::info!("TCP connection #{id} inserted in datastore");
            }
            DbEntry::Blacklist(_) => {
                ds.delete_old_entries(
                    DbTable::Blacklist,
                    get_timestamp_string().as_str(),
                    token.as_str(),
                )
                .await?;
                let _ = ds.insert_batch(self, token.as_str()).await?;
            }
            DbEntry::Firewall(_) => {
                let _ = ds
                    .upsert(self, vec!["app_id".to_string()], token.as_str())
                    .await?;
                log::info!("Firewall inserted in datastore");
            }
            DbEntry::DeniedIp((_, denied_ip, _)) => {
                let _ = ds.insert(self, token.as_str()).await?;
                log::info!(
                    "Denied IP inserted in datastore: {} {:?}",
                    denied_ip.ip,
                    denied_ip.deny_reasons
                );
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
            DbEntry::Blacklist((v, _)) => {
                let mut json = "[".to_string();
                for ip in v {
                    let _ = write!(json, "{{\"ip\":\"{ip}\"}},");
                }
                json.pop();
                json.push(']');
                Ok(json)
            }
            DbEntry::Firewall((app_id, f, _)) => f.to_json(app_id),
            DbEntry::DeniedIp((app_id, denied_ip, _)) => denied_ip.to_json(app_id),
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
            DbEntry::Blacklist(_) => DbTable::Blacklist,
            DbEntry::Firewall(_) => DbTable::Firewall,
            DbEntry::DeniedIp(_) => DbTable::DeniedIp,
        }
    }

    fn get_token(&self) -> String {
        match self {
            DbEntry::HttpRequest((r, _)) => r.token.clone(),
            DbEntry::HttpResponse((r, _)) => r.token.clone(),
            DbEntry::SmtpRequest((r, _)) => r.token.clone(),
            DbEntry::SmtpResponse((r, _)) => r.token.clone(),
            DbEntry::TcpConnection((c, _)) => c.token.clone(),
            DbEntry::IpInfo((_, a))
            | DbEntry::Blacklist((_, a))
            | DbEntry::Firewall((_, _, a))
            | DbEntry::DeniedIp((_, _, a)) => a.clone(),
        }
    }
}

pub struct DbDetails {
    pub id: u64,
    pub fw_res: FirewallResult,
    pub ip: String,
    pub response_time: Option<u32>,
}

impl DbDetails {
    pub fn new(
        id: u64,
        fw_res: FirewallResult,
        tcp_info: Option<&AppGuardTcpInfo>,
        response_time: Option<u32>,
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
    pub async fn get_next(&self, table: DbTable) -> Result<u64, Error> {
        let mut id = match table {
            DbTable::TcpConnection => &self.tcp_connection,
            DbTable::HttpRequest => &self.http_request,
            DbTable::HttpResponse => &self.http_response,
            DbTable::SmtpRequest => &self.smtp_request,
            DbTable::SmtpResponse => &self.smtp_response,
            DbTable::IpInfo | DbTable::Blacklist | DbTable::Firewall | DbTable::DeniedIp => {
                return Err("Not applicable").handle_err(location!())
            }
        }
        .lock()
        .await;
        *id += 1;
        Ok(*id)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_table_ids_get_next() {
        let table_ids = EntryIds::default();
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).await.unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).await.unwrap(), 2);
        assert_eq!(table_ids.get_next(DbTable::HttpRequest).await.unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::HttpResponse).await.unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::SmtpRequest).await.unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::SmtpResponse).await.unwrap(), 1);
        assert_eq!(table_ids.get_next(DbTable::TcpConnection).await.unwrap(), 3);
        assert_eq!(table_ids.get_next(DbTable::SmtpResponse).await.unwrap(), 2);
        assert!(table_ids.get_next(DbTable::IpInfo).await.is_err());
        assert!(table_ids.get_next(DbTable::Firewall).await.is_err());
    }
}
