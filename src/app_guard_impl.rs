use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::mpsc::Sender;
use std::sync::{mpsc, Arc, Condvar, Mutex, RwLock};
use std::time::Instant;
use std::{process, thread};

use indexmap::IndexMap;
use tokio::runtime::Handle;
use tonic::{Request, Response, Status};

use crate::ai::entries::AiEntry;
use crate::ai::helpers::{ai_http_request, ai_interface};
use crate::config::{watch_config, Config};
use crate::constants::{ADDR, AI_PORT, BLACKLIST_PATH, CONFIG_FILE, FIREWALL_FILE, SQLITE_PATH};
use crate::db::entries::{DbDetails, DbEntry};
use crate::db::helpers::{
    create_blacklist_tables, create_db_tables_and_views, delete_old_entries, get_initial_table_ids,
    get_ipinfo_from_db, store_entries,
};
use crate::db::tables::{DbTable, TableIds};
use crate::fetch_data::fetch_ip_data;
use crate::firewall::firewall::{watch_firewall, Firewall};
use crate::ip_info::ip_info_handler;
use crate::proto::aiguard::ai_guard_client::AiGuardClient;
use crate::proto::appguard::app_guard_server::AppGuard;
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardResponse,
    AppGuardSmtpRequest, AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
    AppGuardTcpResponse, FirewallPolicy,
};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libipinfo::IpInfoHandler;

pub struct AppGuardImpl {
    config_pair: Arc<(Mutex<Config>, Condvar)>,
    conn: Arc<Mutex<rusqlite::Connection>>,
    table_ids: TableIds,
    unanswered_connections: Arc<Mutex<HashMap<u64, Instant>>>,
    firewall: Arc<RwLock<Firewall>>,
    ip_info_cache: Arc<Mutex<IndexMap<String, AppGuardIpInfo>>>,
    ip_info_handler: IpInfoHandler,
    blacklist_conn: Arc<Mutex<rusqlite::Connection>>,
    tx_store: Sender<DbEntry>,
    tx_ai: Sender<AiEntry>,
}

#[cfg(not(test))]
impl Drop for AppGuardImpl {
    fn drop(&mut self) {
        terminate_app_guard(1).expect("Unable to gracefully terminate server");
    }
}

pub fn terminate_app_guard(exit_code: i32) -> Result<(), Error> {
    log::info!("Shutting down AppGuard server...");

    // cleanup

    log::info!("Exiting with code {exit_code}");
    process::exit(exit_code);
}

impl AppGuardImpl {
    pub async fn new() -> Result<AppGuardImpl, Error> {
        let conn = Arc::new(Mutex::new(
            rusqlite::Connection::open(SQLITE_PATH.as_str()).handle_err(location!())?,
        ));
        let conn_2 = conn.clone();
        let conn_3 = conn.clone();
        let conn_4 = conn.clone();

        log::info!("Opened SQLite database at {}", SQLITE_PATH.as_str());

        let blacklist_conn = Arc::new(Mutex::new(
            rusqlite::Connection::open(BLACKLIST_PATH).handle_err(location!())?,
        ));
        let blacklist_conn_2 = blacklist_conn.clone();

        log::info!("Opened blacklist SQLite database at {BLACKLIST_PATH}");

        create_db_tables_and_views(&conn)?;
        create_blacklist_tables(&blacklist_conn)?;

        let table_ids = get_initial_table_ids(&conn)?;

        let config = Config::from_file(CONFIG_FILE).unwrap_or_default();
        log::info!(
            "Loaded AppGuard initial configuration: {}",
            serde_json::to_string(&config).unwrap_or_default()
        );
        let config_pair = Arc::new((Mutex::new(config), Condvar::new()));
        let config_pair_2 = config_pair.clone();
        let config_pair_3 = config_pair.clone();

        let firewall = Firewall::load_from_infix(FIREWALL_FILE).unwrap_or_default();
        log::info!(
            "Loaded firewall: {}",
            serde_json::to_string(&firewall).unwrap_or_default()
        );
        let firewall_shared = Arc::new(RwLock::new(firewall));
        let firewall_shared_2 = firewall_shared.clone();

        let ip_info_handler = ip_info_handler();

        let ip_info_cache = Arc::new(Mutex::new(IndexMap::new()));
        let ip_info_cache_2 = ip_info_cache.clone();

        let (tx_store, rx_store) = mpsc::channel();

        let (tx_ai, rx_ai) = mpsc::channel();

        if cfg!(all(not(test), not(feature = "no-ai"))) {
            let ai_client = AiGuardClient::connect(format!("http://{ADDR}:{AI_PORT}"))
                .await
                .handle_err(location!())?;
            log::info!("Connected to AiGuard server at {ADDR}:{AI_PORT}");

            let rt_handle = Handle::current();
            thread::spawn(move || {
                ai_interface(&conn_4, &rx_ai, &ai_client, &rt_handle);
            });
        }

        tokio::spawn(async move {
            fetch_ip_data(&blacklist_conn_2).await;
        });

        thread::spawn(move || {
            watch_config(&config_pair_2).expect("Watch configuration thread failed");
        });

        thread::spawn(move || {
            watch_firewall(&firewall_shared_2).expect("Watch firewall thread failed");
        });

        thread::spawn(move || {
            delete_old_entries(&config_pair_3, &conn_2, &ip_info_cache_2)
                .expect("Delete old entries thread failed");
        });

        thread::spawn(move || {
            store_entries(&conn_3, &rx_store);
        });

        Ok(AppGuardImpl {
            config_pair,
            conn,
            table_ids,
            unanswered_connections: Arc::new(Mutex::new(HashMap::new())),
            firewall: firewall_shared,
            ip_info_cache,
            ip_info_handler,
            blacklist_conn,
            tx_store,
            tx_ai,
        })
    }

    fn config_log_requests(&self) -> Result<bool, Error> {
        Ok(self
            .config_pair
            .0
            .lock()
            .handle_err(location!())?
            .log_requests)
    }

    fn config_log_responses(&self) -> Result<bool, Error> {
        Ok(self
            .config_pair
            .0
            .lock()
            .handle_err(location!())?
            .log_responses)
    }

    fn config_ip_info_cache_size(&self) -> Result<usize, Error> {
        Ok(self
            .config_pair
            .0
            .lock()
            .handle_err(location!())?
            .ip_info_cache_size)
    }

    fn refresh_ip_info_cache(&self, ip: &str, ip_info: &AppGuardIpInfo) -> Result<(), Error> {
        let cache_size = self.config_ip_info_cache_size()?;
        let mut ip_info_cache = self.ip_info_cache.lock().handle_err(location!())?;
        ip_info_cache.shift_insert(0, ip.to_string(), ip_info.clone());
        while ip_info_cache.len() > cache_size {
            ip_info_cache.pop();
        }
        Ok(())
    }

    fn compute_response_time(&self, tcp_id: u64) -> Option<u64> {
        if let Some(request_instant) = self
            .unanswered_connections
            .lock()
            .handle_err(location!())
            .ok()?
            .remove(&tcp_id)
        {
            u64::try_from(request_instant.elapsed().as_millis())
                .handle_err(location!())
                .ok()
        } else {
            log::warn!("Connection ID {tcp_id} not found (cannot compute response time)");
            None
        }
    }

    async fn handle_tcp_connection_impl(
        &self,
        req: Request<AppGuardTcpConnection>,
    ) -> Result<AppGuardTcpInfo, Error> {
        let tcp_id = self.table_ids.get_next(DbTable::TcpConnection)?;

        // start measuring the time it takes to respond to this connection
        self.unanswered_connections
            .lock()
            .handle_err(location!())?
            .insert(tcp_id, Instant::now());

        log::info!("TCP connection #{tcp_id}: {:?}", req.get_ref());

        self.tx_store
            .send(DbEntry::TcpConnection((req.get_ref().clone(), tcp_id)))
            .handle_err(location!())?;

        let mut ip_info = AppGuardIpInfo::default();
        if let Some(ip) = &req.get_ref().source_ip {
            log::info!("Searching IP information for {ip}");
            let info_opt = self
                .ip_info_cache
                .lock()
                .handle_err(location!())?
                .get(ip)
                .cloned();
            ip_info = if let Some(info) = info_opt {
                log::info!("IP information for {ip} already in cache");
                info
            } else if let Ok(Some(info)) = get_ipinfo_from_db(ip, &self.conn) {
                log::info!("IP information for {ip} already in database");
                info
            } else {
                ip_info =
                    AppGuardIpInfo::lookup(ip, &self.ip_info_handler, &self.blacklist_conn).await?;
                log::info!("Looked up new IP information: {ip_info:?}");
                self.tx_store
                    .send(DbEntry::IpInfo(ip_info.clone()))
                    .handle_err(location!())?;
                ip_info
            };
            // refresh the IP info cache
            self.refresh_ip_info_cache(ip, &ip_info)?;
        } else {
            log::warn!(
                "The TCP connection is missing a source IP address (cannot lookup IP information)"
            );
        }

        let tcp_info = AppGuardTcpInfo {
            connection: Some(req.into_inner()),
            ip_info: Some(ip_info),
            tcp_id,
        };

        Ok(tcp_info)
    }

    fn handle_http_request_impl(
        &self,
        req: Request<AppGuardHttpRequest>,
    ) -> Result<FirewallPolicy, Error> {
        let fw_res = self
            .firewall
            .read()
            .handle_err(location!())?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        log::info!("***{policy:?}*** HTTP request: {:?}", req.get_ref());

        if self.config_log_requests()? {
            let id = self.table_ids.get_next(DbTable::HttpRequest)?;
            let details = DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), None);
            self.tx_store
                .send(DbEntry::HttpRequest((req.get_ref().clone(), details)))
                .handle_err(location!())?;

            if cfg!(all(not(test), not(feature = "no-ai"))) {
                let ai_http_request = ai_http_request(req.into_inner());
                self.tx_ai
                    .send(AiEntry::HttpRequest((ai_http_request, id)))
                    .handle_err(location!())?;
            }
        }

        Ok(policy)
    }

    fn handle_http_response_impl(
        &self,
        req: Request<AppGuardHttpResponse>,
    ) -> Result<FirewallPolicy, Error> {
        let fw_res = self
            .firewall
            .read()
            .handle_err(location!())?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        log::info!("***{policy:?}*** HTTP response: {:?}", req.get_ref());

        if self.config_log_responses()? {
            let tcp_id = req
                .get_ref()
                .tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .tcp_id;
            let response_time = self.compute_response_time(tcp_id);
            let id = self.table_ids.get_next(DbTable::HttpResponse)?;

            let details =
                DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), response_time);
            self.tx_store
                .send(DbEntry::HttpResponse((req.into_inner(), details)))
                .handle_err(location!())?;
        }

        Ok(policy)
    }

    fn handle_smtp_request_impl(
        &self,
        req: Request<AppGuardSmtpRequest>,
    ) -> Result<FirewallPolicy, Error> {
        let fw_res = self
            .firewall
            .read()
            .handle_err(location!())?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        log::info!("***{policy:?}*** SMTP request: {:?}", req.get_ref());

        if self.config_log_requests()? {
            let id = self.table_ids.get_next(DbTable::SmtpRequest)?;
            let details = DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), None);
            self.tx_store
                .send(DbEntry::SmtpRequest((req.into_inner(), details)))
                .handle_err(location!())?;
        }

        Ok(policy)
    }

    fn handle_smtp_response_impl(
        &self,
        req: Request<AppGuardSmtpResponse>,
    ) -> Result<FirewallPolicy, Error> {
        let fw_res = self
            .firewall
            .read()
            .handle_err(location!())?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        log::info!("***{policy:?}*** SMTP response: {:?}", req.get_ref());

        if self.config_log_responses()? {
            let tcp_id = req
                .get_ref()
                .tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .tcp_id;
            let response_time = self.compute_response_time(tcp_id);
            let id = self.table_ids.get_next(DbTable::SmtpResponse)?;

            let details =
                DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), response_time);
            self.tx_store
                .send(DbEntry::SmtpResponse((req.into_inner(), details)))
                .handle_err(location!())?;
        }

        Ok(policy)
    }
}

#[tonic::async_trait]
impl AppGuard for AppGuardImpl {
    async fn handle_tcp_connection(
        &self,
        req: Request<AppGuardTcpConnection>,
    ) -> Result<Response<AppGuardTcpResponse>, Status> {
        self.handle_tcp_connection_impl(req)
            .await
            .map(|tcp_info| {
                Response::new(AppGuardTcpResponse {
                    tcp_info: Some(tcp_info),
                })
            })
            .map_err(|err| {
                log::error!("Error handling TCP connection");
                Status::internal(err.to_str())
            })
    }

    async fn handle_http_request(
        &self,
        req: Request<AppGuardHttpRequest>,
    ) -> Result<Response<AppGuardResponse>, Status> {
        self.handle_http_request_impl(req)
            .map(|policy| {
                Response::new(AppGuardResponse {
                    policy: policy.into(),
                })
            })
            .map_err(|err| {
                log::error!("Error handling HTTP request");
                Status::internal(err.to_str())
            })
    }

    async fn handle_http_response(
        &self,
        req: Request<AppGuardHttpResponse>,
    ) -> Result<Response<AppGuardResponse>, Status> {
        self.handle_http_response_impl(req)
            .map(|policy| {
                Response::new(AppGuardResponse {
                    policy: policy.into(),
                })
            })
            .map_err(|err| {
                log::error!("Error handling HTTP response");
                Status::internal(err.to_str())
            })
    }

    async fn handle_smtp_request(
        &self,
        req: Request<AppGuardSmtpRequest>,
    ) -> Result<Response<AppGuardResponse>, Status> {
        self.handle_smtp_request_impl(req)
            .map(|policy| {
                Response::new(AppGuardResponse {
                    policy: policy.into(),
                })
            })
            .map_err(|err| {
                log::error!("Error handling SMTP request");
                Status::internal(err.to_str())
            })
    }

    async fn handle_smtp_response(
        &self,
        req: Request<AppGuardSmtpResponse>,
    ) -> Result<Response<AppGuardResponse>, Status> {
        self.handle_smtp_response_impl(req)
            .map(|policy| {
                Response::new(AppGuardResponse {
                    policy: policy.into(),
                })
            })
            .map_err(|err| {
                log::error!("Error handling SMTP response");
                Status::internal(err.to_str())
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serial_test::serial;

    use super::*;

    fn write_config_to_file(config: &Config) {
        let json = serde_json::to_string(&config).unwrap();
        std::fs::write(CONFIG_FILE, json).unwrap();

        assert_eq!(Config::from_file(CONFIG_FILE).unwrap(), *config);
    }

    fn tcp_connection_with_source_ip(ip: &str) -> AppGuardTcpConnection {
        AppGuardTcpConnection {
            source_ip: Some(ip.to_owned()),
            ..Default::default()
        }
    }

    fn app_guard_ip_info_with_source_ip(ip: &str) -> AppGuardIpInfo {
        AppGuardIpInfo {
            ip: ip.to_owned(),
            ..Default::default()
        }
    }

    async fn handle_tcp_connection(app: &AppGuardImpl, ip: &str) {
        let tcp_connection = tcp_connection_with_source_ip(ip);
        app.handle_tcp_connection_impl(Request::new(tcp_connection))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_ip_info_cache() {
        let app = AppGuardImpl::new().await.unwrap();
        let mut map = IndexMap::new();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        write_config_to_file(&Config {
            ip_info_cache_size: 3,
            ..Default::default()
        });
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        handle_tcp_connection(&app, "::1").await;
        map.insert("::1".to_owned(), app_guard_ip_info_with_source_ip("::1"));
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        handle_tcp_connection(&app, "::2").await;
        map.shift_insert(0, "::2".to_owned(), app_guard_ip_info_with_source_ip("::2"));
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        handle_tcp_connection(&app, "::3").await;
        map.shift_insert(0, "::3".to_owned(), app_guard_ip_info_with_source_ip("::3"));
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        handle_tcp_connection(&app, "::4").await;
        map.shift_insert(0, "::4".to_owned(), app_guard_ip_info_with_source_ip("::4"));
        map.pop();
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        write_config_to_file(&Config {
            ip_info_cache_size: 1,
            ..Default::default()
        });
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        handle_tcp_connection(&app, "::2").await;
        map.clear();
        map.insert("::2".to_owned(), app_guard_ip_info_with_source_ip("::2"));
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        write_config_to_file(&Config {
            ip_info_cache_size: 0,
            ..Default::default()
        });
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        handle_tcp_connection(&app, "::3").await;
        map.clear();
        assert_eq!(*app.ip_info_cache.lock().unwrap(), map);

        write_config_to_file(&Config::default());
    }
}
