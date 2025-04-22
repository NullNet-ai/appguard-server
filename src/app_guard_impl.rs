use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use std::{process, thread};

use indexmap::IndexMap;
use tonic::{Request, Response, Status};

use crate::auth_handler::AuthHandler;
use crate::config::{watch_config, Config};
use crate::constants::CONFIG_FILE;
use crate::db::datastore_wrapper::DatastoreWrapper;
use crate::db::entries::{DbDetails, DbEntry, EntryIds};
use crate::db::helpers::{delete_old_entries, store_entries};
use crate::db::tables::DbTable;
use crate::fetch_data::fetch_ip_data;
use crate::firewall::firewall::Firewall;
use crate::helpers::authenticate;
use crate::ip_info::ip_info_handler;
use crate::proto::appguard::app_guard_server::AppGuard;
use crate::proto::appguard::{
    AppGuardFirewall, AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardResponse,
    AppGuardSmtpRequest, AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
    AppGuardTcpResponse, DeviceStatus, Empty, FirewallPolicy, HeartbeatRequest, HeartbeatResponse,
};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libipinfo::IpInfoHandler;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;

pub struct AppGuardImpl {
    config_pair: Arc<(Mutex<Config>, Condvar)>,
    ds: DatastoreWrapper,
    entry_ids: EntryIds,
    unanswered_connections: Arc<Mutex<HashMap<u64, Instant>>>,
    // firewall: Arc<RwLock<Firewall>>,
    firewalls: HashMap<String, Firewall>,
    ip_info_cache: Arc<Mutex<IndexMap<String, AppGuardIpInfo>>>,
    ip_info_handler: IpInfoHandler,
    tx_store: UnboundedSender<DbEntry>,
    // tx_ai: Sender<AiEntry>,
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
        let ds = DatastoreWrapper::new().await?;
        let ds_2 = ds.clone();
        let ds_3 = ds.clone();
        let ds_4 = ds.clone();

        log::info!("Connected to Datastore");

        let config = Config::from_file(CONFIG_FILE).unwrap_or_default();
        log::info!(
            "Loaded AppGuard initial configuration: {}",
            serde_json::to_string(&config).unwrap_or_default()
        );
        let config_pair = Arc::new((Mutex::new(config), Condvar::new()));
        let config_pair_2 = config_pair.clone();
        let config_pair_3 = config_pair.clone();

        // let firewall = Firewall::load_from_infix(FIREWALL_FILE).unwrap_or_default();
        // log::info!(
        //     "Loaded firewall: {}",
        //     serde_json::to_string(&firewall).unwrap_or_default()
        // );
        // let firewall_shared = Arc::new(RwLock::new(firewall));
        // let firewall_shared_2 = firewall_shared.clone();

        let ip_info_handler = ip_info_handler();

        let ip_info_cache = Arc::new(Mutex::new(IndexMap::new()));
        let ip_info_cache_2 = ip_info_cache.clone();

        let (tx_store, mut rx_store) = mpsc::unbounded_channel();

        // let (tx_ai, rx_ai) = mpsc::channel();
        //
        // if cfg!(all(not(test), not(feature = "no-ai"))) {
        //     let ai_client = AiGuardClient::connect(format!("http://{ADDR}:{AI_PORT}"))
        //         .await
        //         .handle_err(location!())?;
        //     log::info!("Connected to AiGuard server at {ADDR}:{AI_PORT}");
        //
        //     let rt_handle = Handle::current();
        //     thread::spawn(move || {
        //         ai_interface(&ds_4, &rx_ai, &ai_client, &rt_handle);
        //     });
        // }

        tokio::spawn(async move {
            fetch_ip_data(ds_4).await;
        });

        thread::spawn(move || {
            watch_config(&config_pair_2).expect("Watch configuration thread failed");
        });

        // thread::spawn(move || {
        //     watch_firewall(&firewall_shared_2).expect("Watch firewall thread failed");
        // });

        tokio::spawn(async move {
            delete_old_entries(&config_pair_3, &ds_2, &ip_info_cache_2)
                .await
                .expect("Delete old entries thread failed");
        });

        tokio::spawn(async move {
            store_entries(&ds_3, &mut rx_store).await;
        });

        Ok(AppGuardImpl {
            config_pair,
            ds,
            entry_ids: EntryIds::default(),
            unanswered_connections: Arc::new(Mutex::new(HashMap::new())),
            // firewall: firewall_shared,
            firewalls: HashMap::new(),
            ip_info_cache,
            ip_info_handler,
            tx_store,
            // tx_ai,
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

    fn compute_response_time(&self, tcp_id: u64) -> Option<u32> {
        if let Some(request_instant) = self
            .unanswered_connections
            .lock()
            .handle_err(location!())
            .ok()?
            .remove(&tcp_id)
        {
            u32::try_from(request_instant.elapsed().as_millis())
                .handle_err(location!())
                .ok()
        } else {
            log::warn!("Connection ID {tcp_id} not found (cannot compute response time)");
            None
        }
    }

    async fn get_client_firewall(&self, token: String) -> Result<Firewall, Error> {
        if let Some(fw) = self.firewalls.get(&token).cloned() {
            Ok(fw)
        } else {
            // get the firewall from the datastore
            self.ds.clone().get_firewall(&token).await
        }
    }

    pub(crate) async fn heartbeat_impl(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<<AppGuardImpl as AppGuard>::HeartbeatStream>, Error> {
        let datastore = self.ds.clone();
        let remote_address = request
            .remote_addr()
            .map_or_else(|| "Unknown".to_string(), |addr| addr.ip().to_string());

        let authenticate_request = request.into_inner();
        let mut auth_handler = AuthHandler::new(
            authenticate_request.app_id.clone(),
            authenticate_request.app_secret.clone(),
            datastore.clone(),
        );
        let token = auth_handler.obtain_token_safe().await?;
        let (_, token_info) = authenticate(token.clone())?;
        let device_id = token_info.account.device.id;

        let status = datastore.device_status(device_id.clone(), &token).await?;
        if status == DeviceStatus::Draft {
            datastore
                .device_setup(&token, device_id.clone(), remote_address)
                .await?;
        }

        let (tx, rx) = mpsc::channel(6);

        tokio::spawn(async move {
            loop {
                if let Ok(token) = auth_handler.obtain_token_safe().await {
                    if let Ok(response) = datastore.heartbeat(&token, device_id.clone()).await {
                        let response = HeartbeatResponse {
                            token,
                            status: response.status.into(),
                        };
                        tx.send(Ok(response)).await.unwrap();
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn update_firewall_impl(&self, req: Request<AppGuardFirewall>) -> Result<(), Error> {
        let firewall = req.into_inner();

        Ok(())
    }

    async fn handle_tcp_connection_impl(
        &self,
        req: Request<AppGuardTcpConnection>,
    ) -> Result<AppGuardTcpInfo, Error> {
        let tcp_id = self.entry_ids.get_next(DbTable::TcpConnection)?;

        // start measuring the time it takes to respond to this connection
        self.unanswered_connections
            .lock()
            .handle_err(location!())?
            .insert(tcp_id, Instant::now());

        log::info!("TCP connection #{tcp_id}: {}", req.get_ref());

        self.tx_store
            .send(DbEntry::TcpConnection((req.get_ref().clone(), tcp_id)))
            .handle_err(location!())?;

        let token = req.get_ref().token.clone();
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
            } else if let Ok(Some(info)) = self.ds.clone().get_ip_info(ip, token.clone()).await {
                log::info!("IP information for {ip} already in database");
                info
            } else {
                ip_info =
                    AppGuardIpInfo::lookup(ip, &self.ip_info_handler, &self.ds, token.clone())
                        .await?;
                log::info!("Looked up new IP information: {ip_info:?}");
                self.tx_store
                    .send(DbEntry::IpInfo((ip_info.clone(), token)))
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

    async fn handle_http_request_impl(
        &self,
        req: &Request<AppGuardHttpRequest>,
    ) -> Result<FirewallPolicy, Error> {
        let token = req.get_ref().token.clone();
        let fw_res = self
            .get_client_firewall(token)
            .await?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::HttpRequest)?;
        log::info!("***{policy:?}*** HTTP request #{id}: {}", req.get_ref());

        if self.config_log_requests()? {
            let details = DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), None);
            self.tx_store
                .send(DbEntry::HttpRequest((req.get_ref().clone(), details)))
                .handle_err(location!())?;

            // if cfg!(all(not(test), not(feature = "no-ai"))) {
            //     let ai_http_request = ai_http_request(req.into_inner());
            //     self.tx_ai
            //         .send(AiEntry::HttpRequest((ai_http_request, id)))
            //         .handle_err(location!())?;
            // }
        }

        Ok(policy)
    }

    async fn handle_http_response_impl(
        &self,
        req: Request<AppGuardHttpResponse>,
    ) -> Result<FirewallPolicy, Error> {
        let token = req.get_ref().token.clone();
        let fw_res = self
            .get_client_firewall(token)
            .await?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::HttpResponse)?;
        log::info!("***{policy:?}*** HTTP response #{id}: {}", req.get_ref());

        if self.config_log_responses()? {
            let tcp_id = req
                .get_ref()
                .tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .tcp_id;
            let response_time = self.compute_response_time(tcp_id);

            let details =
                DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), response_time);
            self.tx_store
                .send(DbEntry::HttpResponse((req.into_inner(), details)))
                .handle_err(location!())?;
        }

        Ok(policy)
    }

    async fn handle_smtp_request_impl(
        &self,
        req: Request<AppGuardSmtpRequest>,
    ) -> Result<FirewallPolicy, Error> {
        let token = req.get_ref().token.clone();
        let fw_res = self
            .get_client_firewall(token)
            .await?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::SmtpRequest)?;
        log::info!("***{policy:?}*** SMTP request #{id}: {}", req.get_ref());

        if self.config_log_requests()? {
            let details = DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), None);
            self.tx_store
                .send(DbEntry::SmtpRequest((req.into_inner(), details)))
                .handle_err(location!())?;
        }

        Ok(policy)
    }

    async fn handle_smtp_response_impl(
        &self,
        req: Request<AppGuardSmtpResponse>,
    ) -> Result<FirewallPolicy, Error> {
        let token = req.get_ref().token.clone();
        let fw_res = self
            .get_client_firewall(token)
            .await?
            .match_item(req.get_ref());
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::SmtpResponse)?;
        log::info!("***{policy:?}*** SMTP response #{id}: {}", req.get_ref());

        if self.config_log_responses()? {
            let tcp_id = req
                .get_ref()
                .tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .tcp_id;
            let response_time = self.compute_response_time(tcp_id);

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
    type HeartbeatStream = ReceiverStream<Result<HeartbeatResponse, Status>>;

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<Self::HeartbeatStream>, Status> {
        self.heartbeat_impl(request)
            .await
            .map_err(|e| Status::internal(e.to_str().to_string()))
    }

    async fn update_firewall(
        &self,
        request: Request<AppGuardFirewall>,
    ) -> Result<Response<Empty>, Status> {
        self.update_firewall_impl(request)
            .await
            .map(|()| Response::new(Empty {}))
            .map_err(|err| {
                log::error!("Error updating firewall");
                Status::internal(err.to_str())
            })
    }

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
        self.handle_http_request_impl(&req)
            .await
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
            .await
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
            .await
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
            .await
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

// #[cfg(test)]
// #[cfg_attr(coverage_nightly, coverage(off))]
// mod tests {
//     use serial_test::serial;
//
//     use super::*;
//
//     fn write_config_to_file(config: &Config) {
//         let json = serde_json::to_string(&config).unwrap();
//         std::fs::write(CONFIG_FILE, json).unwrap();
//
//         assert_eq!(Config::from_file(CONFIG_FILE).unwrap(), *config);
//     }
//
//     fn tcp_connection_with_source_ip(ip: &str) -> AppGuardTcpConnection {
//         AppGuardTcpConnection {
//             source_ip: Some(ip.to_owned()),
//             ..Default::default()
//         }
//     }
//
//     fn app_guard_ip_info_with_source_ip(ip: &str) -> AppGuardIpInfo {
//         AppGuardIpInfo {
//             ip: ip.to_owned(),
//             ..Default::default()
//         }
//     }
//
//     async fn handle_tcp_connection(app: &AppGuardImpl, ip: &str) {
//         let tcp_connection = tcp_connection_with_source_ip(ip);
//         app.handle_tcp_connection_impl(Request::new(tcp_connection))
//             .await
//             .unwrap();
//     }
//
//     #[tokio::test]
//     #[serial]
//     async fn test_ip_info_cache() {
//         let app = AppGuardImpl::new().await.unwrap();
//         let mut map = IndexMap::new();
//
//         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//         write_config_to_file(&Config {
//             ip_info_cache_size: 3,
//             ..Default::default()
//         });
//         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//
//         handle_tcp_connection(&app, "::1").await;
//         map.insert("::1".to_owned(), app_guard_ip_info_with_source_ip("::1"));
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         handle_tcp_connection(&app, "::2").await;
//         map.shift_insert(0, "::2".to_owned(), app_guard_ip_info_with_source_ip("::2"));
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         handle_tcp_connection(&app, "::3").await;
//         map.shift_insert(0, "::3".to_owned(), app_guard_ip_info_with_source_ip("::3"));
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         handle_tcp_connection(&app, "::4").await;
//         map.shift_insert(0, "::4".to_owned(), app_guard_ip_info_with_source_ip("::4"));
//         map.pop();
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//         write_config_to_file(&Config {
//             ip_info_cache_size: 1,
//             ..Default::default()
//         });
//         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         handle_tcp_connection(&app, "::2").await;
//         map.clear();
//         map.insert("::2".to_owned(), app_guard_ip_info_with_source_ip("::2"));
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//         write_config_to_file(&Config {
//             ip_info_cache_size: 0,
//             ..Default::default()
//         });
//         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         handle_tcp_connection(&app, "::3").await;
//         map.clear();
//         assert_eq!(*app.ip_info_cache.lock().unwrap(), map);
//
//         write_config_to_file(&Config::default());
//     }
// }
