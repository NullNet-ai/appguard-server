use std::collections::HashMap;
use std::convert::TryFrom;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use indexmap::IndexMap;
use tonic::{Request, Response, Status, Streaming};

use crate::app_context::AppContext;
use crate::db::entries::{DbDetails, DbEntry, EntryIds};
use crate::db::helpers::{delete_old_entries, store_entries};
use crate::db::tables::DbTable;
use crate::fetch_data::fetch_ip_data;
use crate::firewall::denied_ip::DeniedIp;
use crate::firewall::firewall::{Firewall, FirewallResult};
use crate::firewall::rules::FirewallRule;
use crate::helpers::authenticate;
use crate::ip_info::ip_info_handler;
use crate::proto::appguard::app_guard_server::AppGuard;
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardIpInfo, AppGuardResponse,
    AppGuardSmtpRequest, AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
    AppGuardTcpResponse, Logs,
};
use crate::proto::appguard_commands::{
    ClientMessage, FirewallDefaults, FirewallPolicy, ServerMessage,
};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libipinfo::IpInfoHandler;
use nullnet_libtoken::Token;
use rpn_predicate_interpreter::PredicateEvaluator;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{mpsc, Mutex};
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;

pub struct AppGuardImpl {
    entry_ids: EntryIds,
    unanswered_connections: Arc<Mutex<HashMap<u64, Instant>>>,
    ip_info_cache: Arc<Mutex<IndexMap<String, AppGuardIpInfo>>>,
    ip_info_handler: IpInfoHandler,
    tx_store: UnboundedSender<DbEntry>,
    ctx: AppContext,
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
    pub fn new(ctx: AppContext) -> AppGuardImpl {
        let ds = ctx.datastore.clone();
        let ds_2 = ctx.datastore.clone();
        let ds_3 = ctx.datastore.clone();

        log::info!("Connected to Datastore");

        let config_2 = ctx.config_pair.clone();

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

        let root_token_provider = ctx.root_token_provider.clone();
        tokio::spawn(async move {
            fetch_ip_data(ds_3, root_token_provider).await;
        });

        let root_token_provider = ctx.root_token_provider.clone();
        tokio::spawn(async move {
            delete_old_entries(&config_2, &ds_2, &ip_info_cache_2, root_token_provider)
                .await
                .expect("Delete old entries thread failed");
        });

        tokio::spawn(async move {
            store_entries(&ds, &mut rx_store).await;
        });

        AppGuardImpl {
            entry_ids: EntryIds::default(),
            unanswered_connections: Arc::new(Mutex::new(HashMap::new())),
            ip_info_cache,
            ip_info_handler,
            tx_store,
            // tx_ai,
            ctx,
        }
    }

    fn config_log_requests(&self) -> Result<bool, Error> {
        Ok(self
            .ctx
            .config_pair
            .0
            .lock()
            .handle_err(location!())?
            .log_request)
    }

    fn config_log_responses(&self) -> Result<bool, Error> {
        Ok(self
            .ctx
            .config_pair
            .0
            .lock()
            .handle_err(location!())?
            .log_response)
    }

    fn config_ip_info_cache_size(&self) -> Result<usize, Error> {
        Ok(self
            .ctx
            .config_pair
            .0
            .lock()
            .handle_err(location!())?
            .ip_info_cache_size)
    }

    async fn refresh_ip_info_cache(&self, ip: &str, ip_info: &AppGuardIpInfo) -> Result<(), Error> {
        let cache_size = self.config_ip_info_cache_size()?;
        let mut ip_info_cache = self.ip_info_cache.lock().await;
        ip_info_cache.shift_insert(0, ip.to_string(), ip_info.clone());
        while ip_info_cache.len() > cache_size {
            ip_info_cache.pop();
        }
        Ok(())
    }

    async fn compute_response_time(&self, tcp_id: u64) -> Option<u32> {
        if let Some(request_instant) = self.unanswered_connections.lock().await.remove(&tcp_id) {
            u32::try_from(request_instant.elapsed().as_millis())
                .handle_err(location!())
                .ok()
        } else {
            log::warn!("Connection ID {tcp_id} not found (cannot compute response time)");
            None
        }
    }

    async fn firewall_match_item<
        I: PredicateEvaluator<Predicate = FirewallRule, Reason = String, Context = AppContext>,
    >(
        &self,
        token: &str,
        item: &I,
    ) -> Result<FirewallResult, Error> {
        let Ok(t) = Token::from_jwt(token) else {
            return Err("invalid token").handle_err(location!());
        };
        let app_id = t
            .account
            .device
            .ok_or("Device not found in token")
            .handle_err(location!())?
            .id;

        let fws = self.ctx.firewalls.read().await;
        let default = Firewall::default();
        let fw = fws.get(&app_id).unwrap_or(&default);

        let res = fw.match_item(item, &self.ctx).await;
        if res.policy == FirewallPolicy::Deny {
            let denied_ip = DeniedIp {
                ip: item.get_remote_ip(),
                deny_reasons: res.reasons.clone(),
            };
            self.tx_store
                .send(DbEntry::DeniedIp((
                    app_id.clone(),
                    denied_ip,
                    token.to_string(),
                )))
                .handle_err(location!())?;
        }

        Ok(res)
    }

    pub(crate) fn control_channel_impl(
        &self,
        request: Request<Streaming<ClientMessage>>,
    ) -> Response<<AppGuardImpl as AppGuard>::ControlChannelStream> {
        let (sender, receiver) = mpsc::channel(64);

        self.ctx
            .orchestrator
            .on_new_connection(request.into_inner(), sender, self.ctx.clone());

        Response::new(ReceiverStream::new(receiver))
    }

    async fn handle_logs_impl(&self, request: Request<Logs>) -> Result<Response<()>, Error> {
        let logs = request.into_inner();
        let (jwt_token, _) = authenticate(logs.token)?;

        // TODO: call tx_store to store logs
        let _ = self
            .ctx
            .datastore
            .logs_insert(&jwt_token, logs.logs)
            .await?;

        Ok(Response::new(()))
    }

    async fn handle_tcp_connection_impl(
        &self,
        req: Request<AppGuardTcpConnection>,
    ) -> Result<AppGuardTcpInfo, Error> {
        let tcp_id = self.entry_ids.get_next(DbTable::TcpConnection).await?;

        // start measuring the time it takes to respond to this connection
        self.unanswered_connections
            .lock()
            .await
            .insert(tcp_id, Instant::now());

        log::info!("TCP connection #{tcp_id}: {}", req.get_ref());

        self.tx_store
            .send(DbEntry::TcpConnection((req.get_ref().clone(), tcp_id)))
            .handle_err(location!())?;

        let token = req.get_ref().token.clone();
        let mut ip_info = AppGuardIpInfo::default();
        if let Some(ip) = &req.get_ref().source_ip {
            log::info!("Searching IP information for {ip}");
            let info_opt = self.ip_info_cache.lock().await.get(ip).cloned();
            ip_info = if let Some(info) = info_opt {
                log::info!("IP information for {ip} already in cache");
                info
            } else if let Ok(Some(info)) = self
                .ctx
                .datastore
                .clone()
                .get_ip_info(ip, token.clone())
                .await
            {
                log::info!("IP information for {ip} already in database");
                info
            } else {
                ip_info = AppGuardIpInfo::lookup(
                    ip,
                    &self.ip_info_handler,
                    &self.ctx.datastore,
                    token.clone(),
                )
                .await?;
                log::info!("Looked up new IP information: {ip_info:?}");
                self.tx_store
                    .send(DbEntry::IpInfo((ip_info.clone(), token)))
                    .handle_err(location!())?;
                ip_info
            };
            // refresh the IP info cache
            self.refresh_ip_info_cache(ip, &ip_info).await?;
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
        let token = &req.get_ref().token;
        let fw_res = self.firewall_match_item(token, req.get_ref()).await?;
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::HttpRequest).await?;
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
        let token = &req.get_ref().token;
        let fw_res = self.firewall_match_item(token, req.get_ref()).await?;
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::HttpResponse).await?;
        log::info!("***{policy:?}*** HTTP response #{id}: {}", req.get_ref());

        if self.config_log_responses()? {
            let tcp_id = req
                .get_ref()
                .tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .tcp_id;
            let response_time = self.compute_response_time(tcp_id).await;

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
        let token = &req.get_ref().token;
        let fw_res = self.firewall_match_item(token, req.get_ref()).await?;
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::SmtpRequest).await?;
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
        let token = &req.get_ref().token;
        let fw_res = self.firewall_match_item(token, req.get_ref()).await?;
        let policy = fw_res.policy;

        let id = self.entry_ids.get_next(DbTable::SmtpResponse).await?;
        log::info!("***{policy:?}*** SMTP response #{id}: {}", req.get_ref());

        if self.config_log_responses()? {
            let tcp_id = req
                .get_ref()
                .tcp_info
                .as_ref()
                .unwrap_or(&AppGuardTcpInfo::default())
                .tcp_id;
            let response_time = self.compute_response_time(tcp_id).await;

            let details =
                DbDetails::new(id, fw_res, req.get_ref().tcp_info.as_ref(), response_time);
            self.tx_store
                .send(DbEntry::SmtpResponse((req.into_inner(), details)))
                .handle_err(location!())?;
        }

        Ok(policy)
    }

    async fn firewall_defaults_request_impl(
        &self,
        req: Request<crate::proto::appguard::Token>,
    ) -> Result<FirewallDefaults, Error> {
        let token = &req.get_ref().token;
        let Ok(t) = Token::from_jwt(token) else {
            return Err("invalid token").handle_err(location!());
        };
        let app_id = t.account.account_id;

        let fws = self.ctx.firewalls.read().await;
        let default = Firewall::default();
        let fw = fws.get(&app_id).unwrap_or(&default);

        Ok(FirewallDefaults {
            timeout: fw.timeout,
            policy: fw.default_policy.into(),
        })
    }
}

#[tonic::async_trait]
impl AppGuard for AppGuardImpl {
    type ControlChannelStream = ReceiverStream<Result<ServerMessage, Status>>;

    async fn control_channel(
        &self,
        request: Request<Streaming<ClientMessage>>,
    ) -> Result<Response<Self::ControlChannelStream>, Status> {
        log::debug!(
            "AppGuardService::control_channel requested from addr {}",
            request
                .remote_addr()
                .map_or("unknown".into(), |addr| addr.to_string())
        );

        Ok(self.control_channel_impl(request))
    }

    async fn handle_logs(&self, request: Request<Logs>) -> Result<Response<()>, Status> {
        // do not log inside here, otherwise it will loop
        let result = self.handle_logs_impl(request).await;
        result.map_err(|e| Status::internal(format!("{e:?}")))
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

    async fn firewall_defaults_request(
        &self,
        req: Request<crate::proto::appguard::Token>,
    ) -> Result<Response<FirewallDefaults>, Status> {
        self.firewall_defaults_request_impl(req)
            .await
            .map(Response::new)
            .map_err(|err| {
                log::error!("Error retrieving firewall defaults");
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
