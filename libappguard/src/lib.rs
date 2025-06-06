mod proto;

use crate::proto::appguard::HeartbeatRequest;
use proto::appguard::app_guard_client::AppGuardClient;
pub use proto::appguard::{
    AppGuardFirewall, AppGuardHttpRequest, AppGuardHttpResponse, AppGuardResponse,
    AppGuardSmtpRequest, AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
    AppGuardTcpResponse, DeviceStatus, FirewallPolicy, HeartbeatResponse, Log, Logs,
};
use std::future::Future;
pub use tonic::Streaming;
use tonic::transport::{Channel, ClientTlsConfig};
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct AppGuardGrpcInterface {
    client: AppGuardClient<Channel>,
}

impl AppGuardGrpcInterface {
    #[allow(clippy::missing_errors_doc)]
    pub async fn new(host: &str, port: u16, tls: bool) -> Result<Self, String> {
        let protocol = if tls { "https" } else { "http" };

        let mut endpoint = Channel::from_shared(format!("{protocol}://{host}:{port}"))
            .map_err(|e| e.to_string())?
            .connect_timeout(std::time::Duration::from_secs(10));

        if tls {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|e| e.to_string())?;
        }

        let channel = endpoint.connect().await.map_err(|e| e.to_string())?;

        Ok(Self {
            client: AppGuardClient::new(channel),
        })
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn heartbeat(
        &mut self,
        app_id: String,
        app_secret: String,
    ) -> Result<Streaming<HeartbeatResponse>, String> {
        self.client
            .heartbeat(Request::new(HeartbeatRequest { app_id, app_secret }))
            .await
            .map(tonic::Response::into_inner)
            .map_err(|e| e.to_string())
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn update_firewall(&mut self, firewall: AppGuardFirewall) -> Result<(), String> {
        self.client
            .update_firewall(Request::new(firewall))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn handle_logs(&mut self, message: Logs) -> Result<(), String> {
        self.client
            .handle_logs(Request::new(message))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn handle_tcp_connection(
        &mut self,
        timeout: Option<u64>,
        tcp_connection: AppGuardTcpConnection,
    ) -> Result<AppGuardTcpResponse, Status> {
        self.client
            .handle_tcp_connection(Request::new(tcp_connection.clone()))
            .wait_until_timeout(
                timeout,
                AppGuardTcpResponse {
                    tcp_info: Some(AppGuardTcpInfo {
                        connection: Some(tcp_connection),
                        ..Default::default()
                    }),
                },
            )
            .await
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn handle_http_request(
        &mut self,
        timeout: Option<u64>,
        default_policy: FirewallPolicy,
        http_request: AppGuardHttpRequest,
    ) -> Result<AppGuardResponse, Status> {
        self.client
            .handle_http_request(Request::new(http_request))
            .wait_until_timeout(
                timeout,
                AppGuardResponse {
                    policy: default_policy as i32,
                },
            )
            .await
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn handle_http_response(
        &mut self,
        timeout: Option<u64>,
        default_policy: FirewallPolicy,
        http_response: AppGuardHttpResponse,
    ) -> Result<AppGuardResponse, Status> {
        self.client
            .handle_http_response(Request::new(http_response))
            .wait_until_timeout(
                timeout,
                AppGuardResponse {
                    policy: default_policy as i32,
                },
            )
            .await
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn handle_smtp_request(
        &mut self,
        timeout: Option<u64>,
        default_policy: FirewallPolicy,
        smtp_request: AppGuardSmtpRequest,
    ) -> Result<AppGuardResponse, Status> {
        self.client
            .handle_smtp_request(Request::new(smtp_request))
            .wait_until_timeout(
                timeout,
                AppGuardResponse {
                    policy: default_policy as i32,
                },
            )
            .await
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn handle_smtp_response(
        &mut self,
        timeout: Option<u64>,
        default_policy: FirewallPolicy,
        smtp_response: AppGuardSmtpResponse,
    ) -> Result<AppGuardResponse, Status> {
        self.client
            .handle_smtp_response(Request::new(smtp_response))
            .wait_until_timeout(
                timeout,
                AppGuardResponse {
                    policy: default_policy as i32,
                },
            )
            .await
    }
}

trait WaitUntilTimeout<T> {
    async fn wait_until_timeout(self, timeout: Option<u64>, default: T) -> Result<T, Status>;
}

impl<T, F: Future<Output = Result<Response<T>, Status>>> WaitUntilTimeout<T> for F {
    async fn wait_until_timeout(self, timeout: Option<u64>, default: T) -> Result<T, Status> {
        if let Some(t) = timeout {
            if let Ok(res) = tokio::time::timeout(std::time::Duration::from_millis(t), self).await {
                res.map(Response::into_inner)
            } else {
                // handler timed out, return default value
                Ok(default)
            }
        } else {
            self.await.map(Response::into_inner)
        }
    }
}
