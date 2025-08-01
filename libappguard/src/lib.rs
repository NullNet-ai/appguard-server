mod proto;

use crate::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardResponse, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo, AppGuardTcpResponse, Logs,
};
use crate::appguard_commands::{ClientMessage, FirewallDefaults, FirewallPolicy, ServerMessage};
use proto::appguard::app_guard_client::AppGuardClient;
pub use proto::*;
use std::future::Future;
use tokio::sync::mpsc;
pub use tonic::Streaming;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
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
    pub async fn control_channel(
        &self,
        receiver: mpsc::Receiver<ClientMessage>,
    ) -> Result<Streaming<ServerMessage>, String> {
        let receiver = ReceiverStream::new(receiver);

        Ok(self
            .client
            .clone()
            .control_channel(Request::new(receiver))
            .await
            .map_err(|e| e.to_string())?
            .into_inner())
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
        timeout: u32,
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
        timeout: u32,
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
        timeout: u32,
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
        timeout: u32,
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
        timeout: u32,
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

    #[allow(clippy::missing_errors_doc)]
    pub async fn firewall_defaults_request(
        &mut self,
        token: String,
    ) -> Result<FirewallDefaults, Status> {
        self.client
            .firewall_defaults_request(Request::new(appguard::Token { token }))
            .await
            .map(Response::into_inner)
    }
}

trait WaitUntilTimeout<T> {
    async fn wait_until_timeout(self, timeout: u32, default: T) -> Result<T, Status>;
}

impl<T, F: Future<Output = Result<Response<T>, Status>>> WaitUntilTimeout<T> for F {
    async fn wait_until_timeout(self, timeout: u32, default: T) -> Result<T, Status> {
        if let Ok(res) =
            tokio::time::timeout(std::time::Duration::from_millis(u64::from(timeout)), self).await
        {
            res.map(Response::into_inner)
        } else {
            // handler timed out, return default value
            Ok(default)
        }
    }
}
