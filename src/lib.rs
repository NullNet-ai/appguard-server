#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
#![allow(
    clippy::used_underscore_binding,
    clippy::module_name_repetitions,
    clippy::wildcard_imports,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::missing_panics_doc
)]

#[cfg(not(feature = "grpc-lib-only"))]
pub mod ai;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod app_guard_impl;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod config;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod constants;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod db;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod deserialize;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod entrypoint;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod fetch_data;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod firewall;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod from_sql;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod helpers;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod ip_info;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod proto;
#[cfg(feature = "grpc-lib-only")]
mod proto;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod serialize;
#[cfg(not(feature = "grpc-lib-only"))]
pub mod to_sql;

use proto::appguard::app_guard_client::AppGuardClient;
pub use proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardResponse, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpInfo, AppGuardTcpResponse,
    FirewallPolicy,
};
use std::future::Future;
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
