use tonic::transport::Channel;
use tonic::{Request, Status};

use appguard::proto::appguard::app_guard_client::AppGuardClient;
use appguard::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardResponse, AppGuardSmtpRequest,
    AppGuardSmtpResponse, AppGuardTcpConnection, AppGuardTcpResponse,
};

#[allow(dead_code)]
pub async fn handle_http_request(
    client: &mut AppGuardClient<Channel>,
    http_request: AppGuardHttpRequest,
) -> Result<AppGuardResponse, Status> {
    client
        .handle_http_request(Request::new(http_request))
        .await
        .map(|x| x.into_inner())
}

#[allow(dead_code)]
pub async fn handle_http_response(
    client: &mut AppGuardClient<Channel>,
    http_response: AppGuardHttpResponse,
) -> Result<AppGuardResponse, Status> {
    client
        .handle_http_response(Request::new(http_response))
        .await
        .map(|x| x.into_inner())
}

#[allow(dead_code)]
pub async fn handle_tcp_connection(
    client: &mut AppGuardClient<Channel>,
    tcp_connection: AppGuardTcpConnection,
) -> Result<AppGuardTcpResponse, Status> {
    client
        .handle_tcp_connection(Request::new(tcp_connection))
        .await
        .map(|x| x.into_inner())
}

#[allow(dead_code)]
pub async fn handle_smtp_request(
    client: &mut AppGuardClient<Channel>,
    smtp_request: AppGuardSmtpRequest,
) -> Result<AppGuardResponse, Status> {
    client
        .handle_smtp_request(Request::new(smtp_request))
        .await
        .map(|x| x.into_inner())
}

#[allow(dead_code)]
pub async fn handle_smtp_response(
    client: &mut AppGuardClient<Channel>,
    smtp_response: AppGuardSmtpResponse,
) -> Result<AppGuardResponse, Status> {
    client
        .handle_smtp_response(Request::new(smtp_response))
        .await
        .map(|x| x.into_inner())
}
