use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use tokio::runtime::Handle;
use tonic::transport::Channel;

use crate::ai::entries::AiEntry;
use crate::error::{ErrorHandler, Location};
use crate::helpers::{get_header, get_timestamp_string};
use crate::location;
use crate::proto::aiguard::ai_guard_client::AiGuardClient;
use crate::proto::aiguard::{AiGuardCommonParams, AiGuardHttpRequest, AiGuardHttpRequestParams};
use crate::proto::appguard::{AppGuardHttpRequest, AppGuardTcpInfo};

pub fn ai_interface(
    conn: &Arc<Mutex<Connection>>,
    rx: &Receiver<AiEntry>,
    ai_client: &AiGuardClient<Channel>,
    rt_handle: &Handle,
) {
    loop {
        if let Ok(entry) = rx.recv().handle_err(location!()) {
            let conn = conn.clone();
            let ai_client = ai_client.clone();
            rt_handle.spawn(async move {
                entry.handle(&conn, ai_client).await.unwrap_or_default();
            });
        }
    }
}

pub fn ai_http_request(http_request: AppGuardHttpRequest) -> AiGuardHttpRequest {
    let headers = http_request.headers;
    let user_agent = get_header(&headers, "User-Agent").cloned();
    let cookies = get_header(&headers, "Cookie").cloned();

    AiGuardHttpRequest {
        common: http_request.tcp_info.map(ai_common_params),
        params: Some(AiGuardHttpRequestParams {
            original_url: http_request.original_url,
            user_agent,
            headers,
            method: http_request.method,
            query: http_request.query,
            cookies,
        }),
    }
}

fn ai_common_params(tcp_info: AppGuardTcpInfo) -> AiGuardCommonParams {
    let connection = tcp_info.connection.unwrap_or_default();
    let ip_info = tcp_info.ip_info.unwrap_or_default();
    AiGuardCommonParams {
        timestamp: get_timestamp_string(),
        source_ip: connection.source_ip,
        source_port: connection.source_port,
        country: ip_info.country,
        asn: ip_info.asn,
        org: ip_info.org,
        blacklist: ip_info.blacklist,
    }
}
