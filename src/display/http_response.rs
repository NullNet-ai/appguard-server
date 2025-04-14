use crate::proto::appguard::{AppGuardHttpResponse, AppGuardTcpConnection, AppGuardTcpInfo};
use std::fmt::Display;

impl Display for AppGuardHttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ip = self
            .tcp_info
            .as_ref()
            .unwrap_or(&AppGuardTcpInfo::default())
            .connection
            .as_ref()
            .unwrap_or(&AppGuardTcpConnection::default())
            .source_ip
            .clone()
            .unwrap_or("?".to_string());
        write!(f, "status {} (to {ip})", self.code)
    }
}
