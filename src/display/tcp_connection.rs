use crate::proto::appguard::AppGuardTcpConnection;
use std::fmt::Display;

impl Display for AppGuardTcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.source_ip.as_ref().unwrap_or(&"?".to_string()),
            self.source_port.map_or("?".to_string(), |x| x.to_string()),
            self.destination_ip.as_ref().unwrap_or(&"?".to_string()),
            self.destination_port
                .map_or("?".to_string(), |x| x.to_string()),
            self.protocol
        )
    }
}
