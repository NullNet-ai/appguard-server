use crate::helpers::get_timestamp_string;
use crate::proto::appguard::AppGuardTcpConnection;
use serde_json::json;

impl AppGuardTcpConnection {
    pub(crate) fn to_json(&self, id: u64) -> String {
        json!({
            "id": id,
            "timestamp": get_timestamp_string(),
            "source": self.source_ip,
            "sport": self.source_port,
            "dest": self.destination_ip,
            "dport": self.destination_port,
            "proto": self.protocol,
        })
        .to_string()
    }
}
