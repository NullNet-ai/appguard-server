use crate::firewall::denied_ip::DeniedIp;
use nullnet_liberror::Error;
use serde_json::json;

impl DeniedIp {
    pub(crate) fn to_json(&self, quarantine_alias_id: u64) -> Result<String, Error> {
        // a denied IP is always a single IP and (not a subnet)
        let prefix = if self.ip.is_ipv4() { 32 } else { 128 };
        Ok(json!({
            "alias_id": quarantine_alias_id,
            "ip": self.ip,
            "prefix": prefix,
        })
        .to_string())
    }
}
