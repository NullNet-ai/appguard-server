use crate::firewall::denied_ip::DeniedIp;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;

impl DeniedIp {
    pub(crate) fn to_json(&self, app_id: &str) -> Result<String, Error> {
        Ok(json!({
            "app_id": app_id,
            "ip": self.ip,
            "deny_reasons": serde_json::to_string(&self.deny_reasons).handle_err(location!())?,
        })
        .to_string())
    }
}
