use crate::firewall::firewall::Firewall;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;

impl Firewall {
    pub(crate) fn to_json(&self, app_id: &str) -> Result<String, Error> {
        Ok(json!({
            "app_id": app_id,
            "firewall": serde_json::to_string(self).handle_err(location!())?,
        })
        .to_string())
    }
}
