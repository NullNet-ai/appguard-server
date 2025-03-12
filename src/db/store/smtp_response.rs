use crate::db::entries::DbDetails;
use crate::helpers::get_timestamp_string;
use crate::proto::appguard::AppGuardSmtpResponse;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;

impl AppGuardSmtpResponse {
    pub(crate) fn to_json(&self, details: &DbDetails) -> Result<String, Error> {
        Ok(json!({
            "timestamp": get_timestamp_string(),
            "fw_policy": details.fw_res.policy.as_str_name(),
            "fw_reasons": serde_json::to_string(&details.fw_res.reasons).handle_err(location!())?,
            "ip": details.ip,
            "code": self.code,
            "time": details.response_time,
        })
        .to_string())
    }
}
