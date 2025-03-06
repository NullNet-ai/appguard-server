use crate::db::entries::DbDetails;
use crate::helpers::get_timestamp_string;
use crate::proto::appguard::AppGuardSmtpResponse;
use nullnet_liberror::Error;
use serde_json::json;

impl AppGuardSmtpResponse {
    pub(crate) fn json_record(&self, details: &DbDetails) -> Result<String, Error> {
        Ok(json!({
            "id": details.id,
            "timestamp": get_timestamp_string(),
            "fw_res": details.fw_res,
            "tcp_id": details.tcp_id,
            "ip": details.ip,
            "code": self.code,
            "time": details.response_time,
        })
        .to_string())
    }
}
