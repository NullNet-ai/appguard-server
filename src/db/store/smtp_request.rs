use crate::db::entries::DbDetails;
use crate::helpers::{get_header, get_timestamp_string};
use crate::proto::appguard::AppGuardSmtpRequest;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;

impl AppGuardSmtpRequest {
    pub(crate) fn json_record(&self, details: &DbDetails) -> Result<String, Error> {
        let headers = &self.headers;

        let user_agent = get_header(headers, "User-Agent");

        let headers_json = serde_json::to_string(headers).handle_err(location!())?;

        Ok(json!({
            "id": details.id,
            "timestamp": get_timestamp_string(),
            "fw_res": details.fw_res,
            "tcp_id": details.tcp_id,
            "ip": details.ip,
            "user_agent": user_agent,
            "headers": headers_json,
            "body": self.body,
        })
        .to_string())
    }
}
