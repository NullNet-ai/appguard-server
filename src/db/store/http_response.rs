use crate::db::entries::DbDetails;
use crate::helpers::{get_header, get_timestamp_string};
use crate::proto::appguard::AppGuardHttpResponse;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;

impl AppGuardHttpResponse {
    pub(crate) fn json_record(&self, details: &DbDetails) -> Result<String, Error> {
        let headers = &self.headers;

        let size = get_header(headers, "Content-Length");

        let headers_json = serde_json::to_string(headers).handle_err(location!())?;

        Ok(json!({
            "id": details.id,
            "timestamp": get_timestamp_string(),
            "fw_res": details.fw_res,
            "tcp_id": details.tcp_id,
            "ip": details.ip,
            "code": self.code,
            "headers": headers_json,
            "time": details.response_time,
            "size": size,
        })
        .to_string())
    }
}
