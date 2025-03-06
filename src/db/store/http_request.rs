use crate::db::entries::DbDetails;
use crate::helpers::{get_header, get_timestamp_string};
use crate::proto::appguard::AppGuardHttpRequest;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;

impl AppGuardHttpRequest {
    pub(crate) fn to_json(&self, details: &DbDetails) -> Result<String, Error> {
        let headers = &self.headers;
        let query = &self.query;

        let user_agent = get_header(headers, "User-Agent");
        let cookies = get_header(headers, "Cookie");

        let headers_json = serde_json::to_string(headers).handle_err(location!())?;
        let query_json = serde_json::to_string(query).handle_err(location!())?;

        Ok(json!({
            "id": details.id,
            "timestamp": get_timestamp_string(),
            "fw_policy": details.fw_res.policy,
            "fw_reasons": details.fw_res.reasons,
            "tcp_id": details.tcp_id,
            "ip": details.ip,
            "original_url": self.original_url,
            "user_agent": user_agent,
            "headers": headers_json,
            "method": self.method,
            "body": self.body,
            "query": query_json,
            "cookies": cookies,
        })
        .to_string())
    }
}
