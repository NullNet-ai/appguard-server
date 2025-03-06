use crate::helpers::get_timestamp_string;
use crate::proto::appguard::AppGuardIpInfo;
use serde_json::json;

impl AppGuardIpInfo {
    pub(crate) fn to_json(&self) -> String {
        json!({
            "timestamp": get_timestamp_string(),
            "ip": self.ip,
            "country": self.country,
            "asn": self.asn,
            "org": self.org,
            "continent_code": self.continent_code,
            "city": self.city,
            "region": self.region,
            "postal": self.postal,
            "timezone": self.timezone,
            "blacklist": self.blacklist,
        })
        .to_string()
    }
}
