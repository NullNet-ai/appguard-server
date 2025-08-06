use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Device {
    pub id: String,

    #[serde(rename = "device_uuid")]
    pub uuid: String,
    #[serde(rename = "is_traffic_monitoring_enabled")]
    pub traffic_monitoring: bool,
    #[serde(rename = "is_config_monitoring_enabled")]
    pub sysconf_monitoring: bool,
    #[serde(rename = "is_telemetry_monitoring_enabled")]
    pub telemetry_monitoring: bool,
    #[serde(rename = "is_device_authorized")]
    pub authorized: bool,
    #[serde(rename = "device_category")]
    pub category: String,
    #[serde(rename = "device_type")]
    pub r#type: String,
    #[serde(rename = "device_name")]
    pub name: String,
    #[serde(rename = "device_os")]
    pub os: String,
    #[serde(rename = "is_device_online")]
    pub online: bool,
    #[serde(rename = "organization_id")]
    pub organization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceInstance {
    pub id: String,
    pub device_id: String,
}
