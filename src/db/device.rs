use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Device {
    pub id: String,

    #[serde(rename = "device_uuid")]
    pub uuid: String,
    #[serde(rename = "is_device_authorized")]
    pub authorized: bool,
    #[serde(rename = "device_category")]
    pub category: String,
    #[serde(rename = "device_model")]
    pub model: String,
    #[serde(rename = "device_os")]
    pub os: String,
    #[serde(rename = "is_device_online")]
    pub online: bool,
    #[serde(rename = "organization_id")]
    pub organization: String,
}
