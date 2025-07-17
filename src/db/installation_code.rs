use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationCode {
    pub id: String,
    pub device_id: String,
    pub device_code: String,
    pub redeemed: bool,
    pub organization_id: String,
}
