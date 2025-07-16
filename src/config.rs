use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Config {
    pub log_request: bool,
    pub log_response: bool,
    pub retention_sec: u64,
    pub ip_info_cache_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_request: true,
            log_response: true,
            ip_info_cache_size: 1000,
            retention_sec: 0,
        }
    }
}
