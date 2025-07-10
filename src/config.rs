use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Config {
    pub log_requests: bool,
    pub log_responses: bool,
    pub retention_sec: u64,
    pub ip_info_cache_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_requests: true,
            log_responses: true,
            ip_info_cache_size: 1000,
            retention_sec: 0,
        }
    }
}
