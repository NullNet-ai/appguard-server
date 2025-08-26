use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use crate::app_context::AppContext;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct RateLimit {
    pub limit: usize,
    pub period: usize,
    pub urls: Vec<String>,
}

impl RateLimit {
    pub fn get_urls(&self, ctx: &AppContext, ip: IpAddr) -> Vec<String> {
        // get from datastore all the urls queried by this ip in the last period seconds
        vec![]
    }
}