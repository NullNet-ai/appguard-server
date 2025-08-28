use crate::app_context::AppContext;
use nullnet_liberror::Error;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct RateLimit {
    pub limit: usize,
    pub period: usize,
    pub urls: Vec<String>,
}

impl RateLimit {
    pub async fn get_recent_urls_for_ip(
        &self,
        ctx: &AppContext,
        ip: IpAddr,
    ) -> Result<Vec<String>, Error> {
        let token = ctx.root_token_provider.get().await?;
        let jwt = &token.jwt;
        ctx.datastore
            .get_recent_urls_for_ip(jwt, ip, self.period)
            .await
    }
}
