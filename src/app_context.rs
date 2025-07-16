use crate::config::Config;
use crate::db::datastore_wrapper::DatastoreWrapper;
use crate::firewall::firewall::Firewall;
use crate::orchestrator::Orchestrator;
use crate::token_provider::TokenProvider;
use nullnet_liberror::Error;
use std::collections::HashMap;
use std::sync::{Arc, Condvar};
use tokio::sync::RwLock;
// Unfortunately, we have to use both root and system device credentials because:
// - The system device cannot fetch data outside its own organization; only the root account can do that.
// - We cannot use the root account for everything because it cannot create records in the database.

pub static ROOT_ACCOUNT_ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("ROOT_ACCOUNT_ID").unwrap_or_else(|_| {
        log::warn!("'ROOT_ACCOUNT_ID' environment variable not set");
        String::new()
    })
});

pub static ROOT_ACCOUNT_SECRET: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("ROOT_ACCOUNT_SECRET").unwrap_or_else(|_| {
        log::warn!("'ROOT_ACCOUNT_SECRET' environment variable not set");
        String::new()
    })
});

pub static SYSTEM_ACCOUNT_ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("SYSTEM_ACCOUNT_ID").unwrap_or_else(|_| {
        log::warn!("'SYSTEM_ACCOUNT_ID' environment variable not set");
        String::new()
    })
});

pub static SYSTEM_ACCOUNT_SECRET: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("SYSTEM_ACCOUNT_SECRET").unwrap_or_else(|_| {
        log::warn!("'SYSTEM_ACCOUNT_SECRET' environment variable not set");
        String::new()
    })
});

#[derive(Debug, Clone)]
pub struct AppContext {
    pub datastore: DatastoreWrapper,
    pub orchestrator: Orchestrator,
    pub root_token_provider: TokenProvider,
    pub sysdev_token_provider: TokenProvider,
    pub firewalls: Arc<RwLock<HashMap<String, Firewall>>>,
    pub config_pair: Arc<(std::sync::Mutex<Config>, Condvar)>,
}

impl AppContext {
    pub async fn new() -> Result<Self, Error> {
        let mut datastore = DatastoreWrapper::new().await?;
        let orchestrator = Orchestrator::new();

        let firewalls = datastore.get_firewalls().await?;
        log::info!(
            "Loaded firewalls from datastore: {}",
            serde_json::to_string(&firewalls).unwrap_or_default()
        );

        let config = datastore.get_configs().await?;
        log::info!(
            "Loaded AppGuard configuration: {}",
            serde_json::to_string(&config).unwrap_or_default()
        );

        let sysdev_token_provider = TokenProvider::new(
            SYSTEM_ACCOUNT_ID.to_string(),
            SYSTEM_ACCOUNT_SECRET.to_string(),
            false,
            datastore.clone(),
        );

        let root_token_provider = TokenProvider::new(
            ROOT_ACCOUNT_ID.to_string(),
            ROOT_ACCOUNT_SECRET.to_string(),
            true,
            datastore.clone(),
        );

        Ok(Self {
            datastore,
            orchestrator,
            sysdev_token_provider,
            firewalls: Arc::new(RwLock::new(firewalls)),
            root_token_provider,
            config_pair: Arc::new((std::sync::Mutex::new(config), Condvar::new())),
        })
    }
}
