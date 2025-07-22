use crate::config::Config;
use crate::constants::{
    ROOT_ACCOUNT_ID, ROOT_ACCOUNT_SECRET, SYSTEM_ACCOUNT_ID, SYSTEM_ACCOUNT_SECRET,
};
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

        let root_token = root_token_provider.get().await?.jwt.clone();

        let firewalls = datastore.get_firewalls(root_token.clone()).await?;
        log::info!(
            "Loaded firewalls from datastore: {}",
            serde_json::to_string(&firewalls).unwrap_or_default()
        );

        let config = datastore.get_configs(root_token).await?;
        log::info!(
            "Loaded AppGuard configuration: {}",
            serde_json::to_string(&config).unwrap_or_default()
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
