use nullnet_liberror::Error;

use crate::db::datastore_wrapper::DatastoreWrapper;
use crate::orchestrator::Orchestrator;
use crate::token_provider::TokenProvider;

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
}

impl AppContext {
    pub async fn new() -> Result<Self, Error> {
        let datastore = DatastoreWrapper::new().await?;
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

        Ok(Self {
            datastore,
            orchestrator,
            sysdev_token_provider,
            root_token_provider,
        })
    }
}
