use nullnet_liberror::{location, ErrorHandler, Location};

// project-level constants
pub static IP_INFO_API_KEY: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("IP_INFO_API_KEY").unwrap_or_else(|_| {
        log::warn!("Environment variable IP_INFO_API_KEY not found");
        String::new()
    })
});

// -------------------------------------------------------------------------------------------------

// server constants
pub const ADDR: &str = "0.0.0.0";
pub const PORT: u16 = 50051;

// pub const AI_PORT: u16 = 50052;

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

// -------------------------------------------------------------------------------------------------

// blacklist
// const DEFAULT_BLACKLIST_LINK: &str =
//     "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt";
//
// pub static BLACKLIST_LINK: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
//     std::env::var("BLACKLIST_LINK").unwrap_or_else(|_| DEFAULT_BLACKLIST_LINK.to_string())
// });

// -------------------------------------------------------------------------------------------------

// tls constants
pub static SERVER_CERT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::fs::read_to_string("./tls/appguard.pem")
        .handle_err(location!())
        .unwrap_or_default()
});

pub static SERVER_KEY: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::fs::read_to_string("./tls/appguard-key.pem")
        .handle_err(location!())
        .unwrap_or_default()
});

// pub static CA_CERT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
//     std::fs::read_to_string("test_material/tls/ca.cer")
//         .handle_err(location!())
//         .unwrap_or_default()
// });
