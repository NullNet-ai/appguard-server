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
#[cfg(debug_assertions)]
pub const ADDR: &str = "localhost";
#[cfg(not(debug_assertions))]
pub const ADDR: &str = "appguard";

pub const PORT: u16 = 50051;

// pub const AI_PORT: u16 = 50052;

pub static ACCOUNT_ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("ACCOUNT_ID").unwrap_or_else(|_| {
        log::warn!("Environment variable ACCOUNT_ID not found");
        String::new()
    })
});
pub static ACCOUNT_SECRET: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("ACCOUNT_SECRET").unwrap_or_else(|_| {
        log::warn!("Environment variable ACCOUNT_SECRET not found");
        String::new()
    })
});

// -------------------------------------------------------------------------------------------------

// config constants
#[cfg(not(debug_assertions))]
pub const CONFIG_DIR: &str = "/opt/config";
#[cfg(debug_assertions)]
pub const CONFIG_DIR: &str = "./test_material/config";

#[cfg(not(debug_assertions))]
pub const CONFIG_FILE: &str = "/opt/config/config.json";
#[cfg(debug_assertions)]
pub const CONFIG_FILE: &str = "./test_material/config/config.json";

// -------------------------------------------------------------------------------------------------

// blacklist
const DEFAULT_BLACKLIST_LINK: &str =
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt";

pub static BLACKLIST_LINK: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("BLACKLIST_LINK").unwrap_or_else(|_| DEFAULT_BLACKLIST_LINK.to_string())
});

// -------------------------------------------------------------------------------------------------

// firewall constants
#[cfg(not(debug_assertions))]
pub const FIREWALL_FILE: &str = "/opt/firewall/firewall.json";
#[cfg(debug_assertions)]
pub const FIREWALL_FILE: &str = "./test_material/firewall/firewall.json";

#[cfg(not(debug_assertions))]
pub const FIREWALL_DIR: &str = "/opt/firewall";
#[cfg(debug_assertions)]
pub const FIREWALL_DIR: &str = "./test_material/firewall";

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
