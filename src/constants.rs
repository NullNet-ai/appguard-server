use nullnet_liberror::{location, ErrorHandler, Location};

// project-level constants
pub const APP_GUARD_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const API_KEY: Option<&str> = option_env!("API_KEY");

// -------------------------------------------------------------------------------------------------

// server constants
#[cfg(debug_assertions)]
pub const ADDR: &str = "localhost";
#[cfg(not(debug_assertions))]
pub const ADDR: &str = "appguard";

pub const PORT: u16 = 50051;

// pub const AI_PORT: u16 = 50052;

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

// remote source constants
// pub const BLACKLIST_LINK: &str =
//     "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt";

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
pub static SERVER_CERT: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
    std::fs::read_to_string("./tls/appguard.pem")
        .handle_err(location!())
        .unwrap_or_default()
});

pub static SERVER_KEY: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
    std::fs::read_to_string("./tls/appguard-key.pem")
        .handle_err(location!())
        .unwrap_or_default()
});

// pub static CA_CERT: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
//     std::fs::read_to_string("test_material/tls/ca.cer")
//         .handle_err(location!())
//         .unwrap_or_default()
// });
