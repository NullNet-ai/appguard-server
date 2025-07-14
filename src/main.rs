mod app_context;
mod app_guard_impl;
mod config;
mod constants;
mod db;
mod deserialize;
mod display;
mod entrypoint;
mod fetch_data;
mod firewall;
mod helpers;
mod http_proxy;
mod ip_info;
mod orchestrator;
mod proto;
mod serialize;
mod token_provider;

use crate::app_context::AppContext;
use crate::entrypoint::start_appguard;
use crate::http_proxy::run_http_proxy;

#[tokio::main]
pub async fn main() {
    env_logger::init();

    let app_context = AppContext::new().await.unwrap_or_else(|err| {
        log::error!("Failed to initialize application context: {}", err.to_str());
        std::process::exit(1);
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = start_appguard(app_context.clone()) => {},
        _ = run_http_proxy(app_context) => {}
    }
}
