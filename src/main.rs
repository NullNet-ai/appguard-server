mod app_context;
mod app_guard_impl;
mod auth_handler;
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

use crate::entrypoint::start_appguard;

pub fn main() {
    start_appguard().unwrap();
}
