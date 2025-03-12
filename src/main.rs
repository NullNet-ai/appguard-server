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
mod ip_info;
mod proto;
mod serialize;

use crate::entrypoint::start_appguard;

pub fn main() {
    start_appguard().unwrap();
}
