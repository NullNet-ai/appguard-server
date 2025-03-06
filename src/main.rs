// mod ai;
mod app_guard_impl;
mod config;
mod constants;
mod db;
mod deserialize;
mod entrypoint;
mod fetch_data;
mod firewall;
// mod from_sql;
mod helpers;
mod ip_info;
mod proto;
mod serialize;
// mod to_sql;

use crate::entrypoint::start_appguard;

pub fn main() {
    start_appguard().unwrap();
}
