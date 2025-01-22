use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use maxminddb::{MaxMindDBError, Reader};
use reqwest::{Client, ClientBuilder};
use rusqlite::{params, Connection};
use serde::Deserialize;

use crate::constants::{APP_GUARD_VERSION, BLACKLIST_LINK, IP_MMDB_LINK, MMDB_KEY};
use crate::error::{Error, ErrorHandler, Location};
use crate::helpers::get_env;
use crate::location;

pub async fn fetch_ip_data(
    blacklist_conn: &Arc<Mutex<Connection>>,
    mmdb_reader: &Arc<RwLock<MmdbReader>>,
) {
    if cfg!(test) {
        return;
    }

    let client = client_builder_with_ua()
        .timeout(Duration::from_secs(300))
        .build()
        .handle_err(location!())
        .unwrap_or_default();

    let mmdb_key = get_env(MMDB_KEY, "token", "IP info MMDB key");

    loop {
        fetch_ip_blacklist(blacklist_conn, &client)
            .await
            .unwrap_or_default();
        fetch_ip_info_mmdb(mmdb_reader, &mmdb_key, &client)
            .await
            .unwrap_or_default();
        tokio::time::sleep(Duration::from_secs(60 * 60 * 24)).await; // 24 hours
    }
}

pub async fn fetch_ip_blacklist(
    blacklist_conn: &Arc<Mutex<Connection>>,
    client: &Client,
) -> Result<(), Error> {
    log::info!("Fetching IP blacklist from remote...");

    let blacklist = client
        .get(BLACKLIST_LINK)
        .send()
        .await
        .handle_err(location!())?
        .text()
        .await
        .handle_err(location!())?;

    log::info!("Remote IP blacklist fetched; updating local blacklist...");

    let conn = blacklist_conn.lock().handle_err(location!())?;
    conn.execute("BEGIN TRANSACTION;", [])
        .handle_err(location!())?;
    conn.execute("DELETE FROM blacklist;", [])
        .handle_err(location!())?;

    let mut stmt = conn
        .prepare("INSERT INTO blacklist (ip, count) VALUES (?1, ?2);")
        .handle_err(location!())?;

    let mut num_entries = 0;
    for line in blacklist.lines() {
        if !line.trim().is_empty() && !line.contains('#') {
            let [ip_str, count_str]: [&str; 2] = line
                .split_whitespace()
                .collect::<Vec<&str>>()
                .try_into()
                .unwrap_or_default();
            let (Ok(_ip), Ok(count)) = (IpAddr::from_str(ip_str), count_str.parse::<usize>())
            else {
                continue;
            };
            stmt.execute(params![ip_str, count])
                .handle_err(location!())?;
            num_entries += 1;
        }
    }

    if num_entries == 0 {
        Err("No valid entries found in remote IP blacklist; local blacklist was not updated")
            .handle_err(location!())?;
    }

    conn.execute("COMMIT;", []).handle_err(location!())?;

    drop(stmt);
    drop(conn);

    log::info!("Local IP blacklist updated successfully ({num_entries} entries)");

    Ok(())
}

pub async fn fetch_ip_info_mmdb(
    mmdb_reader: &Arc<RwLock<MmdbReader>>,
    mmdb_key: &str,
    client: &Client,
) -> Result<(), Error> {
    if mmdb_key.is_empty() {
        log::warn!("IP info MMDB key not found (cannot download database)");
    } else {
        log::info!("Fetching IP info MMDB from remote...");

        let link = format!("{IP_MMDB_LINK}{mmdb_key}");
        let mmdb = client
            .get(link)
            .send()
            .await
            .handle_err(location!())?
            .bytes()
            .await
            .handle_err(location!())?
            .to_vec();
        *mmdb_reader.write().handle_err(location!())? =
            MmdbReader::Reader(Reader::from_source(mmdb).handle_err(location!())?);

        log::info!("IP info MMDB updated successfully");
    }

    Ok(())
}

#[derive(Default)]
pub enum MmdbReader {
    #[default]
    Empty,
    Reader(Reader<Vec<u8>>),
}

impl MmdbReader {
    pub fn lookup<'de, T: Default + Deserialize<'de>>(
        &'de self,
        ip: IpAddr,
    ) -> Result<T, MaxMindDBError> {
        match self {
            MmdbReader::Reader(reader) => reader.lookup(ip),
            MmdbReader::Empty => Ok(T::default()),
        }
    }
}

pub fn client_builder_with_ua() -> ClientBuilder {
    ClientBuilder::new().user_agent(format!("AppGuard-{APP_GUARD_VERSION}"))
}
