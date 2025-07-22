use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use reqwest::{Client, ClientBuilder};

use crate::constants::BLACKLIST_LINK;
use crate::db::datastore_wrapper::DatastoreWrapper;
use crate::db::entries::DbEntry;
use crate::token_provider::TokenProvider;
use nullnet_liberror::{location, Error, ErrorHandler, Location};

pub async fn fetch_ip_data(ds: DatastoreWrapper, token_provider: TokenProvider) {
    if cfg!(test) {
        return;
    }

    let client = client_builder_with_ua()
        .timeout(Duration::from_secs(300))
        .build()
        .handle_err(location!())
        .unwrap_or_default();

    loop {
        fetch_ip_blacklist(ds.clone(), &client, token_provider.clone())
            .await
            .unwrap_or_default();
        tokio::time::sleep(Duration::from_secs(60 * 60 * 24)).await; // 24 hours
    }
}

pub async fn fetch_ip_blacklist(
    ds: DatastoreWrapper,
    client: &Client,
    token_provider: TokenProvider,
) -> Result<(), Error> {
    log::info!("Fetching IP blacklist from {}...", BLACKLIST_LINK.as_str());

    let blacklist_string = client
        .get(BLACKLIST_LINK.as_str())
        .send()
        .await
        .handle_err(location!())?
        .text()
        .await
        .handle_err(location!())?;
    let mut blacklist = vec![];

    log::info!("Remote IP blacklist fetched; updating blacklist in datastore...");

    let mut num_entries = 0;
    for line in blacklist_string.lines() {
        if let Some(ip_str) = line.split_whitespace().next() {
            if IpAddr::from_str(ip_str).is_ok() {
                blacklist.push(ip_str.to_string());
                num_entries += 1;
            }
        }
    }

    if num_entries == 0 {
        Err("No valid entries found in remote IP blacklist; local blacklist was not updated")
            .handle_err(location!())?;
    }

    let token = token_provider.get().await?.jwt.clone();

    DbEntry::Blacklist((blacklist, token)).store(ds).await?;

    log::info!("IP blacklist in datastore updated successfully ({num_entries} entries)");

    Ok(())
}

fn client_builder_with_ua() -> ClientBuilder {
    ClientBuilder::new().user_agent("AppGuard")
}
