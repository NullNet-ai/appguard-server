use crate::config::Config;
use crate::db::datastore_wrapper::DatastoreWrapper;
use crate::db::entries::DbEntry;
use crate::db::tables::DbTable;
use crate::helpers::{get_timestamp_string, timestamp_str_diff_usec};
use crate::proto::appguard::AppGuardIpInfo;
use crate::token_provider::TokenProvider;
use chrono::Utc;
use indexmap::IndexMap;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use std::ops::Sub;
use std::sync::{Arc, Condvar};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

pub async fn delete_old_entries(
    config_pair: &Arc<(std::sync::Mutex<Config>, Condvar)>,
    ds: &DatastoreWrapper,
    ip_info_cache: &Arc<Mutex<IndexMap<String, AppGuardIpInfo>>>,
    token_provider: TokenProvider,
) -> Result<(), Error> {
    loop {
        let retention_sec = config_pair.0.lock().handle_err(location!())?.retention_sec;

        if retention_sec == 0 {
            drop(
                config_pair
                    .1
                    .wait_while(config_pair.0.lock().handle_err(location!())?, |config| {
                        config.retention_sec == 0
                    })
                    .handle_err(location!())?,
            );
            continue;
        }

        let threshold = Utc::now()
            .sub(Duration::from_secs(retention_sec))
            .to_rfc3339();
        let mut oldest = get_timestamp_string();
        let token = token_provider.get().await?.jwt.clone();

        let num_deleted = ds
            .clone()
            .delete_old_entries(DbTable::IpInfo, threshold.as_str(), token.as_str())
            .await?;

        if let Ok(Some(table_oldest)) = ds
            .clone()
            .get_oldest_timestamp(DbTable::IpInfo, token.as_str())
            .await
        {
            if table_oldest < oldest {
                oldest = table_oldest;
            }
        }

        if num_deleted > 0 {
            log::info!("Deleted {num_deleted} IP info(s) from datastore older than {threshold}");
            // clear the cache if at least one entry was deleted
            ip_info_cache.lock().await.clear();
        }

        let _ = config_pair
            .1
            .wait_timeout_while(
                config_pair.0.lock().handle_err(location!())?,
                Duration::from_micros(timestamp_str_diff_usec(&oldest, &threshold)?),
                |config| config.retention_sec >= retention_sec,
            )
            .handle_err(location!())?;
    }
}

pub async fn store_entries(ds: &DatastoreWrapper, rx: &mut UnboundedReceiver<DbEntry>) {
    loop {
        if let Some(entry) = rx.recv().await {
            let ds = ds.clone();
            tokio::spawn(async move { entry.store(ds).await.unwrap_or_default() });
        }
    }
}
