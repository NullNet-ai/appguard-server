use crate::db::entries::DbEntry;
use crate::db::store::store::DatastoreWrapper;
use tokio::sync::mpsc::UnboundedReceiver;

// todo: create tables in datastore
// pub fn create_db_tables_and_views(conn: &Arc<Mutex<Connection>>) -> Result<(), Error> {
//     let sql_1 = DbTable::ALL
//         .into_iter()
//         .map(DbTable::sql_create)
//         .collect::<Vec<String>>()
//         .join("\n");
//     conn.lock()
//         .handle_err(location!())?
//         .execute_batch(&format!("BEGIN TRANSACTION;\n{sql_1}\nCOMMIT;"))
//         .handle_err(location!())?;
//
//     let sql_2 = DbView::ALL
//         .into_iter()
//         .map(DbView::sql_create)
//         .collect::<Vec<String>>()
//         .join("\n");
//     conn.lock()
//         .handle_err(location!())?
//         .execute_batch(&format!("BEGIN TRANSACTION;\n{sql_2}\nCOMMIT;"))
//         .handle_err(location!())?;
//
//     Ok(())
// }

// todo: create tables in datastore
// pub fn create_blacklist_tables(blacklist_conn: &Arc<Mutex<Connection>>) -> Result<(), Error> {
//     blacklist_conn
//         .lock()
//         .handle_err(location!())?
//         .execute(
//             "
//             CREATE TABLE IF NOT EXISTS blacklist (
//                 id INTEGER PRIMARY KEY,
//                 ip TEXT NOT NULL,
//                 count INTEGER NOT NULL
//             );
//         ",
//             [],
//         )
//         .handle_err(location!())?;
//
//     Ok(())
// }

// todo: delete old entries from datastore
// pub fn delete_old_entries(
//     config_pair: &Arc<(Mutex<Config>, Condvar)>,
//     conn: &DatastoreWrapper,
//     ip_info_cache: &Arc<Mutex<IndexMap<String, AppGuardIpInfo>>>,
// ) -> Result<(), Error> {
//     loop {
//         let retention_sec = config_pair.0.lock().handle_err(location!())?.retention_sec;
//
//         if retention_sec == 0 {
//             drop(
//                 config_pair
//                     .1
//                     .wait_while(config_pair.0.lock().handle_err(location!())?, |config| {
//                         config.retention_sec == 0
//                     })
//                     .handle_err(location!())?,
//             );
//             continue;
//         }
//
//         let threshold = Utc::now()
//             .sub(Duration::from_secs(retention_sec))
//             .to_rfc3339();
//         let mut oldest = get_timestamp_string();
//         let mut num_deleted = 0;
//
//         for table_name in DbTable::ALL.into_iter().map(DbTable::to_str) {
//             num_deleted += conn
//                 .lock()
//                 .handle_err(location!())?
//                 .execute(
//                     &format!("DELETE FROM {table_name} WHERE timestamp <= ?1"),
//                     [&threshold],
//                 )
//                 .handle_err(location!())?;
//             if let Ok(Some(table_oldest)) = get_oldest_timestamp(table_name, conn) {
//                 if table_oldest < oldest {
//                     oldest = table_oldest;
//                 }
//             }
//         }
//
//         if num_deleted > 0 {
//             log::info!("Deleted {num_deleted} item(s) from database older than {threshold}");
//             // clear the cache if at least one entry was deleted
//             ip_info_cache.lock().handle_err(location!())?.clear();
//         }
//
//         let _ = config_pair
//             .1
//             .wait_timeout_while(
//                 config_pair.0.lock().handle_err(location!())?,
//                 Duration::from_micros(timestamp_str_diff_usec(&oldest, &threshold)?),
//                 |config| config.retention_sec >= retention_sec,
//             )
//             .handle_err(location!())?;
//     }
// }

// todo: get ip info from datastore
// pub fn get_ipinfo_from_db(
//     ip: &str,
//     conn: &DatastoreWrapper,
// ) -> Result<Option<AppGuardIpInfo>, Error> {
//     let table_name = DbTable::IpInfo.to_str();
//     let c = conn.lock().handle_err(location!())?;
//     let mut stmt = c
//         .prepare(&format!("SELECT * FROM {table_name} WHERE ip = ?1"))
//         .handle_err(location!())?;
//
//     stmt.query_row([&ip], |row| {
//         Ok(AppGuardIpInfo {
//             ip: row.get(2)?,
//             country: row.get(3)?,
//             asn: row.get(4)?,
//             org: row.get(5)?,
//             ..Default::default()
//         })
//     })
//     .optional()
//     .handle_err(location!())
// }

// todo: get oldest timestamp from datastore
// fn get_oldest_timestamp(
//     table: &str,
//     conn: &Arc<Mutex<Connection>>,
// ) -> Result<Option<String>, Error> {
//     let c = conn.lock().handle_err(location!())?;
//     let mut stmt = c
//         .prepare(&format!("SELECT MIN(timestamp) FROM {table}"))
//         .handle_err(location!())?;
//
//     // SELECT MIN returns NULL if the table is empty
//     stmt.query_row([], |row| row.get(0)).handle_err(location!())
// }

pub async fn store_entries(ds: &DatastoreWrapper, rx: &mut UnboundedReceiver<DbEntry>) {
    loop {
        if let Some(entry) = rx.recv().await {
            entry.store(ds).await.unwrap_or_default();
        }
    }
}

// todo: get initial table ids from datastore
// pub fn get_initial_table_ids(conn: &Arc<Mutex<Connection>>) -> Result<TableIds, Error> {
//     let c = conn.lock().handle_err(location!())?;
//
//     let tcp_connection = get_max_table_id(&c, DbTable::TcpConnection.to_str())?.unwrap_or_default();
//     let http_request = get_max_table_id(&c, DbTable::HttpRequest.to_str())?.unwrap_or_default();
//     let http_response = get_max_table_id(&c, DbTable::HttpResponse.to_str())?.unwrap_or_default();
//     let smtp_request = get_max_table_id(&c, DbTable::SmtpRequest.to_str())?.unwrap_or_default();
//     let smtp_response = get_max_table_id(&c, DbTable::SmtpResponse.to_str())?.unwrap_or_default();
//
//     Ok(TableIds {
//         tcp_connection: Arc::new(Mutex::new(tcp_connection)),
//         http_request: Arc::new(Mutex::new(http_request)),
//         http_response: Arc::new(Mutex::new(http_response)),
//         smtp_request: Arc::new(Mutex::new(smtp_request)),
//         smtp_response: Arc::new(Mutex::new(smtp_response)),
//     })
// }

// todo: get max table id from datastore
// fn get_max_table_id(c: &MutexGuard<Connection>, table_name: &str) -> Result<Option<u64>, Error> {
//     let mut stmt = c
//         .prepare(&format!("SELECT MAX(id) FROM {table_name}",))
//         .handle_err(location!())?;
//
//     // SELECT MAX returns NULL if the table is empty
//     stmt.query_row([], |row| row.get(0)).handle_err(location!())
// }
