use crate::db::entries::DbEntry;
use crate::db::store::store::DatastoreWrapper;
use tokio::sync::mpsc::UnboundedReceiver;

// todo: create blacklist table in datastore
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

pub async fn store_entries(ds: &DatastoreWrapper, rx: &mut UnboundedReceiver<DbEntry>) {
    loop {
        if let Some(entry) = rx.recv().await {
            let ds = ds.clone();
            tokio::spawn(async move { entry.store(ds).await.unwrap_or_default() });
        }
    }
}
