use crate::db::entries::DbEntry;
use crate::db::store::store::DatastoreWrapper;
use tokio::sync::mpsc::UnboundedReceiver;

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
