use std::time::Duration;

use reqwest::ClientBuilder;

use crate::constants::APP_GUARD_VERSION;
use crate::db::store::store::DatastoreWrapper;
use nullnet_liberror::{location, ErrorHandler, Location};

pub async fn fetch_ip_data(_ds: &DatastoreWrapper) {
    if cfg!(test) {
        return;
    }

    let _client = client_builder_with_ua()
        .timeout(Duration::from_secs(300))
        .build()
        .handle_err(location!())
        .unwrap_or_default();

    loop {
        // todo: fetch custom IP blacklist
        // fetch_ip_blacklist(blacklist_conn, &client)
        //     .await
        //     .unwrap_or_default();
        tokio::time::sleep(Duration::from_secs(60 * 60 * 24)).await; // 24 hours
    }
}

// todo: fetch custom IP blacklist and store it in datastore
// pub async fn fetch_ip_blacklist(
//     blacklist_conn: &Arc<Mutex<Connection>>,
//     client: &Client,
// ) -> Result<(), Error> {
//     log::info!("Fetching IP blacklist from remote...");
//
//     let blacklist = client
//         .get(BLACKLIST_LINK)
//         .send()
//         .await
//         .handle_err(location!())?
//         .text()
//         .await
//         .handle_err(location!())?;
//
//     log::info!("Remote IP blacklist fetched; updating local blacklist...");
//
//     let conn = blacklist_conn.lock().handle_err(location!())?;
//     conn.execute("BEGIN TRANSACTION;", [])
//         .handle_err(location!())?;
//     conn.execute("DELETE FROM blacklist;", [])
//         .handle_err(location!())?;
//
//     let mut stmt = conn
//         .prepare("INSERT INTO blacklist (ip, count) VALUES (?1, ?2);")
//         .handle_err(location!())?;
//
//     let mut num_entries = 0;
//     for line in blacklist.lines() {
//         if !line.trim().is_empty() && !line.contains('#') {
//             let [ip_str, count_str]: [&str; 2] = line
//                 .split_whitespace()
//                 .collect::<Vec<&str>>()
//                 .try_into()
//                 .unwrap_or_default();
//             let (Ok(_ip), Ok(count)) = (IpAddr::from_str(ip_str), count_str.parse::<usize>())
//             else {
//                 continue;
//             };
//             stmt.execute(params![ip_str, count])
//                 .handle_err(location!())?;
//             num_entries += 1;
//         }
//     }
//
//     if num_entries == 0 {
//         Err("No valid entries found in remote IP blacklist; local blacklist was not updated")
//             .handle_err(location!())?;
//     }
//
//     conn.execute("COMMIT;", []).handle_err(location!())?;
//
//     drop(stmt);
//     drop(conn);
//
//     log::info!("Local IP blacklist updated successfully ({num_entries} entries)");
//
//     Ok(())
// }

fn client_builder_with_ua() -> ClientBuilder {
    ClientBuilder::new().user_agent(format!("AppGuard-{APP_GUARD_VERSION}"))
}
