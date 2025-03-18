use crate::db::datastore_wrapper::DatastoreWrapper;
use crate::db::entries::DbEntry;
use tokio::sync::mpsc::UnboundedReceiver;

pub async fn store_entries(ds: &DatastoreWrapper, rx: &mut UnboundedReceiver<DbEntry>) {
    loop {
        if let Some(entry) = rx.recv().await {
            let ds = ds.clone();
            tokio::spawn(async move { entry.store(ds).await.unwrap_or_default() });
        }
    }
}
