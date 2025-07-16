use crate::db::datastore_wrapper::DatastoreWrapper;
use data::AuthData;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libtoken::Token;
use std::sync::Arc;
use tokio::sync::Mutex;

mod data;

#[derive(Debug, Clone)]
pub struct TokenProvider {
    datastore: DatastoreWrapper,
    data: Arc<Mutex<AuthData>>,
}

impl TokenProvider {
    pub fn new(
        app_id: impl Into<String>,
        app_secret: impl Into<String>,
        is_root: bool,
        datastore: DatastoreWrapper,
    ) -> Self {
        let data = AuthData::new(app_id, app_secret, is_root);
        Self {
            datastore,
            data: Arc::new(Mutex::new(data)),
        }
    }

    pub async fn get(&self) -> Result<Arc<Token>, Error> {
        let mut lock = self.data.lock().await;

        if lock.needs_refresh() {
            let jwt = self
                .datastore
                .login(lock.app_id.clone(), lock.app_secret.clone(), lock.is_root)
                .await?;

            let token = Token::from_jwt(&jwt).handle_err(location!())?;

            lock.token = Some(Arc::new(token));
        }

        Ok(lock.token.as_ref().unwrap().clone())
    }
}
