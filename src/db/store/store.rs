use crate::db::entries::DbEntry;
use nullnet_libdatastore::{
    CreateBody, CreateParams, CreateRequest, LoginBody, LoginData, LoginRequest, Query,
    ResponseData,
};
use nullnet_libdatastore::{DatastoreClient, DatastoreConfig};
use nullnet_liberror::Error;

#[derive(Debug, Clone)]
pub struct DatastoreWrapper {
    inner: DatastoreClient,
}

impl DatastoreWrapper {
    pub(crate) async fn new() -> Result<Self, Error> {
        let config = DatastoreConfig::from_env();
        let inner = DatastoreClient::new(config).await?;
        Ok(Self { inner })
    }

    pub(crate) async fn insert(
        &mut self,
        entry: &DbEntry,
        token: &str,
    ) -> Result<ResponseData, Error> {
        let record = entry.to_json()?;
        let table = entry.table();

        let request = CreateRequest {
            params: Some(CreateParams {
                table: table.to_str().into(),
            }),
            query: Some(Query {
                pluck: String::from("id"),
                durability: String::from("soft"),
            }),
            body: Some(CreateBody {
                record,
                entity_prefix: String::from("LO"),
            }),
        };

        self.inner.create(request, token).await
    }

    pub async fn login(&self, account_id: String, account_secret: String) -> Result<String, Error> {
        let request = LoginRequest {
            body: Some(LoginBody {
                data: Some(LoginData {
                    account_id,
                    account_secret,
                }),
            }),
        };

        let response = self.inner.clone().login(request).await?;

        Ok(response.token)
    }
}
