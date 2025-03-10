use crate::db::entries::DbEntry;
use crate::db::store::latest_device_info::LatestDeviceInfo;
use crate::helpers::map_status_value_to_enum;
use crate::proto::appguard::DeviceStatus;
use chrono::Utc;
use nullnet_libdatastore::{
    CreateBody, CreateParams, CreateRequest, GetByIdRequest, LoginBody, LoginData, LoginRequest,
    Params, Query, ResponseData, UpdateRequest,
};
use nullnet_libdatastore::{DatastoreClient, DatastoreConfig};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;

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

    pub async fn device_status(
        &self,
        device_id: String,
        token: &str,
    ) -> Result<DeviceStatus, Error> {
        let request = GetByIdRequest {
            params: Some(Params {
                id: device_id,
                table: String::from("devices"),
            }),
            query: Some(Query {
                pluck: String::from("status"),
                durability: String::from("soft"),
            }),
        };

        let response = self.inner.clone().get_by_id(request, token).await?;

        let status = Self::internal_ds_parse_response_data(&response.data)?;

        Ok(map_status_value_to_enum(&status))
    }

    fn internal_ds_parse_response_data(data: &str) -> Result<String, Error> {
        serde_json::from_str::<serde_json::Value>(data)
            .handle_err(location!())?
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|obj| obj.as_object())
            .and_then(|map| map.get("status"))
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string)
            .ok_or("Failed to parse response")
            .handle_err(location!())
    }

    pub async fn device_setup(
        &self,
        token: &str,
        device_id: String,
        device_version: String,
        device_uuid: String,
        device_address: String,
    ) -> Result<ResponseData, Error> {
        let request = UpdateRequest {
            params: Some(Params {
                table: String::from("devices"),
                id: device_id,
            }),
            query: Some(Query {
                pluck: String::from("id,code"),
                durability: String::from("soft"),
            }),
            body: json!({
                "device_version": device_version,
                "system_id": device_uuid,
                "ip_address": device_address,
                "is_connection_established": true,
                "status": "Active"
            })
            .to_string(),
        };

        let response = self.inner.clone().update(request, token).await?;

        Ok(response)
    }

    pub async fn heartbeat(
        &self,
        token: &str,
        device_id: String,
    ) -> Result<LatestDeviceInfo, Error> {
        let (create_result, fetch_result) = tokio::join!(
            Self::internal_hb_create_hb_record(self.inner.clone(), device_id.clone(), token),
            Self::internal_hb_fetch_device_info(self.inner.clone(), device_id, token)
        );

        let _ = create_result?;

        fetch_result
    }

    async fn internal_hb_create_hb_record(
        mut client: DatastoreClient,
        device_id: String,
        token: &str,
    ) -> Result<ResponseData, Error> {
        let request = CreateRequest {
            params: Some(CreateParams {
                table: String::from("device_heartbeats"),
            }),
            query: Some(Query {
                pluck: String::new(),
                durability: String::from("soft"),
            }),
            body: Some(CreateBody {
                record: json!({
                    "device_id": device_id.clone(),
                    "timestamp": Utc::now().to_rfc3339(),
                })
                .to_string(),
                entity_prefix: String::from("HB"),
            }),
        };

        let retval = client.create(request, token).await?;

        Ok(retval)
    }

    async fn internal_hb_fetch_device_info(
        mut client: DatastoreClient,
        device_id: String,
        token: &str,
    ) -> Result<LatestDeviceInfo, Error> {
        let request = GetByIdRequest {
            params: Some(Params {
                id: device_id,
                table: String::from("devices"),
            }),
            query: Some(Query {
                pluck: String::from("status,is_monitoring_enabled,is_remote_access_enabled"),
                durability: String::from("soft"),
            }),
        };

        let response = client.get_by_id(request, token).await?;
        LatestDeviceInfo::from_response_data(&response)
    }
}
