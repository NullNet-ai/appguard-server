use crate::db::entries::DbEntry;
use crate::db::store::latest_device_info::LatestDeviceInfo;
use crate::helpers::{authenticate, map_status_value_to_enum};
use crate::proto::appguard::{AppGuardIpInfo, Authentication, DeviceStatus};
use chrono::Utc;
use nullnet_libdatastore::{
    AdvanceFilter, BatchCreateBody, BatchCreateRequest, BatchDeleteBody, BatchDeleteRequest,
    CreateBody, CreateParams, CreateRequest, GetByFilterBody, GetByFilterRequest, GetByIdRequest,
    LoginBody, LoginData, LoginRequest, MultipleSort, Params, Query, ResponseData, UpdateRequest,
};
use nullnet_libdatastore::{DatastoreClient, DatastoreConfig};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::json;
use std::collections::HashMap;

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
        let table = entry.table().to_str();

        let request = CreateRequest {
            params: Some(CreateParams {
                table: table.into(),
            }),
            query: Some(Query {
                pluck: String::from("id"),
                durability: String::from("soft"),
            }),
            body: Some(CreateBody {
                record,
                entity_prefix: String::from("AG"),
            }),
        };

        log::trace!("Before create to {table}");
        let result = self.inner.create(request, token).await;
        log::trace!("After create to {table}");
        result
    }

    pub(crate) async fn insert_batch(
        &mut self,
        entry: &DbEntry,
        token: &str,
    ) -> Result<ResponseData, Error> {
        let records = entry.to_json()?;
        let table = entry.table().to_str();

        let request = BatchCreateRequest {
            params: Some(CreateParams {
                table: table.into(),
            }),
            query: Some(Query {
                pluck: String::from("id"),
                durability: String::from("soft"),
            }),
            body: Some(BatchCreateBody {
                records,
                entity_prefix: String::from("BL"),
            }),
        };

        log::trace!("Before create batch to {table}");
        let result = self.inner.batch_create(request, token).await;
        log::trace!("After create batch to {table}");
        result
    }

    // SELECT COUNT(*) FROM {table} WHERE ip = {ip}
    pub(crate) async fn is_ip_blacklisted(&mut self, ip: &str, token: &str) -> Result<bool, Error> {
        let table = "ip_blacklist";

        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
            }),
            body: Some(GetByFilterBody {
                pluck: vec!["id".to_string()],
                advance_filters: vec![AdvanceFilter {
                    r#type: "criteria".to_string(),
                    field: "ip".to_string(),
                    operator: "equal".to_string(),
                    entity: table.to_string(),
                    values: format!("[\"{ip}\"]"),
                }],
                order_by: String::new(),
                limit: 1,
                offset: 0,
                order_direction: String::new(),
                joins: vec![],
                multiple_sort: vec![],
                pluck_object: HashMap::default(),
                date_format: String::new(),
            }),
        };

        log::trace!("Before get by filter to {table}");
        // todo: verify query
        let result = self.inner.get_by_filter(request, token).await?.count > 0;
        log::trace!("After get by filter to {table}: {result}");
        Ok(result)
    }

    // SELECT * FROM {table} WHERE ip = {ip} LIMIT 1
    pub(crate) async fn get_ip_info(
        &mut self,
        ip: &str,
        auth: Option<Authentication>,
    ) -> Result<Option<AppGuardIpInfo>, Error> {
        let (token, _) = authenticate(auth)?;
        let table = "ip_info";

        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
            }),
            body: Some(GetByFilterBody {
                pluck: vec!["*".to_string()],
                advance_filters: vec![AdvanceFilter {
                    r#type: "criteria".to_string(),
                    field: "ip".to_string(),
                    operator: "equal".to_string(),
                    entity: table.to_string(),
                    values: format!("[\"{ip}\"]"),
                }],
                order_by: String::new(),
                limit: 1,
                offset: 0,
                order_direction: String::new(),
                joins: vec![],
                multiple_sort: vec![],
                pluck_object: HashMap::default(),
                date_format: String::new(),
            }),
        };

        log::trace!("Before get by filter to {table}");
        // todo: verify query
        let result_json = self
            .inner
            .get_by_filter(request, token.as_str())
            .await?
            .data;
        let result_vec: Option<Vec<AppGuardIpInfo>> = serde_json::from_str(&result_json).ok();
        let result = result_vec.and_then(|v| v.first().cloned());
        log::trace!("After get by filter to {table}: {result:?}");
        Ok(result)
    }

    // SELECT MIN(timestamp) FROM {table}
    pub(crate) async fn get_oldest_timestamp(
        &mut self,
        table: &str,
        token: &str,
    ) -> Result<Option<String>, Error> {
        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
            }),
            body: Some(GetByFilterBody {
                pluck: vec!["timestamp".to_string()],
                advance_filters: vec![],
                order_by: String::new(),
                limit: 1,
                offset: 0,
                order_direction: String::new(),
                joins: vec![],
                multiple_sort: vec![MultipleSort {
                    by_field: format!("{table}.timestamp"),
                    by_direction: "asc".to_string(),
                }],
                pluck_object: HashMap::default(),
                date_format: String::new(),
            }),
        };

        log::trace!("Before get oldest timestamp to {table}");
        // todo: verify query
        let result_json = self.inner.get_by_filter(request, token).await?.data;
        let result_vec: Option<Vec<String>> = serde_json::from_str(&result_json).ok();
        let result = result_vec.and_then(|v| v.first().cloned());
        log::trace!("After get oldest timestamp to {table}: {result:?}");
        Ok(result)
    }

    // DELETE FROM {table} WHERE timestamp <= {timestamp}
    pub(crate) async fn delete_old_entries(
        &mut self,
        table: &str,
        timestamp: &str,
        token: &str,
    ) -> Result<i32, Error> {
        let request = BatchDeleteRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
            }),
            body: Some(BatchDeleteBody {
                advance_filters: vec![AdvanceFilter {
                    r#type: "criteria".to_string(),
                    field: "timestamp".to_string(),
                    operator: "less_than_or_equal".to_string(),
                    entity: table.to_string(),
                    values: format!("[\"{timestamp}\"]"),
                }],
            }),
        };

        log::trace!("Before delete old entries to {table}");
        // todo: verify query
        let count = self.inner.batch_delete(request, token).await?.count;
        log::trace!("After delete old entries to {table}: {count}");
        Ok(count)
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
