use crate::config::Config;
use crate::db::device::Device;
use crate::db::entries::DbEntry;
use crate::db::installation_code::InstallationCode;
use crate::db::tables::DbTable;
use crate::firewall::firewall::Firewall;
use crate::proto::appguard::{AppGuardIpInfo, Log};
use nullnet_libdatastore::{
    AdvanceFilter, BatchCreateBody, BatchCreateRequest, BatchDeleteBody, BatchDeleteRequest,
    BatchUpdateBody, BatchUpdateRequest, CreateBody, CreateParams, CreateRequest, GetByFilterBody,
    GetByFilterRequest, GetByIdRequest, LoginBody, LoginData, LoginParams, LoginRequest,
    MultipleSort, Params, Query, RegisterDeviceParams, RegisterDeviceRequest, Response,
    ResponseData, UpdateRequest, UpsertBody, UpsertRequest,
};
use nullnet_libdatastore::{DatastoreClient, DatastoreConfig};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::{json, Value};
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
            body: Some(CreateBody { record }),
        };

        log::trace!("Before create to {table}");
        let result = self.inner.create(request, token).await?;
        log::trace!("After create to {table}");
        Ok(result)
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
            body: Some(BatchCreateBody { records }),
        };

        log::trace!("Before create batch to {table}");
        let result = self.inner.batch_create(request, token).await?;
        log::trace!("After create batch to {table}");
        Ok(result)
    }

    pub(crate) async fn upsert(
        &mut self,
        entry: &DbEntry,
        conflict_columns: Vec<String>,
        token: &str,
    ) -> Result<ResponseData, Error> {
        let record = entry.to_json()?;
        let table = entry.table().to_str();

        let request = UpsertRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::new(),
            }),
            query: Some(Query {
                pluck: String::from("id"),
                durability: String::from("soft"),
            }),
            body: Some(UpsertBody {
                data: record,
                conflict_columns,
            }),
        };

        log::trace!("Before upsert to {table}");
        let result = self.inner.upsert(request, token).await?;
        log::trace!("After upsert to {table}");
        Ok(result)
    }

    // SELECT COUNT(*) FROM {table} WHERE ip = {ip}
    pub(crate) async fn is_ip_blacklisted(&mut self, ip: &str, token: &str) -> Result<bool, Error> {
        let table = DbTable::Blacklist.to_str();

        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::new(),
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
                is_case_sensitive_sorting: false,
            }),
        };

        log::trace!("Before get by filter to {table}");
        let result = self.inner.get_by_filter(request, token).await?.count > 0;
        log::trace!("After get by filter to {table}: {result}");
        Ok(result)
    }

    // SELECT * FROM {table} WHERE ip = {ip} LIMIT 1
    pub(crate) async fn get_ip_info(
        &mut self,
        ip: &str,
        token: String,
    ) -> Result<Option<AppGuardIpInfo>, Error> {
        let table = DbTable::IpInfo.to_str();

        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::new(),
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
                is_case_sensitive_sorting: false,
            }),
        };

        log::trace!("Before get by filter to {table}");
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
    // TODO: An error occurred while processing your request
    pub(crate) async fn get_oldest_timestamp(
        &mut self,
        table: DbTable,
        token: &str,
    ) -> Result<Option<String>, Error> {
        let table = table.to_str();
        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::new(),
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
                    is_case_sensitive_sorting: false,
                }],
                pluck_object: HashMap::default(),
                date_format: String::new(),
                is_case_sensitive_sorting: false,
            }),
        };

        log::trace!("Before get oldest timestamp to {table}");
        let result_json = self.inner.get_by_filter(request, token).await?.data;
        let result_vec: Option<Vec<String>> = serde_json::from_str(&result_json).ok();
        let result = result_vec.and_then(|v| v.first().cloned());
        log::trace!("After get oldest timestamp to {table}: {result:?}");
        Ok(result)
    }

    // DELETE FROM {table} WHERE timestamp <= {timestamp}
    /// todo: error 'missing FROM-clause entry for table "ip_blacklists"'
    pub(crate) async fn delete_old_entries(
        &mut self,
        table: DbTable,
        timestamp: &str,
        token: &str,
    ) -> Result<i32, Error> {
        let table = table.to_str();
        let request = BatchDeleteRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::new(),
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
        let count = self.inner.batch_delete(request, token).await?.count;
        log::trace!("After delete old entries to {table}: {count}");
        Ok(count)
    }

    // SELECT app_id, firewall FROM {table}
    pub(crate) async fn get_firewalls(
        &mut self,
        token: String,
    ) -> Result<HashMap<String, Firewall>, Error> {
        let table = DbTable::Firewall.to_str();

        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::new(),
            }),
            body: Some(GetByFilterBody {
                pluck: vec!["app_id".to_string(), "firewall".to_string()],
                advance_filters: vec![],
                order_by: String::new(),
                limit: i32::MAX,
                offset: 0,
                order_direction: String::new(),
                joins: vec![],
                multiple_sort: vec![],
                pluck_object: HashMap::default(),
                date_format: String::new(),
                is_case_sensitive_sorting: false,
            }),
        };

        log::trace!("Before get by filter to {table}");
        let result = self.inner.get_by_filter(request, &token).await?.data;
        log::trace!("After get by filter to {table}: {result}");

        Self::internal_firewall_parse_response_data(&result)
    }

    fn internal_firewall_parse_response_data(
        data: &str,
    ) -> Result<HashMap<String, Firewall>, Error> {
        let mut ret_val = HashMap::new();

        let array_val = serde_json::from_str::<serde_json::Value>(data).handle_err(location!())?;
        let array = array_val
            .as_array()
            .ok_or("Failed to parse response")
            .handle_err(location!())?;

        for i in array {
            let Some(map) = i.as_object() else { continue };
            let Some(app_id_val) = map.get("app_id") else {
                continue;
            };
            let Some(app_id_str) = app_id_val.as_str() else {
                continue;
            };
            let Some(firewall_val) = map.get("firewall") else {
                continue;
            };
            let Some(firewall_str) = firewall_val.as_str() else {
                continue;
            };
            let Some(firewall) = Firewall::from_postfix(firewall_str).ok() else {
                continue;
            };
            ret_val.insert(app_id_str.to_string(), firewall);
        }

        Ok(ret_val)
    }

    pub(crate) async fn get_configs(&mut self, token: String) -> Result<Config, Error> {
        let table = DbTable::Config.to_str();

        let request = GetByFilterRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::new(),
            }),
            body: Some(GetByFilterBody {
                pluck: vec![
                    "log_request".to_string(),
                    "log_response".to_string(),
                    "retention_sec".to_string(),
                    "ip_info_cache_size".to_string(),
                ],
                advance_filters: vec![],
                order_by: String::new(),
                limit: 1,
                offset: 0,
                order_direction: String::new(),
                joins: vec![],
                multiple_sort: vec![],
                pluck_object: HashMap::default(),
                date_format: String::new(),
                is_case_sensitive_sorting: false,
            }),
        };

        log::trace!("Before get by filter to {table}");
        let result = self.inner.get_by_filter(request, &token).await?.data;
        log::trace!("After get by filter to {table}: {result}");

        Self::internal_configs_parse_response_data(&result)
    }

    fn internal_configs_parse_response_data(data: &str) -> Result<Config, Error> {
        let array_val = serde_json::from_str::<serde_json::Value>(data).handle_err(location!())?;
        let array = array_val
            .as_array()
            .ok_or("Failed to parse response")
            .handle_err(location!())?;

        let i = array
            .first()
            .ok_or("No data found")
            .handle_err(location!())?;

        let map = i
            .as_object()
            .ok_or("Invalid data")
            .handle_err(location!())?;
        let log_request = map
            .get("log_request")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let log_response = map
            .get("log_response")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let retention_sec = map
            .get("retention_sec")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let ip_info_cache_size = map
            .get("ip_info_cache_size")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1000) as usize;

        Ok(Config {
            log_request,
            log_response,
            retention_sec,
            ip_info_cache_size,
        })
    }

    pub async fn login(
        &self,
        account_id: String,
        account_secret: String,
        is_root: bool,
    ) -> Result<String, Error> {
        let request = LoginRequest {
            params: Some(LoginParams {
                is_root: if is_root {
                    String::from("root")
                } else {
                    String::new()
                },
                t: String::new(),
            }),
            body: Some(LoginBody {
                data: Some(LoginData {
                    account_id: account_id.to_owned(),
                    account_secret: account_secret.to_owned(),
                }),
            }),
        };

        log::trace!("Before login");
        let response = self.inner.clone().login(request).await?;
        log::trace!("After login");

        Ok(response.token)
    }

    // pub async fn device_status(
    //     &self,
    //     device_id: String,
    //     token: &str,
    // ) -> Result<DeviceStatus, Error> {
    //     let request = GetByIdRequest {
    //         params: Some(Params {
    //             id: device_id,
    //             table: String::from("devices"),
    //             r#type: String::new(),
    //         }),
    //         query: Some(Query {
    //             pluck: String::from("status"),
    //             durability: String::from("soft"),
    //         }),
    //     };
    //
    //     log::trace!("Before device status");
    //     let response = self.inner.clone().get_by_id(request, token).await?;
    //     log::trace!("After device status");
    //
    //     let status = Self::internal_ds_parse_response_data(&response.data)?;
    //
    //     Ok(map_status_value_to_enum(&status))
    // }

    // fn internal_ds_parse_response_data(data: &str) -> Result<String, Error> {
    //     serde_json::from_str::<serde_json::Value>(data)
    //         .handle_err(location!())?
    //         .as_array()
    //         .and_then(|arr| arr.first())
    //         .and_then(|obj| obj.as_object())
    //         .and_then(|map| map.get("status"))
    //         .and_then(|v| v.as_str())
    //         .map(std::string::ToString::to_string)
    //         .ok_or("Failed to parse response")
    //         .handle_err(location!())
    // }

    pub async fn device_setup(
        &self,
        token: &str,
        device_id: String,
        device_address: String,
    ) -> Result<ResponseData, Error> {
        let request = UpdateRequest {
            params: Some(Params {
                table: String::from("devices"),
                id: device_id,
                r#type: String::new(),
            }),
            query: Some(Query {
                pluck: String::from("id,code"),
                durability: String::from("soft"),
            }),
            body: json!({
                "device_version": "",
                "system_id": "",
                "ip_address": device_address,
                "is_connection_established": true,
                "status": "Active"
            })
            .to_string(),
        };

        log::trace!("Before device setup");
        let response = self.inner.clone().update(request, token).await?;
        log::trace!("After device setup");

        Ok(response)
    }

    // pub async fn register_device(
    //     &self,
    //     token: &str,
    //     account_id: &str,
    //     account_secret: &str,
    //     device: &Device,
    // ) -> Result<Response, Error> {
    //     let request = RegisterDeviceRequestBuilder::new()
    //         .account_id(account_id)
    //         .account_secret(account_secret)
    //         .account_organization_status("Active")
    //         .is_new_user(true)
    //         .add_account_organization_category("Device")
    //         .add_device_category("Device")
    //         .organization_id(&device.organization)
    //         .device_id(&device.id)
    //         .build();
    //
    //     let response = self.inner.clone().register_device(request, token).await?;
    //
    //     Ok(response)
    // }

    // pub async fn heartbeat(
    //     &self,
    //     token: &str,
    //     device_id: String,
    // ) -> Result<LatestDeviceInfo, Error> {
    //     let (create_result, fetch_result) = tokio::join!(
    //         Self::internal_hb_create_hb_record(self.inner.clone(), device_id.clone(), token),
    //         Self::internal_hb_fetch_device_info(self.inner.clone(), device_id, token)
    //     );
    //
    //     let _ = create_result?;
    //
    //     fetch_result
    // }

    pub async fn logs_insert(&self, token: &str, logs: Vec<Log>) -> Result<ResponseData, Error> {
        match logs.as_slice() {
            [] => Ok(ResponseData {
                count: 0,
                data: String::new(),
                encoding: String::new(),
            }),
            [log] => self.clone().logs_insert_single(log.to_owned(), token).await,
            _ => self.clone().logs_insert_batch(logs, token).await,
        }
    }

    // TODO: There was an error while creating the new record
    async fn logs_insert_single(&mut self, log: Log, token: &str) -> Result<ResponseData, Error> {
        let record = serde_json::to_string(&log).handle_err(location!())?;

        let request = CreateRequest {
            params: Some(CreateParams {
                table: String::from("appguard_logs"),
            }),
            query: Some(Query {
                pluck: String::from("id"),
                durability: String::from("soft"),
            }),
            body: Some(CreateBody { record }),
        };

        println!("Before single log insert");
        let res = self.inner.create(request, token).await?;
        println!("After single log insert");

        Ok(res)
    }

    async fn logs_insert_batch(
        &mut self,
        logs: Vec<Log>,
        token: &str,
    ) -> Result<ResponseData, Error> {
        let records = serde_json::to_string(&logs).handle_err(location!())?;

        let request = BatchCreateRequest {
            params: Some(CreateParams {
                table: String::from("appguard_logs"),
            }),
            query: Some(Query {
                pluck: String::new(),
                durability: String::from("soft"),
            }),
            body: Some(BatchCreateBody { records }),
        };

        println!("Before batch log insert");
        let res = self.inner.batch_create(request, token).await?;
        println!("After batch log insert");

        Ok(res)
    }

    // TODO: There was an error while creating the new record
    // async fn internal_hb_create_hb_record(
    //     mut client: DatastoreClient,
    //     device_id: String,
    //     token: &str,
    // ) -> Result<ResponseData, Error> {
    //     let request = CreateRequest {
    //         params: Some(CreateParams {
    //             table: String::from("device_heartbeats"),
    //         }),
    //         query: Some(Query {
    //             pluck: String::new(),
    //             durability: String::from("soft"),
    //         }),
    //         body: Some(CreateBody {
    //             record: json!({
    //                 "device_id": device_id.clone(),
    //                 "timestamp": Utc::now().to_rfc3339(),
    //             })
    //             .to_string(),
    //         }),
    //     };
    //
    //     log::trace!("Before create heartbeat record");
    //     let res = client.create(request, token).await?;
    //     log::trace!("After create heartbeat record");
    //
    //     Ok(res)
    // }

    // async fn internal_hb_fetch_device_info(
    //     mut client: DatastoreClient,
    //     device_id: String,
    //     token: &str,
    // ) -> Result<LatestDeviceInfo, Error> {
    //     let request = GetByIdRequest {
    //         params: Some(Params {
    //             id: device_id,
    //             table: String::from("devices"),
    //             r#type: String::new(),
    //         }),
    //         query: Some(Query {
    //             pluck: String::from("status,is_monitoring_enabled,is_remote_access_enabled"),
    //             durability: String::from("soft"),
    //         }),
    //     };
    //
    //     log::trace!("Before fetch heartbeat device info");
    //     let response = client.get_by_id(request, token).await?;
    //     log::trace!("After fetch heartbeat device info");
    //     LatestDeviceInfo::from_response_data(&response)
    // }

    pub async fn obtain_device_by_id(
        &self,
        token: &str,
        device_id: &str,
        performed_by_root: bool,
    ) -> Result<Option<Device>, Error> {
        let r#type = if performed_by_root {
            String::from("root")
        } else {
            String::new()
        };

        let request = GetByIdRequest {
            params: Some(Params {
                id: String::from(device_id),
                table: String::from("devices"),
                r#type,
            }),
            query: Some(Query {
                pluck: serde_json::to_string(&vec![
                    "id",
                    "device_uuid",
                    "is_traffic_monitoring_enabled",
                    "is_config_monitoring_enabled",
                    "is_telemetry_monitoring_enabled",
                    "is_device_authorized",
                    "device_category",
                    "device_model",
                    "device_os",
                    "is_device_online",
                    "organization_id",
                ])
                .unwrap(),
                durability: String::from("soft"),
            }),
        };

        let response = self.inner.clone().get_by_id(request, token).await?;
        if response.count == 0 {
            return Ok(None);
        }

        let json_data = serde_json::from_str::<Value>(&response.data).handle_err(location!());
        let data = json_data?
            .as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or("Operation failed")
            .handle_err(location!())?;

        let device = serde_json::from_value::<Device>(data).handle_err(location!())?;
        Ok(Some(device))
    }

    pub async fn register_device(
        &self,
        token: &str,
        account_id: &str,
        account_secret: &str,
        device: &Device,
    ) -> Result<Response, Error> {
        let request = RegisterDeviceRequest {
            device: Some(RegisterDeviceParams {
                organization_id: String::new(),
                account_id: String::from(account_id),
                account_secret: String::from(account_secret),
                is_new_user: true,
                is_invited: false,
                role_id: String::new(),
                account_organization_status: "Active".to_string(),
                account_organization_categories: vec![String::from("Device")],
                device_categories: vec![String::from("Device")],
                device_id: device.id.clone(),
            }),
        };

        let response = self.inner.clone().register_device(request, token).await?;

        Ok(response)
    }

    pub async fn update_device(
        &self,
        token: &str,
        device_id: &str,
        device: &Device,
    ) -> Result<bool, Error> {
        let request = UpdateRequest {
            params: Some(Params {
                id: String::from(device_id),
                table: String::from("devices"),
                r#type: String::new(),
            }),
            query: Some(Query {
                pluck: String::new(),
                durability: String::from("soft"),
            }),
            body: json!(device).to_string(),
        };

        let data = self.inner.clone().update(request, token).await?;

        Ok(data.count == 1)
    }

    pub async fn update_device_online_status(
        &self,
        token: &str,
        device_uuid: &str,
        is_online: bool,
    ) -> Result<(), Error> {
        let updates = json!({
            "is_device_online": is_online
        })
        .to_string();

        let filter = AdvanceFilter {
            r#type: String::from("criteria"),
            field: String::from("device_uuid"),
            operator: String::from("equal"),
            entity: String::from("devices"),
            values: format!("[\"{device_uuid}\"]"),
        };

        let request = BatchUpdateRequest {
            params: Some(Params {
                id: String::new(),
                table: String::from("devices"),
                r#type: String::new(),
            }),
            body: Some(BatchUpdateBody {
                advance_filters: vec![filter],
                updates,
            }),
        };

        let _ = self.inner.clone().batch_update(request, token).await;

        Ok(())
    }

    pub async fn create_device(&self, token: &str, device: &Device) -> Result<(), Error> {
        let mut json = json!(device);

        json.as_object_mut().unwrap().remove("id");

        let request = CreateRequest {
            params: Some(CreateParams {
                table: String::from("devices"),
            }),
            query: Some(Query {
                pluck: serde_json::to_string(&vec![
                    "id",
                    "device_uuid",
                    "is_traffic_monitoring_enabled",
                    "is_config_monitoring_enabled",
                    "is_telemetry_monitoring_enabled",
                    "is_device_authorized",
                    "device_category",
                    "device_model",
                    "device_os",
                    "is_device_online",
                    "organization_id",
                ])
                .unwrap(),
                durability: String::from("soft"),
            }),
            body: Some(CreateBody {
                record: json.to_string(),
            }),
        };

        let _ = self.inner.clone().create(request, token).await?;

        Ok(())
    }

    pub async fn obtain_device_by_uuid(
        &self,
        token: &str,
        device_uuid: &str,
    ) -> Result<Option<Device>, Error> {
        let filter = AdvanceFilter {
            r#type: String::from("criteria"),
            field: String::from("device_uuid"),
            operator: String::from("equal"),
            entity: String::from("devices"),
            values: format!("[\"{device_uuid}\"]"),
        };

        let request = GetByFilterRequest {
            body: Some(GetByFilterBody {
                pluck: vec![
                    "id".to_string(),
                    "device_uuid".to_string(),
                    "is_traffic_monitoring_enabled".to_string(),
                    "is_config_monitoring_enabled".to_string(),
                    "is_telemetry_monitoring_enabled".to_string(),
                    "is_device_authorized".to_string(),
                    "device_category".to_string(),
                    "device_model".to_string(),
                    "device_os".to_string(),
                    "is_device_online".to_string(),
                    "organization_id".to_string(),
                ],
                advance_filters: vec![filter],
                order_by: "timestamp".to_string(),
                limit: 1,
                offset: 0,
                order_direction: "desc".to_string(),
                joins: vec![],
                multiple_sort: vec![],
                pluck_object: HashMap::new(),
                date_format: String::new(),
                is_case_sensitive_sorting: true,
            }),
            params: Some(Params {
                id: String::new(),
                table: "devices".to_string(),
                r#type: String::from("root"),
            }),
        };

        let response = self.inner.clone().get_by_filter(request, token).await?;

        if response.count == 0 {
            return Ok(None);
        }

        let json_data = serde_json::from_str::<Value>(&response.data).handle_err(location!());
        let data = json_data?
            .as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or("Operation failed")
            .handle_err(location!())?;

        let device = serde_json::from_value::<Device>(data).handle_err(location!())?;
        Ok(Some(device))
    }

    pub async fn obtain_installation_code(
        &self,
        code: &str,
        token: &str,
    ) -> Result<Option<InstallationCode>, Error> {
        let filter = AdvanceFilter {
            r#type: String::from("criteria"),
            field: String::from("code"),
            operator: String::from("equal"),
            entity: String::from("installation_codes"),
            values: format!("[\"{code}\"]"),
        };

        let request = GetByFilterRequest {
            body: Some(GetByFilterBody {
                pluck: vec![
                    "id".into(),
                    "redeemed".into(),
                    "device_id".into(),
                    "device_code".into(),
                    "organization_id".into(),
                ],
                advance_filters: vec![filter],
                order_by: "timestamp".to_string(),
                limit: 1,
                offset: 0,
                order_direction: "desc".to_string(),
                joins: vec![],
                multiple_sort: vec![],
                pluck_object: HashMap::new(),
                date_format: String::new(),
                is_case_sensitive_sorting: true,
            }),
            params: Some(Params {
                id: String::new(),
                table: "installation_codes".to_string(),
                r#type: String::from("root"),
            }),
        };

        let response = self.inner.clone().get_by_filter(request, token).await?;

        if response.count == 0 {
            return Ok(None);
        }

        let json_data = serde_json::from_str::<Value>(&response.data).handle_err(location!());
        let data = json_data?
            .as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or("Operation failed")
            .handle_err(location!())?;

        let installation_code =
            serde_json::from_value::<InstallationCode>(data).handle_err(location!())?;
        Ok(Some(installation_code))
    }

    pub async fn redeem_installation_code(
        &self,
        code: &InstallationCode,
        token: &str,
    ) -> Result<(), Error> {
        let request = UpdateRequest {
            params: Some(Params {
                table: String::from("installation_codes"),
                id: code.id.clone(),
                r#type: String::from("root"),
            }),
            query: Some(Query {
                pluck: String::from("id,code"),
                durability: String::from("soft"),
            }),
            body: json!({"redeemed": true}).to_string(),
        };

        let _ = self.inner.clone().update(request, token).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::db::datastore_wrapper::DatastoreWrapper;
    use crate::firewall::firewall::Firewall;

    #[test]
    fn test_internal_firewall_parse_response_data() {
        let data = r#"[{"app_id": "app1", "firewall": "{\"timeout\" : 1000, \"default_policy\": \"allow\", \"expressions\": []}"}, {"app_id": "app2", "firewall": "{\"timeout\" : 2000, \"default_policy\": \"deny\", \"expressions\": [{\"policy\": \"deny\", \"postfix_tokens\": [{\"type\": \"predicate\", \"condition\": \"equal\", \"protocol\": [\"HTTPS\"]}]}]}"}]"#;
        let result = DatastoreWrapper::internal_firewall_parse_response_data(data).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(*result.get("app1").unwrap(), Firewall::default());
        assert_eq!(*result.get("app2").unwrap(), Firewall::from_postfix(r#"{"timeout" : 2000, "default_policy": "deny", "expressions": [{"policy": "deny", "postfix_tokens": [{"type": "predicate", "condition": "equal", "protocol": ["HTTPS"]}]}]}"#).unwrap());
    }
}
