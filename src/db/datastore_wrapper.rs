use crate::config::Config;
use crate::db::device::{Device, DeviceInstance};
use crate::db::entries::DbEntry;
use crate::db::installation_code::InstallationCode;
use crate::db::tables::DbTable;
use crate::firewall::firewall::Firewall;
use crate::proto::appguard::{AppGuardIpInfo, Log};
use chrono::Utc;
use ipnetwork::IpNetwork;
use nullnet_libdatastore::{
    AdvanceFilter, AdvanceFilterBuilder, BatchCreateRequestBuilder, BatchDeleteBody,
    BatchDeleteRequest, BatchUpdateRequestBuilder, CreateRequestBuilder, DeleteRequestBuilder,
    EntityFieldFrom, EntityFieldTo, FieldRelation, GetByFilterRequestBuilder,
    GetByIdRequestBuilder, Join, LoginRequestBuilder, MultipleSort, Params, Query,
    RegisterDeviceRequestBuilder, Response, ResponseData, UpdateRequestBuilder, UpsertBody,
    UpsertRequest,
};
use nullnet_libdatastore::{DatastoreClient, DatastoreConfig};
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Sub;
use std::str::FromStr;
use std::time::Duration;

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

        let request = CreateRequestBuilder::new()
            .table(table)
            .durability("soft")
            .pluck(["id"])
            .record(record)
            .build();

        log::trace!("Before create to {table}");
        let result = self.inner.create(request, token).await?;
        log::trace!("After create to {table}");
        Ok(result)
    }

    // pub(crate) async fn insert_batch(
    //     &mut self,
    //     entry: &DbEntry,
    //     token: &str,
    // ) -> Result<ResponseData, Error> {
    //     let records = entry.to_json()?;
    //     let table = entry.table().to_str();
    //
    //     let request = BatchCreateRequest {
    //         params: Some(CreateParams {
    //             table: table.into(),
    //         }),
    //         query: Some(Query {
    //             pluck: String::from("id"),
    //             durability: String::from("soft"),
    //         }),
    //         body: Some(BatchCreateBody { records }),
    //     };
    //
    //     log::trace!("Before create batch to {table}");
    //     let result = self.inner.batch_create(request, token).await?;
    //     log::trace!("After create batch to {table}");
    //     Ok(result)
    // }

    pub(crate) async fn upsert(
        &mut self,
        entry: &DbEntry,
        conflict_columns: Vec<String>,
        token: &str,
    ) -> Result<ResponseData, Error> {
        let record = entry.to_json()?;
        let table = entry.table().to_str();

        // TODO: create builder for upsert requests
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
    // pub(crate) async fn is_ip_blacklisted(&mut self, ip: &str, token: &str) -> Result<bool, Error> {
    //     let table = DbTable::Blacklist.to_str();
    //
    //     let request = GetByFilterRequest {
    //         params: Some(Params {
    //             id: String::new(),
    //             table: table.into(),
    //             r#type: String::new(),
    //         }),
    //         body: Some(GetByFilterBody {
    //             pluck: vec!["id".to_string()],
    //             advance_filters: vec![AdvanceFilter {
    //                 r#type: "criteria".to_string(),
    //                 field: "ip".to_string(),
    //                 operator: "equal".to_string(),
    //                 entity: table.to_string(),
    //                 values: format!("[\"{ip}\"]"),
    //             }],
    //             order_by: String::new(),
    //             limit: 1,
    //             offset: 0,
    //             order_direction: String::new(),
    //             joins: vec![],
    //             multiple_sort: vec![],
    //             pluck_object: HashMap::default(),
    //             date_format: String::new(),
    //             is_case_sensitive_sorting: false,
    //         }),
    //     };
    //
    //     log::trace!("Before get by filter to {table}");
    //     let result = self.inner.get_by_filter(request, token).await?.count > 0;
    //     log::trace!("After get by filter to {table}: {result}");
    //     Ok(result)
    // }

    // SELECT * FROM {table} WHERE ip = {ip} LIMIT 1
    pub(crate) async fn get_ip_info(
        &mut self,
        ip: &str,
        token: String,
    ) -> Result<Option<AppGuardIpInfo>, Error> {
        let table = DbTable::IpInfo.to_str();

        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("ip")
            .operator("equal")
            .entity(table)
            .values(format!("[\"{ip}\"]"))
            .build();

        let request = GetByFilterRequestBuilder::new()
            .table(table)
            .pluck("*")
            .limit(1)
            .advance_filter(filter)
            .build();

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

    // TODO: spot error in this query
    // SELECT MIN(timestamp) FROM {table}
    pub(crate) async fn get_oldest_timestamp(
        &mut self,
        table: DbTable,
        token: &str,
    ) -> Result<Option<String>, Error> {
        let table = table.to_str();

        // TODO: create builder for MultipleSort
        let sort = MultipleSort {
            by_field: format!("{table}.timestamp"),
            by_direction: "asc".to_string(),
            is_case_sensitive_sorting: false,
        };

        let request = GetByFilterRequestBuilder::new()
            .table(table)
            .performed_by_root(true)
            .pluck("timestamp")
            .limit(1)
            .multiple_sort(sort)
            .build();

        log::trace!("Before get oldest timestamp to {table}");
        let result_json = self.inner.get_by_filter(request, token).await?.data;
        let result_vec: Option<Vec<String>> = serde_json::from_str(&result_json).ok();
        let result = result_vec.and_then(|v| v.first().cloned());
        log::trace!("After get oldest timestamp to {table}: {result:?}");
        Ok(result)
    }

    // DELETE FROM {table} WHERE timestamp <= {timestamp}
    pub(crate) async fn delete_old_entries(
        &mut self,
        table: DbTable,
        timestamp: &str,
        token: &str,
    ) -> Result<i32, Error> {
        let table = table.to_str();

        // TODO: builder for BatchDeleteRequest
        let request = BatchDeleteRequest {
            params: Some(Params {
                id: String::new(),
                table: table.into(),
                r#type: String::from("root"),
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

    pub(crate) async fn get_firewalls(
        &mut self,
        token: String,
    ) -> Result<HashMap<String, Firewall>, Error> {
        let table = DbTable::Firewall.to_str();

        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("active")
            .operator("equal")
            .entity(table)
            .values("[true]")
            .build();

        let request = GetByFilterRequestBuilder::new()
            .table(table)
            .performed_by_root(true)
            .plucks(["app_id", "firewall"])
            .advance_filter(filter)
            .limit(i32::MAX)
            .build();

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

        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("active")
            .operator("equal")
            .entity(table)
            .values("[true]")
            .build();

        let request = GetByFilterRequestBuilder::new()
            .table(table)
            .performed_by_root(true)
            .plucks(vec![
                "log_request",
                "log_response",
                "retention_sec",
                "ip_info_cache_size",
            ])
            .advance_filter(filter)
            .limit(1)
            .build();

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
            .ok_or("No active configs found for AppGuard")
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
        let request = LoginRequestBuilder::new()
            .set_root(is_root)
            .account_id(account_id)
            .account_secret(account_secret)
            .build();

        log::trace!("Before login");
        let response = self.inner.clone().login(request).await?;
        log::trace!("After login");

        if response.token.is_empty() {
            return Err("Unauthenticated: wrong app_id and/or app_secret").handle_err(location!());
        }

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
        let request = UpdateRequestBuilder::new()
            .id(device_id)
            .table("devices")
            .query("id,code", "soft")
            .body(
                json!({
                    "device_version": "",
                    "system_id": "",
                    "ip_address": device_address,
                    "is_connection_established": true,
                    "status": "Active"
                })
                .to_string(),
            )
            .build();

        log::trace!("Before device setup");
        let response = self.inner.clone().update(request, token).await?;
        log::trace!("After device setup");

        Ok(response)
    }

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

    async fn logs_insert_single(&mut self, log: Log, token: &str) -> Result<ResponseData, Error> {
        let record = serde_json::to_string(&log).handle_err(location!())?;

        let request = CreateRequestBuilder::new()
            .table("appguard_logs")
            .pluck(["id"])
            .durability("soft")
            .record(record)
            .build();

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

        let request = BatchCreateRequestBuilder::new()
            .table("appguard_logs")
            .durability("soft")
            .records(records)
            .build();

        println!("Before batch log insert");
        let res = self.inner.batch_create(request, token).await?;
        println!("After batch log insert");

        Ok(res)
    }

    pub async fn obtain_device_by_id(
        &self,
        token: &str,
        device_id: &str,
        performed_by_root: bool,
    ) -> Result<Option<Device>, Error> {
        let request = GetByIdRequestBuilder::new()
            .id(device_id)
            .table("devices")
            .performed_by_root(performed_by_root)
            .pluck(vec![
                "id",
                "device_uuid",
                "is_traffic_monitoring_enabled",
                "is_config_monitoring_enabled",
                "is_telemetry_monitoring_enabled",
                "is_device_authorized",
                "device_category",
                "device_type",
                "device_os",
                "device_name",
                "is_device_online",
                "organization_id",
            ])
            .durability("soft")
            .build();

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
        let request = RegisterDeviceRequestBuilder::new()
            .organization_id(&device.organization)
            .account_id(account_id)
            .account_secret(account_secret)
            .set_is_new_user(true)
            .set_is_invited(false)
            .account_organization_status("Active")
            .add_account_organization_category("Device")
            .add_device_category("Device")
            .device_id(&device.id)
            .build();

        let response = self.inner.clone().register_device(request, token).await?;

        Ok(response)
    }

    pub async fn update_device(
        &self,
        token: &str,
        device_id: &str,
        device: &Device,
    ) -> Result<bool, Error> {
        let request = UpdateRequestBuilder::new()
            .id(device_id)
            .table("devices")
            .query("", "soft")
            .body(json!(device).to_string())
            .build();

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

        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("device_uuid")
            .operator("equal")
            .entity("devices")
            .values(format!("[\"{device_uuid}\"]"))
            .build();

        let request = BatchUpdateRequestBuilder::new()
            .table("devices")
            .updates(updates)
            .advance_filter(filter)
            .build();

        let _ = self.inner.clone().batch_update(request, token).await;

        Ok(())
    }

    pub async fn create_device(&self, token: &str, device: &Device) -> Result<String, Error> {
        let mut json = json!(device);
        json.as_object_mut().unwrap().remove("id");

        let request = CreateRequestBuilder::new()
            .table("devices")
            .pluck(vec![
                "id",
                "device_uuid",
                "is_traffic_monitoring_enabled",
                "is_config_monitoring_enabled",
                "is_telemetry_monitoring_enabled",
                "is_device_authorized",
                "device_category",
                "device_type",
                "device_os",
                "device_name",
                "is_device_online",
                "organization_id",
            ])
            .durability("soft")
            .record(json.to_string())
            .build();

        let response = self.inner.clone().create(request, token).await?;

        let json_data = serde_json::from_str::<Value>(&response.data).handle_err(location!());
        let data = json_data?
            .as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or("Operation failed")
            .handle_err(location!())?;

        let retval = serde_json::from_value::<Device>(data).handle_err(location!())?;

        Ok(retval.id)
    }

    pub async fn create_device_instance(
        &self,
        token: &str,
        instance: &DeviceInstance,
    ) -> Result<String, Error> {
        let mut json = json!(instance);
        json.as_object_mut()
            .ok_or("Expected JSON object")
            .handle_err(location!())?
            .remove("id");

        let request = CreateRequestBuilder::new()
            .table("device_instances")
            .pluck(vec!["id", "device_id"])
            .record(json.to_string())
            .build();

        let response = self.inner.clone().create(request, token).await?;

        let json_data = serde_json::from_str::<Value>(&response.data).handle_err(location!());
        let data = json_data?
            .as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or("Operation failed")
            .handle_err(location!())?;

        let retval = serde_json::from_value::<DeviceInstance>(data).handle_err(location!())?;

        Ok(retval.id.clone())
    }

    pub async fn delete_device_instance(
        &self,
        token: &str,
        instance_id: &str,
    ) -> Result<(), Error> {
        let request = DeleteRequestBuilder::new()
            .id(instance_id)
            .table("device_instances")
            .build();

        let _ = self.inner.clone().delete(request, token).await?;

        Ok(())
    }

    pub async fn obtain_device_by_uuid(
        &self,
        token: &str,
        device_uuid: &str,
    ) -> Result<Option<Device>, Error> {
        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("device_uuid")
            .operator("equal")
            .entity("devices")
            .values(format!("[\"{device_uuid}\"]"))
            .build();

        let request = GetByFilterRequestBuilder::new()
            .plucks(vec![
                "id",
                "device_uuid",
                "is_traffic_monitoring_enabled",
                "is_config_monitoring_enabled",
                "is_telemetry_monitoring_enabled",
                "is_device_authorized",
                "device_category",
                "device_type",
                "device_os",
                "device_name",
                "is_device_online",
                "organization_id",
            ])
            .advance_filter(filter)
            .order_by("timestamp")
            .limit(1)
            .order_direction("desc")
            .case_sensitive_sorting(true)
            .table("devices")
            .performed_by_root(true)
            .build();

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
        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("code")
            .operator("equal")
            .entity("installation_codes")
            .values(format!("[\"{code}\"]"))
            .build();

        let request = GetByFilterRequestBuilder::new()
            .plucks(vec![
                "id",
                "redeemed",
                "device_id",
                "device_code",
                "organization_id",
            ])
            .advance_filter(filter)
            .order_by("timestamp")
            .limit(1)
            .order_direction("desc")
            .case_sensitive_sorting(true)
            .table("installation_codes")
            .performed_by_root(true)
            .build();

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
        let request = UpdateRequestBuilder::new()
            .table("installation_codes")
            .id(&code.id)
            .performed_by_root(true)
            .query("id,code", "soft")
            .body(json!({"redeemed": true}).to_string())
            .build();

        let _ = self.inner.clone().update(request, token).await;

        Ok(())
    }

    pub(crate) async fn deactivate_old_configs(&mut self, token: &str) -> Result<i32, Error> {
        let table = DbTable::Config.to_str();

        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("active")
            .operator("equal")
            .entity(table)
            .values("[true]")
            .build();

        let updates = json!({"active": false}).to_string();

        let request = BatchUpdateRequestBuilder::new()
            .table(table)
            .performed_by_root(true)
            .advance_filter(filter)
            .updates(updates)
            .build();

        log::trace!("Before batch update to {table}");
        let count = self.inner.batch_update(request, token).await?.count;
        log::trace!("After batch update to {table}: {count}");
        Ok(count)
    }

    pub(crate) async fn deactivate_old_firewalls(
        &mut self,
        token: &str,
        device_id: &str,
    ) -> Result<i32, Error> {
        let table = DbTable::Firewall.to_str();

        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("app_id")
            .operator("equal")
            .entity(table)
            .values(format!("[\"{device_id}\"]"))
            .build();

        let updates = json!({"active": false}).to_string();

        let request = BatchUpdateRequestBuilder::new()
            .table(table)
            .advance_filter(filter)
            .updates(updates)
            .build();

        log::trace!("Before batch update to {table}");
        let count = self.inner.batch_update(request, token).await?.count;
        log::trace!("After batch update to {table}: {count}");
        Ok(count)
    }

    pub(crate) async fn get_ip_aliases(
        &mut self,
        token: String,
        name: &str,
    ) -> Result<Vec<IpNetwork>, Error> {
        let table_aliases = DbTable::Alias.to_str();
        let table_ip_aliases = DbTable::IpAlias.to_str();

        let filter = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("name")
            .operator("equal")
            .entity(table_aliases)
            .values(format!("[\"{name}\"]"))
            .build();

        // TODO: builder for Join
        let join = Join {
            r#type: "left".to_string(),
            field_relation: Some(FieldRelation {
                to: Some(EntityFieldTo {
                    entity: table_ip_aliases.to_string(),
                    field: String::from("alias_id"),
                    alias: String::from(""),
                    limit: i32::MAX,
                    order_by: String::new(),
                    filters: Vec::new(),
                }),
                from: Some(EntityFieldFrom {
                    entity: table_aliases.to_string(),
                    field: String::from("id"),
                }),
            }),
        };

        let request = GetByFilterRequestBuilder::new()
            .table(table_aliases)
            .performed_by_root(true)
            .advance_filter(filter)
            .limit(i32::MAX)
            .join(join)
            .pluck_objects(HashMap::from([
                (
                    table_ip_aliases.to_string(),
                    String::from("[\"ip\", \"prefix\"]"),
                ),
                (table_aliases.to_string(), String::from("[\"id\"]")),
            ]))
            .build();

        log::trace!("Before get by filter to {table_aliases} and {table_ip_aliases}");
        let result = self.inner.get_by_filter(request, &token).await?.data;
        log::trace!("After get by filter to {table_aliases} and {table_ip_aliases}: {result}");

        Self::internal_ip_alias_parse_response_data(result)
    }

    fn internal_ip_alias_parse_response_data(data: String) -> Result<Vec<IpNetwork>, Error> {
        let array_val = serde_json::from_str::<serde_json::Value>(&data).handle_err(location!())?;
        let array = array_val
            .as_array()
            .ok_or("Failed to parse response")
            .handle_err(location!())?;

        let mut ret_val = Vec::new();

        for i in array {
            let Some(map) = i.as_object() else { continue };
            // this is the pluck object returned by a join query, so it's nested
            let Some(ip_aliases) = map.get("ip_aliases") else {
                continue;
            };
            let Some(ip_aliases_map) = ip_aliases.as_object() else {
                continue;
            };
            let Some(ip_val) = ip_aliases_map.get("ip") else {
                continue;
            };
            let Some(ip_addr) = ip_val.as_str().and_then(|ip| IpAddr::from_str(ip).ok()) else {
                continue;
            };
            let Some(prefix_val) = ip_aliases_map.get("prefix") else {
                continue;
            };
            let Some(prefix) = prefix_val.as_u64().and_then(|int| u8::try_from(int).ok()) else {
                continue;
            };
            let Ok(ip_network) = IpNetwork::new(ip_addr, prefix) else {
                continue;
            };
            ret_val.push(ip_network);
        }

        Ok(ret_val)
    }

    pub(crate) async fn upsert_quarantine_alias(&mut self, token: &str) -> Result<String, Error> {
        let record = json!(
            {
                "type": "host",
                "name": "quarantine",
                "description": "Alias for quarantined IPs",
                "alias_status": "Applied",
            }
        )
        .to_string();
        let table = "aliases";

        // TODO: Upsert builder
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
                conflict_columns: vec!["name".to_string()],
            }),
        };

        log::trace!("Before upsert to {table}");
        let result = self.inner.upsert(request, token).await?;
        log::trace!("After upsert to {table}");

        let id = Self::internal_upsert_quarantine_alias_parse_response_data(result.data)?;
        Ok(id)
    }

    fn internal_upsert_quarantine_alias_parse_response_data(data: String) -> Result<String, Error> {
        let array_val = serde_json::from_str::<serde_json::Value>(&data).handle_err(location!())?;
        let array = array_val
            .as_array()
            .ok_or("Failed to parse response")
            .handle_err(location!())?;

        let i = array
            .first()
            .ok_or("Error upserting quarantine alias")
            .handle_err(location!())?;

        let map = i
            .as_object()
            .ok_or("Invalid data")
            .handle_err(location!())?;
        let id = map
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or("Invalid data")
            .handle_err(location!())?
            .to_string();

        Ok(id)
    }

    pub async fn get_recent_urls_for_ip(
        &self,
        token: &str,
        ip: IpAddr,
        period: usize,
    ) -> Result<Vec<String>, Error> {
        let table = DbTable::HttpRequest.to_str();

        let filter_1 = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("ip")
            .operator("equal")
            .entity(table)
            .values(format!("[\"{ip}\"]"))
            .build();

        let filter_2 = AdvanceFilterBuilder::new()
            .r#type("operator")
            .operator("and")
            .build();

        let timestamp = Utc::now()
            .sub(Duration::from_secs(
                u64::try_from(period).handle_err(location!())?,
            ))
            .to_rfc3339();

        let filter_3 = AdvanceFilterBuilder::new()
            .r#type("criteria")
            .field("timestamp")
            .operator("greater_than_or_equal")
            .entity(table)
            .values(format!("[\"{timestamp}\"]"))
            .build();

        let request = GetByFilterRequestBuilder::new()
            .plucks(vec!["id", "original_url"])
            .advance_filters(vec![filter_1, filter_2, filter_3])
            .limit(i32::MAX)
            .case_sensitive_sorting(true)
            .table(table)
            .performed_by_root(true)
            .build();

        let result = self.inner.clone().get_by_filter(request, token).await?.data;

        Self::internal_recent_urls_for_ip_parse_response_data(result)
    }

    fn internal_recent_urls_for_ip_parse_response_data(data: String) -> Result<Vec<String>, Error> {
        let array_val = serde_json::from_str::<serde_json::Value>(&data).handle_err(location!())?;
        let array = array_val
            .as_array()
            .ok_or("Failed to parse response")
            .handle_err(location!())?;

        let mut ret_val = Vec::new();

        for i in array {
            let Some(map) = i.as_object() else { continue };
            let Some(original_url_val) = map.get("original_url") else {
                continue;
            };
            let Some(original_url) = original_url_val.as_str() else {
                continue;
            };
            ret_val.push(original_url.to_string());
        }

        Ok(ret_val)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::datastore_wrapper::DatastoreWrapper;
    use crate::firewall::firewall::Firewall;

    #[test]
    fn test_internal_firewall_parse_response_data() {
        let data = r#"[{"app_id": "app1", "firewall": "{\"timeout\" : 1000, \"default_policy\": \"allow\", \"cache\" : true, \"expressions\": []}"}, {"app_id": "app2", "firewall": "{\"timeout\" : 2000, \"default_policy\": \"deny\", \"cache\" : false,  \"expressions\": [{\"policy\": \"deny\", \"postfix_tokens\": [{\"type\": \"predicate\", \"condition\": \"equal\", \"protocol\": [\"HTTPS\"]}]}]}"}]"#;
        let result = DatastoreWrapper::internal_firewall_parse_response_data(data).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(*result.get("app1").unwrap(), Firewall::default());
        assert_eq!(*result.get("app2").unwrap(), Firewall::from_postfix(r#"{"timeout" : 2000, "default_policy": "deny", "cache" : false, "expressions": [{"policy": "deny", "postfix_tokens": [{"type": "predicate", "condition": "equal", "protocol": ["HTTPS"]}]}]}"#).unwrap());
    }
}
