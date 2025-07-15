// use crate::helpers::map_status_value_to_enum;
// use nullnet_libdatastore::ResponseData;
// use nullnet_liberror::{location, Error, ErrorHandler, Location};
//
// pub struct LatestDeviceInfo {
//     pub status: DeviceStatus,
// }
//
// impl LatestDeviceInfo {
//     pub fn from_response_data(response: &ResponseData) -> Result<Self, Error> {
//         let json =
//             serde_json::from_str::<serde_json::Value>(&response.data).handle_err(location!())?;
//         Self::from_json(&json)
//     }
//
//     fn from_json(value: &serde_json::Value) -> Result<Self, Error> {
//         let object = value
//             .as_array()
//             .and_then(|arr| arr.first())
//             .and_then(|obj| obj.as_object())
//             .ok_or("Unexpected response data format")
//             .handle_err(location!())?;
//
//         let status = object
//             .get("status")
//             .and_then(|v| v.as_str())
//             .map(std::string::ToString::to_string)
//             .ok_or("Could not parse 'status'")
//             .handle_err(location!())?;
//
//         Ok(Self {
//             status: map_status_value_to_enum(&status),
//         })
//     }
// }
