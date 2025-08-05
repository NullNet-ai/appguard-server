//! Handles the initial authorization of new client connections.
//!
//! This component is responsible for processing incoming `AuthorizationRequest`s,
//! validating and registering clients, and syncing device records with the datastore.
//! It prevents duplicate connections and ensures proper authorization flow based on device status.
//!
//! If the device does not exist in the datastore, it will be created in an unauthorized state.
//! If the device is already authorized, the handler attempts to authorize the client session.
//!
//! For rejected or failed authorization attempts, appropriate error messages are sent back via the outbound stream.

use crate::app_context::AppContext;
use crate::db::device::{Device, DeviceInstance};
use crate::helpers::generate_random_string;
use crate::orchestrator::client::{InboundStream, Instance, OutboundStream};
use crate::orchestrator::InstancesVector;
use crate::proto::appguard_commands::{AuthenticationData, AuthorizationRequest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::Status;

macro_rules! fail_with_status {
    ($outbound:expr, $msg:expr) => {{
        log::error!("{}", $msg);
        let _ = $outbound.send(Err(tonic::Status::internal($msg))).await;
        return;
    }};
}

pub struct AuthReqHandler {
    context: AppContext,
}

impl AuthReqHandler {
    pub fn new(context: AppContext) -> Self {
        Self { context }
    }

    pub async fn handle(
        self,
        inbound: InboundStream,
        outbound: OutboundStream,
        auth: AuthorizationRequest,
    ) {
        log::info!(
            "Auth request received: code={}, uuid={}",
            auth.code,
            auth.uuid
        );

        let mut clients = self.context.orchestrator.clients.lock().await;

        let root_token = match self.context.root_token_provider.get().await {
            Ok(token) => token,
            Err(_) => fail_with_status!(outbound, "Failed to obtain root token"),
        };

        let sys_token = match self.context.sysdev_token_provider.get().await {
            Ok(token) => token,
            Err(_) => fail_with_status!(outbound, "Failed to obtain system device token"),
        };

        let installation_code = match self
            .context
            .datastore
            .obtain_installation_code(&auth.code, &root_token.jwt)
            .await
        {
            Ok(code) => {
                if code.is_none() {
                    let status = Status::internal(format!("Code {} is invalid", auth.code));
                    let _ = outbound.send(Err(status)).await;
                    return;
                }

                code.unwrap()
            }
            Err(_) => fail_with_status!(outbound, "Failed to fetch installation code"),
        };

        if !installation_code.redeemed {
            let mut device = match self
                .context
                .datastore
                .obtain_device_by_id(&root_token.jwt, &installation_code.device_id, true)
                .await
            {
                Ok(Some(device)) => device,
                Ok(None) => {
                    fail_with_status!(outbound, "Device assosiated with the device does not exist")
                }
                Err(_) => fail_with_status!(outbound, "Failed to fetch device"),
            };

            device.authorized = true;
            device.online = true;
            device.os = auth.target_os;
            device.uuid = auth.uuid.clone();

            if self
                .context
                .datastore
                .update_device(&sys_token.jwt, &installation_code.device_id, &device)
                .await
                .is_err()
            {
                fail_with_status!(outbound, "Failed to update device")
            }

            if self
                .context
                .datastore
                .redeem_installation_code(&installation_code, &root_token.jwt)
                .await
                .is_err()
            {
                fail_with_status!(outbound, "Failed to redeem installation code")
            }

            let account_id = generate_random_string(12);
            let account_secret = generate_random_string(36);

            if self
                .context
                .datastore
                .register_device(&sys_token.jwt, &account_id, &account_secret, &device)
                .await
                .is_err()
            {
                fail_with_status!(outbound, "Failed to register device")
            }

            let authentication = AuthenticationData {
                app_id: Some(account_id),
                app_secret: Some(account_secret),
            };

            Self::add_device_instance(
                &mut clients,
                &device,
                &sys_token.jwt,
                inbound,
                outbound,
                self.context.clone(),
                Some(authentication),
            )
            .await;
        } else {
            let device = match self
                .context
                .datastore
                .obtain_device_by_uuid(&root_token.jwt, &auth.uuid)
                .await
            {
                Ok(device) => device,
                Err(_) => fail_with_status!(outbound, "Failed to obtain device"),
            };

            if device.is_some() {
                let device = device.unwrap();

                Self::add_device_instance(
                    &mut clients,
                    &device,
                    &sys_token.jwt,
                    inbound,
                    outbound,
                    self.context.clone(),
                    if device.authorized {
                        Some(AuthenticationData::default())
                    } else {
                        None
                    },
                )
                .await;
            } else {
                let mut device = Device {
                    authorized: false,
                    uuid: auth.uuid.clone(),
                    category: auth.category,
                    r#type: auth.r#type,
                    os: auth.target_os,
                    online: true,
                    organization: installation_code.organization_id.clone(),
                    ..Default::default()
                };

                let Ok(device_id) = self
                    .context
                    .datastore
                    .create_device(&sys_token.jwt, &device)
                    .await
                else {
                    fail_with_status!(outbound, "Failed to create device")
                };

                device.id = device_id;

                Self::add_device_instance(
                    &mut clients,
                    &device,
                    &sys_token.jwt,
                    inbound,
                    outbound,
                    self.context.clone(),
                    None,
                )
                .await;
            }
        }
    }

    async fn add_device_instance(
        clients: &mut HashMap<String, InstancesVector>,
        device: &Device,
        token: &str,
        inbound: InboundStream,
        outbound: OutboundStream,
        context: AppContext,
        authentication: Option<AuthenticationData>,
    ) {
        let device_instance = DeviceInstance {
            device_id: device.id.clone(),
            ..Default::default()
        };

        let Ok(instance_id) = context
            .datastore
            .create_device_instance(token, &device_instance)
            .await
        else {
            fail_with_status!(outbound, "Failed to create device instance")
        };

        let instance = Arc::new(Mutex::new(Instance::new(
            device.uuid.clone(),
            instance_id.into(),
            inbound,
            outbound,
            context,
        )));

        if clients.get(&device.uuid).is_none() {
            clients.insert(device.uuid.clone(), Default::default());
        }

        if let Some(auth_data) = authentication {
            if instance.lock().await.authorize(auth_data).await.is_ok() {
                clients
                    .get(&device.uuid)
                    .unwrap()
                    .lock()
                    .await
                    .push(instance);
            } else {
                log::error!("Failed to authorize a device");
            }
        } else {
            clients
                .get(&device.uuid)
                .unwrap()
                .lock()
                .await
                .push(instance);
        }
    }
}
