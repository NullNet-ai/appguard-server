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
use crate::db::device::Device;
use crate::orchestrator::client::{Client, InboundStream, OutboundStream};
use crate::proto::appguard_commands::server_message::Message;
use crate::proto::appguard_commands::{AuthenticationData, AuthorizationRequest, ServerMessage};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::Status;

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
            "Auth request received: org_id={}, uuid={}",
            auth.org_id,
            auth.uuid
        );

        let mut clients = self.context.orchestrator.clients.lock().await;

        if clients.contains_key(&auth.uuid) {
            log::warn!(
                "Rejecting duplicate connection: device UUID {} is already connected",
                auth.uuid
            );
            let _ = outbound
                .send(Ok(ServerMessage {
                    message: Some(Message::AuthorizationRejectedMessage(())),
                }))
                .await;
            return;
        }

        let root_token = match self.context.root_token_provider.get().await {
            Ok(token) => token,
            Err(err) => {
                log::error!("Failed to fetch root token: {}", err.to_str());
                let status = Status::internal("Internal Server Error: wrong root credentials");
                let _ = outbound.send(Err(status)).await;
                return;
            }
        };

        let sys_token = match self.context.sysdev_token_provider.get().await {
            Ok(token) => token,
            Err(err) => {
                log::error!("Failed to fetch sysdevice token: {}", err.to_str());
                let status =
                    Status::internal("Internal Server Error: wrong system device credentials");
                let _ = outbound.send(Err(status)).await;
                return;
            }
        };

        let device = match self
            .context
            .datastore
            .obtain_device_by_uuid(&root_token.jwt, &auth.uuid)
            .await
        {
            Ok(device) => device,
            Err(err) => {
                log::error!("Failed to fetch device: {}", err.to_str());
                let status = Status::internal("Internal Server Error: datastore operation failed");
                let _ = outbound.send(Err(status)).await;
                return;
            }
        };

        if device.is_none() {
            let device = Device {
                authorized: false,
                uuid: auth.uuid.clone(),
                category: auth.category,
                model: auth.model,
                os: auth.target_os,
                online: true,
                organization: auth.org_id.clone(),
                ..Default::default()
            };

            if let Err(status) = self
                .context
                .datastore
                .create_device(&sys_token.jwt, &device)
                .await
                .map_err(|err| Status::internal(err.to_str()))
            {
                log::error!("Failed to create device credentials: {}", status);
                let _ = outbound.send(Err(status)).await;
                return;
            };

            let client = Client::new(
                auth.uuid.clone(),
                auth.org_id,
                inbound,
                outbound,
                self.context.clone(),
            );

            clients.insert(auth.uuid, Arc::new(Mutex::new(client)));
        } else {
            let device = device.unwrap();

            // @TODO:
            // Here we can check if device's data (`model`, `target_os` or `category`) has changed
            // and act accordingly.

            if let Err(status) = self
                .context
                .datastore
                .update_device_online_status(&sys_token.jwt, &device.uuid, true)
                .await
                .map_err(|err| Status::internal(err.to_str()))
            {
                log::error!("Failed to udpate device record: {}", status);
                let _ = outbound.send(Err(status)).await;
                return;
            }

            if !device.authorized {
                let client = Client::new(
                    auth.uuid.clone(),
                    auth.org_id,
                    inbound,
                    outbound,
                    self.context.clone(),
                );

                clients.insert(auth.uuid, Arc::new(Mutex::new(client)));
            } else {
                let authentication = AuthenticationData::default();

                let client = Arc::new(Mutex::new(Client::new(
                    auth.uuid.clone(),
                    auth.org_id,
                    inbound,
                    outbound,
                    self.context.clone(),
                )));

                if client.lock().await.authorize(authentication).await.is_ok() {
                    clients.insert(auth.uuid, client.clone());
                } else {
                    log::error!("Failed to authorize a device")
                }
            }
        }
    }
}
