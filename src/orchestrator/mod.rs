use client::Client;
use nullnet_liberror::{Error, ErrorHandler, Location, location};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    app_context::AppContext,
    orchestrator::{
        client::{InboundStream, OutboundStream},
        new_connection_handler::NewConnectionHandler,
    },
};

mod auth_request_handler;
mod client;
mod control_stream;
mod new_connection_handler;

type ClientsMap = Arc<Mutex<HashMap<String, Arc<Mutex<Client>>>>>;

#[derive(Debug, Clone, Default)]
pub struct Orchestrator {
    pub(crate) clients: ClientsMap,
}

impl Orchestrator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_new_connection(
        &self,
        inbound: InboundStream,
        outbound: OutboundStream,
        context: AppContext,
    ) {
        log::info!("Orchestrator: on_new_connection");
        let handler = NewConnectionHandler::new(context);
        tokio::spawn(handler.handle(inbound, outbound));
    }

    pub async fn on_disconnected(&self, uuid: &str) -> Result<(), Error> {
        log::info!("Orchestrator: on_client_disconnected, uuid {}", uuid);

        if self.clients.lock().await.remove(uuid).is_none() {
            Err(format!("Device with UUID '{}' is not connected", uuid)).handle_err(location!())?;
        }

        Ok(())
    }

    pub async fn get_client(&self, device_uuid: &str) -> Option<Arc<Mutex<Client>>> {
        self.clients.lock().await.get(device_uuid).cloned()
    }
}
