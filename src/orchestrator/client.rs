use nullnet_liberror::{location, Error, ErrorHandler, Location};

use tokio::sync::mpsc;
use tonic::Status;
use tonic::Streaming;

use crate::app_context::AppContext;
use crate::orchestrator::control_stream::control_stream;
use crate::proto::appguard_commands::server_message::Message;
use crate::proto::appguard_commands::AuthenticationData;
use crate::proto::appguard_commands::ClientMessage;
use crate::proto::appguard_commands::ServerMessage;

pub(crate) type OutboundStream = mpsc::Sender<Result<ServerMessage, Status>>;
pub(crate) type InboundStream = Streaming<ClientMessage>;

#[derive(Debug)]
pub struct Client {
    uuid: String,
    _org_id: String,
    outbound: OutboundStream,
}

impl Client {
    pub fn new(
        uuid: String,
        org_id: String,
        inbound: InboundStream,
        outbound: OutboundStream,
        context: AppContext,
    ) -> Self {
        tokio::spawn(control_stream(
            uuid.clone(),
            inbound,
            outbound.clone(),
            context,
        ));

        Self {
            uuid,
            outbound,
            _org_id: org_id,
        }
    }

    pub async fn authorize(&mut self, data: AuthenticationData) -> Result<(), Error> {
        log::debug!("Authorizing device {}", self.uuid);

        let message = ServerMessage {
            message: Some(Message::DeviceAuthorizedMessage(data)),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())?;

        Ok(())
    }

    pub async fn _deauthorize(&mut self) -> Result<(), Error> {
        log::debug!("Deauthorizing device {}", self.uuid);

        let message = ServerMessage {
            message: Some(Message::DeviceDeauthorizedMessage(())),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())?;

        Ok(())
    }

    pub async fn enable_network_monitoring(&self, enable: bool) -> Result<(), Error> {
        log::info!(
            "Sending EnableNetworkMonitoringCommand to the client with device UUID {}",
            self.uuid
        );

        let message = ServerMessage {
            message: Some(Message::EnableNetworkMonitoringCommand(enable)),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())
    }

    pub async fn enable_telemetry_monitoring(&self, enable: bool) -> Result<(), Error> {
        log::info!(
            "Sending EnableTelemetryMonitoringCommand to the client with device UUID {}",
            self.uuid
        );

        let message = ServerMessage {
            message: Some(Message::EnableTelemetryMonitoringCommand(enable)),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())
    }

    pub async fn enable_configuration_monitoring(&self, enable: bool) -> Result<(), Error> {
        log::info!(
            "Sending EnableConfigurationMonitoringCommand to the client with device UUID {}",
            self.uuid
        );

        let message = ServerMessage {
            message: Some(Message::EnableConfigurationMonitoringCommand(enable)),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())
    }
}
