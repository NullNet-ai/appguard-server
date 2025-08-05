use nullnet_liberror::{location, Error, ErrorHandler, Location};

use tokio::sync::mpsc;
use tonic::Status;
use tonic::Streaming;

use crate::app_context::AppContext;
use crate::orchestrator::control_stream::control_stream;
use crate::proto::appguard_commands::server_message::Message;
use crate::proto::appguard_commands::ClientMessage;
use crate::proto::appguard_commands::ServerMessage;
use crate::proto::appguard_commands::{AuthenticationData, FirewallDefaults};

pub(crate) type OutboundStream = mpsc::Sender<Result<ServerMessage, Status>>;
pub(crate) type InboundStream = Streaming<ClientMessage>;

#[derive(Debug)]
pub struct Instance {
    pub(crate) device_uuid: String,
    pub(crate) instance_id: String,
    pub(crate) outbound: OutboundStream,
}

impl Instance {
    pub fn new(
        device_uuid: String,
        instance_id: String,
        inbound: InboundStream,
        outbound: OutboundStream,
        context: AppContext,
    ) -> Self {
        tokio::spawn(control_stream(
            device_uuid.clone(),
            instance_id.clone(),
            inbound,
            outbound.clone(),
            context,
        ));

        Self {
            device_uuid,
            instance_id,
            outbound,
        }
    }

    pub async fn authorize(&mut self, data: AuthenticationData) -> Result<(), Error> {
        log::debug!(
            "Authorizing device {}, instance {}",
            self.device_uuid,
            self.instance_id
        );

        let message = ServerMessage {
            message: Some(Message::DeviceAuthorized(data)),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())?;

        Ok(())
    }

    pub async fn _deauthorize(&mut self) -> Result<(), Error> {
        log::debug!(
            "Deauthorizing device {}, instance {}",
            self.device_uuid,
            self.instance_id
        );

        let message = ServerMessage {
            message: Some(Message::DeviceDeauthorized(())),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())?;

        Ok(())
    }

    pub async fn set_firewall_defaults(&mut self, data: FirewallDefaults) -> Result<(), Error> {
        let message = ServerMessage {
            message: Some(Message::SetFirewallDefaults(data)),
        };

        self.outbound
            .send(Ok(message))
            .await
            .handle_err(location!())?;

        Ok(())
    }
}
