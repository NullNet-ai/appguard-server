//! Handles new incoming client connections in the Orchestrator.
//!
//! For more details, see: https://github.com/NullNet-ai/wallguard-server/issues/17
//!
//! Once a new connection is established, the client is expected to send an `AuthorizationRequest`
//! containing its `UUID` and `ORG_ID`.
//!
//! This component is responsible for:
//! - Receiving the initial authorization message
//! - Ensuring the message arrives in the correct order and within the allowed timeout
//! - Rejecting connections that are late, malformed, or duplicates

use crate::app_context::AppContext;
use crate::orchestrator::auth_request_handler::AuthReqHandler;
use crate::orchestrator::client::{InboundStream, OutboundStream};
use crate::proto::appguard_commands::client_message::Message;
use std::time::Duration;

const AUTH_TIMEOUT: Duration = Duration::from_millis(1_000);

pub struct NewConnectionHandler {
    context: AppContext,
}

impl NewConnectionHandler {
    pub fn new(context: AppContext) -> Self {
        Self { context }
    }

    pub async fn handle(self, inbound: InboundStream, outbound: OutboundStream) {
        tokio::select! {
            _ = tokio::time::sleep(AUTH_TIMEOUT) => {
                log::warn!("Connection abandoned: no authorization message received within timeout.");
            }
            res = self.await_authorization(inbound, outbound) => {
                if let Err(e) = res {
                    log::warn!("Authorization failed: {}", e);
                }
            }
        }
    }

    async fn await_authorization(
        self,
        mut inbound: InboundStream,
        outbound: OutboundStream,
    ) -> Result<(), String> {
        let Some(msg) = inbound
            .message()
            .await
            .map_err(|e| format!("Failed to receive message: {}", e))?
        else {
            return Err("Client disconnected without sending a message.".into());
        };

        let Some(inner_msg) = msg.message else {
            return Err("Received empty ClientMessage.".into());
        };

        match inner_msg {
            Message::AuthorizationRequest(auth) => {
                let handler = AuthReqHandler::new(self.context);
                tokio::spawn(handler.handle(inbound, outbound, auth));
                Ok(())
            }
            _ => Err("First message must be AuthorizationRequest.".into()),
        }
    }
}
