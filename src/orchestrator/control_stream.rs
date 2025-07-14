use nullnet_liberror::{location, Error, ErrorHandler, Location};
use std::time::Duration;

use crate::app_context::AppContext;
use crate::orchestrator::client::{InboundStream, OutboundStream};
use crate::proto::appguard_commands::{client_message, server_message, ServerMessage};
use crate::token_provider::TokenProvider;

const HEARTBEAT_TIME: Duration = Duration::from_secs(20);
const TOKEN_UPDATE_TIME: Duration = Duration::from_secs(60);

pub(crate) async fn control_stream(
    device_uuid: String,
    inbound: InboundStream,
    outbound: OutboundStream,
    context: AppContext,
) {
    log::info!("Starting a control stream for device UUID {device_uuid}");

    tokio::select! {
        hres = healthcheck(outbound.clone()) => {
            if let Err(err) = hres {
                log::error!(
                    "Health check for client with device UUID '{}' failed: {}",
                    device_uuid,
                    err.to_str()
                );
            }
        },
        ares = authstream(inbound, outbound, context.clone()) => {
            if let Err(err) = ares {
                log::error!(
                    "Control stream for client with device UUID '{}' failed: {}",
                    device_uuid,
                    err.to_str()
                );
            }
        },
    };

    if let Ok(token) = context.sysdev_token_provider.get().await {
        if context
            .datastore
            .update_device_online_status(&token.jwt, &device_uuid, false)
            .await
            .is_err()
        {
            log::error!("Failed to update device record");
        }
    } else {
        log::error!("Failed to obtain system device token");
    }

    let _ = context.orchestrator.on_disconnected(&device_uuid).await;
}

async fn healthcheck(stream: OutboundStream) -> Result<(), Error> {
    loop {
        let heartbeat = ServerMessage {
            message: Some(server_message::Message::Heartbeat(())),
        };

        stream.send(Ok(heartbeat)).await.handle_err(location!())?;

        tokio::time::sleep(HEARTBEAT_TIME).await;
    }
}

async fn authstream(
    mut inbound: InboundStream,
    outbound: OutboundStream,
    context: AppContext,
) -> Result<(), Error> {
    let message = inbound
        .message()
        .await
        .handle_err(location!())?
        .ok_or("Client sent an empty message")
        .handle_err(location!())?
        .message
        .ok_or("Malformed message (missing payload)")
        .handle_err(location!())?;

    let authentication = match message {
        client_message::Message::Authentication(authentication) => authentication,
        _ => Err("Unexpected message").handle_err(location!())?,
    };

    let token_provider = TokenProvider::new(
        authentication.app_id,
        authentication.app_secret,
        false,
        context.datastore,
    );

    outbound
        .send(Ok(ServerMessage {
            message: Some(server_message::Message::UpdateTokenCommand(
                token_provider.get().await?.jwt.clone(),
            )),
        }))
        .await
        .handle_err(location!())?;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(TOKEN_UPDATE_TIME) => {
                outbound
                    .send(Ok(ServerMessage {
                        message: Some(server_message::Message::UpdateTokenCommand(
                            token_provider.get().await?.jwt.clone(),
                        )),
                    }))
                    .await
                    .handle_err(location!())?;
            }

            msg = inbound.message() => {
                match msg {
                    Ok(Some(_)) => {
                        log::warn!("Unexpected message from client after authentication; ignoring");
                    }
                    Ok(None) => {
                        return Err("Inbound stream closed by client").handle_err(location!());
                    }
                    Err(e) => {
                        return Err(format!("Inbound stream error: {e}")).handle_err(location!());
                    }
                }
            }
        }
    }
}
