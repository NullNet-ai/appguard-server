use std::net::ToSocketAddrs;
use std::panic;
use tonic::transport::{Identity, Server, ServerTlsConfig};

use crate::app_context::AppContext;
use crate::app_guard_impl::{terminate_app_guard, AppGuardImpl};
use crate::constants::PORT;
use crate::constants::{ADDR, SERVER_CERT, SERVER_KEY};
use crate::proto::appguard::app_guard_server::AppGuardServer;
use nullnet_liberror::{location, Error, ErrorHandler, Location};

pub async fn start_appguard(ctx: AppContext) -> Result<(), Error> {
    // init_logger(ctx.root_token_provider.clone());

    let addr = format!("{ADDR}:{PORT}")
        .to_socket_addrs()
        .handle_err(location!())?
        .next()
        .ok_or("Unable to resolve address")
        .handle_err(location!())?;

    log::info!("Starting AppGuard server on address '{addr}'");

    server_builder()?
        .add_service(
            AppGuardServer::new(init_app_guard(ctx)?).max_decoding_message_size(50 * 1024 * 1024),
        )
        .serve(addr)
        .await
        .handle_err(location!())?;

    Ok(())
}

// fn init_logger(provider: TokenProvider) {
//     let token = token_provider.get().await?.jwt.clone();
//
//     let datastore_config =
//         DatastoreConfig::new(token, ServerKind::AppGuard, ADDR.to_string(), PORT, false);
//     let logger_config = LoggerConfig::new(true, false, Some(datastore_config), vec![]);
//     Logger::init(logger_config);
// }

fn init_app_guard(ctx: AppContext) -> Result<AppGuardImpl, Error> {
    if cfg!(not(debug_assertions)) {
        // custom panic hook to correctly clean up the server, even in case a secondary thread fails
        let orig_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            // invoke the default handler and exit the process
            orig_hook(panic_info);
            terminate_app_guard(1).expect("Unable to gracefully terminate server");
        }));
    }

    // handle termination signals: SIGINT, SIGTERM, SIGHUP
    ctrlc::set_handler(move || {
        terminate_app_guard(130).expect("Unable to gracefully terminate server");
    })
    .handle_err(location!())?;

    let app_guard_impl = AppGuardImpl::new(ctx);

    Ok(app_guard_impl)
}

fn server_builder() -> Result<Server, Error> {
    let server = Server::builder();

    if cfg!(feature = "no-tls") {
        log::info!("Starting AppGuard server without TLS");
        return Ok(server);
    }

    let cert = SERVER_CERT.as_str();
    let key = SERVER_KEY.as_str();
    let identity = Identity::from_pem(cert, key);

    log::info!("Starting AppGuard server with TLS");

    server
        .tls_config(ServerTlsConfig::new().identity(identity))
        .handle_err(location!())
}
