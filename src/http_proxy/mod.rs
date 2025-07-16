use crate::app_context::AppContext;
use crate::http_proxy::api::update_client_firewall;
use actix_cors::Cors;
use actix_web::{http, web, App, HttpServer};
use api::{authorize_device, update_config};
use config::HttpProxyConfig;

mod api;
mod config;
mod utilities;

pub async fn run_http_proxy(context: AppContext) {
    let config = HttpProxyConfig::from_env();
    log::info!("HTTP proxy listening on {}", config.addr);

    let context = web::Data::new(context);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "DELETE", "PUT"])
            .allowed_headers(vec![
                http::header::CONTENT_TYPE,
                http::header::AUTHORIZATION,
            ])
            .max_age(3600);

        App::new()
            .app_data(context.clone())
            .wrap(cors)
            .route(
                "/appguard/api/v1/authorize_device",
                web::post().to(authorize_device),
            )
            .route(
                "/appguard/api/v1/update_config",
                web::post().to(update_config),
            )
            .route(
                "/appguard/api/v1/update_client_firewall",
                web::post().to(update_client_firewall),
            )
        // .default_service(web::to(proxy::proxy_http_request))
    })
    .bind(config.addr)
    .unwrap()
    .run()
    .await
    .unwrap();
}
