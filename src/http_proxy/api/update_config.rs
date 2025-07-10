use crate::app_context::AppContext;
use crate::http_proxy::utilities::authorization;
use crate::http_proxy::utilities::error_json::ErrorJson;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;
use nullnet_liberror::{location, ErrorHandler, Location};

use crate::config::Config;
use actix_web::web::Data;
use actix_web::web::Json;
use serde_json::json;

pub async fn update_config(
    request: HttpRequest,
    context: Data<AppContext>,
    body: Json<Config>,
) -> impl Responder {
    let Some(_jwt) = authorization::extract_authorization_token(&request) else {
        return HttpResponse::Unauthorized().json(ErrorJson::from("Missing Authorization header"));
    };

    // TODO: save config in datastore

    match context.config_pair.0.lock().handle_err(location!()) {
        Ok(mut config) => {
            log::info!("Updated IP info cache configuration: {body:?}");
            *config = body.into_inner();
            context.config_pair.1.notify_all();
        }
        Err(err) => {
            return HttpResponse::InternalServerError().json(ErrorJson::from(err));
        }
    }

    HttpResponse::Ok().json(json!({}))
}
