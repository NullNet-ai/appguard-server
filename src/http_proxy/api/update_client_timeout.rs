use crate::app_context::AppContext;
use crate::http_proxy::utilities::authorization;
use crate::http_proxy::utilities::error_json::ErrorJson;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;

use actix_web::web::Data;
use actix_web::web::Json;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct RequestPayload {
    device_id: String,
    enable: bool,
}

pub async fn update_client_timeout(
    request: HttpRequest,
    context: Data<AppContext>,
    body: Json<RequestPayload>,
) -> impl Responder {
    let Some(jwt) = authorization::extract_authorization_token(&request) else {
        return HttpResponse::Unauthorized().json(ErrorJson::from("Missing Authorization header"));
    };

    let Ok(device) = context
        .datastore
        .obtain_device_by_id(&jwt, &body.device_id)
        .await
    else {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Failed to fetch device record"));
    };

    if device.is_none() {
        return HttpResponse::NotFound().json(ErrorJson::from("Device not found"));
    }

    let mut device = device.unwrap();

    if !device.authorized {
        return HttpResponse::BadRequest().json(ErrorJson::from("Device is not authorized yet"));
    }

    device.traffic_monitoring = body.enable;

    if context
        .datastore
        .update_device(&jwt, &body.device_id, &device)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Failed to update device"));
    }

    let Some(client) = context.orchestrator.get_client(&device.uuid).await else {
        return HttpResponse::NotFound().json(ErrorJson::from("Device is not online"));
    };

    if let Err(err) = client
        .lock()
        .await
        .enable_network_monitoring(body.enable)
        .await
    {
        return HttpResponse::InternalServerError().json(ErrorJson::from(err));
    }

    HttpResponse::Ok().json(json!({}))
}
