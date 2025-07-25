use crate::app_context::AppContext;
use crate::http_proxy::utilities::authorization;
use crate::http_proxy::utilities::error_json::ErrorJson;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;

use crate::db::entries::DbEntry;
use crate::firewall::firewall::Firewall;
use crate::proto::appguard_commands::FirewallDefaults;
use actix_web::web::Data;
use actix_web::web::Json;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct RequestPayload {
    device_id: String,
    firewall: String,
}

pub async fn update_client_firewall(
    request: HttpRequest,
    context: Data<AppContext>,
    body: Json<RequestPayload>,
) -> impl Responder {
    let Some(jwt) = authorization::extract_authorization_token(&request) else {
        return HttpResponse::Unauthorized().json(ErrorJson::from("Missing Authorization header"));
    };

    let Ok(value) = context
        .datastore
        .obtain_device_by_id(&jwt, &body.device_id, false)
        .await
    else {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Failed to fetch device record"));
    };

    let Some(device) = value else {
        return HttpResponse::NotFound().json(ErrorJson::from("Device not found"));
    };

    if !device.authorized {
        return HttpResponse::BadRequest().json(ErrorJson::from("Device is not authorized yet"));
    }

    let device_id = &body.device_id;
    let firewall = match Firewall::from_infix(&body.firewall) {
        Ok(firewall) => firewall,
        Err(err) => {
            log::error!("Failed to parse firewall: {}", err.to_str());
            return HttpResponse::BadRequest().json(ErrorJson::from(err.to_str()));
        }
    };
    log::info!("Updating firewall for '{device_id}': {firewall:?}",);
    let default_policy = firewall.default_policy;
    let timeout = firewall.timeout;

    if DbEntry::Firewall((device_id.clone(), firewall.clone(), jwt))
        .store(context.datastore.clone())
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Failed to save firewall in datastore"));
    }

    context
        .firewalls
        .write()
        .await
        .insert(device_id.clone(), firewall);

    let Some(client) = context.orchestrator.get_client(&device.uuid).await else {
        return HttpResponse::NotFound().json(ErrorJson::from("Device is not online"));
    };

    let defaults = FirewallDefaults {
        timeout,
        policy: default_policy.into(),
    };
    if let Err(err) = client.lock().await.set_firewall_defaults(defaults).await {
        return HttpResponse::InternalServerError().json(ErrorJson::from(err));
    }

    HttpResponse::Ok().json(json!({}))
}
