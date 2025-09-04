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
    let cache = firewall.cache;

    if deactivate_old_firewalls(&context, device_id, &jwt)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(ErrorJson::from(
            "Failed to deactivate old firewalls from datastore",
        ));
    }

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

    let defaults = FirewallDefaults {
        timeout,
        policy: default_policy.into(),
        cache,
    };

    let Some(instances) = context
        .orchestrator
        .get_client_instances(&device.uuid)
        .await
    else {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Device is not connected"));
    };

    if instances.lock().await.is_empty() {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Device is not connected"));
    }

    let instances_ids: Vec<String> = {
        let instances_guard = instances.lock().await;
        let mut ids = Vec::new();
        for inst in instances_guard.iter() {
            let id = inst.lock().await.instance_id.clone();
            ids.push(id);
        }
        ids
    };

    for id in instances_ids {
        let Some(instance) = context.orchestrator.get_client(&device.uuid, &id).await else {
            return HttpResponse::InternalServerError().json(format!(
                "Failed to find an instance {} of device {}",
                id, device.uuid
            ));
        };

        let mut lock = instance.lock().await;

        if lock.set_firewall_defaults(defaults).await.is_err() {
            return HttpResponse::InternalServerError()
                .json(ErrorJson::from("Failed to send approval"));
        }
    }

    HttpResponse::Ok().json(json!({}))
}

async fn deactivate_old_firewalls(
    context: &AppContext,
    device_id: &str,
    jwt: &str,
) -> Result<(), nullnet_liberror::Error> {
    context
        .datastore
        .clone()
        .deactivate_old_firewalls(jwt, device_id)
        .await?;

    Ok(())
}
