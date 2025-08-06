use crate::app_context::AppContext;
use crate::helpers::generate_random_string;
use crate::http_proxy::utilities::authorization;
use crate::http_proxy::utilities::error_json::ErrorJson;
use crate::proto::appguard_commands::AuthenticationData;
use actix_web::web::Data;
use actix_web::web::Json;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct RequestPayload {
    device_id: String,
}

pub async fn authorize_device(
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

    let Some(mut device) = value else {
        return HttpResponse::BadRequest().json(ErrorJson::from("Device not found"));
    };

    if !device.online {
        return HttpResponse::BadRequest().json(ErrorJson::from("Device is offline"));
    }

    if device.authorized {
        return HttpResponse::Ok().json(json!({}));
    }

    device.authorized = true;

    let account_id = generate_random_string(12);
    let account_secret = generate_random_string(36);

    if context
        .datastore
        .register_device(&jwt, &account_id, &account_secret, &device)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Failed to register device"));
    }

    if context
        .datastore
        .update_device(&jwt, &body.device_id, &device)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(ErrorJson::from("Failed to update device record"));
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

        if lock
            .authorize(AuthenticationData {
                app_id: Some(account_id.clone()),
                app_secret: Some(account_secret.clone()),
            })
            .await
            .is_err()
        {
            return HttpResponse::InternalServerError()
                .json(ErrorJson::from("Failed to send approval"));
        }
    }

    HttpResponse::Ok().json(json!({}))
}
