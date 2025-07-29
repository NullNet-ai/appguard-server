use crate::app_context::AppContext;
use crate::http_proxy::utilities::authorization;
use crate::http_proxy::utilities::error_json::ErrorJson;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;
use nullnet_liberror::{location, ErrorHandler, Location};

use crate::config::Config;
use crate::db::entries::DbEntry;
use crate::db::tables::DbTable;
use crate::helpers::get_timestamp_string;
use actix_web::web::Data;
use actix_web::web::Json;
use serde_json::json;

pub async fn update_config(
    request: HttpRequest,
    context: Data<AppContext>,
    body: Json<Config>,
) -> impl Responder {
    let Some(jwt) = authorization::extract_authorization_token(&request) else {
        return HttpResponse::Unauthorized().json(ErrorJson::from("Missing Authorization header"));
    };

    let body_config = body.into_inner();

    if delete_old_configs(&context).await.is_err() {
        return HttpResponse::InternalServerError().json(ErrorJson::from(
            "Failed to delete old AppGuard configs from datastore",
        ));
    }

    if DbEntry::Config((body_config, jwt))
        .store(context.datastore.clone())
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(ErrorJson::from(
            "Failed to save AppGuard configs in datastore",
        ));
    }

    match context.config_pair.0.lock().handle_err(location!()) {
        Ok(mut config) => {
            log::info!("Updated configuration: {body_config:?}");
            *config = body_config;
            context.config_pair.1.notify_all();
        }
        Err(err) => {
            return HttpResponse::InternalServerError().json(ErrorJson::from(err));
        }
    }

    HttpResponse::Ok().json(json!({}))
}

async fn delete_old_configs(context: &AppContext) -> Result<(), nullnet_liberror::Error> {
    context
        .datastore
        .clone()
        .delete_old_entries(
            DbTable::Config,
            get_timestamp_string().as_str(),
            &context.root_token_provider.get().await?.jwt,
        )
        .await?;

    Ok(())
}
