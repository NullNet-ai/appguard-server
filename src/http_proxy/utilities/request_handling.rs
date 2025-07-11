use crate::app_context::AppContext;
use crate::http_proxy::utilities::authorization;
use crate::http_proxy::utilities::error_json::ErrorJson;
use actix_web::web::Payload;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_ws::{MessageStream, Session as WSSession};
use nullnet_libtoken::Token;
use std::sync::Arc;

pub fn extract_session_token(req: &HttpRequest) -> Result<String, HttpResponse> {
    authorization::extract_proxy_session_token(req).ok_or_else(|| {
        HttpResponse::Unauthorized().json(ErrorJson::from("Session token is missing"))
    })
}

pub async fn fetch_token(ctx: &AppContext) -> Result<Arc<Token>, HttpResponse> {
    ctx.root_token_provider.get().await.map_err(|_| {
        HttpResponse::InternalServerError()
            .json(ErrorJson::from("Server error, can't obtain root token"))
    })
}

pub fn upgrade_to_websocket(
    request: HttpRequest,
    body: Payload,
) -> Result<(HttpResponse, WSSession, MessageStream), HttpResponse> {
    actix_ws::handle(&request, body)
        .map_err(|err| HttpResponse::InternalServerError().json(ErrorJson::from(err.to_string())))
}
