use std::sync::{Arc, Mutex};

use crate::db::tables::DbTable;
use rusqlite::{params, Connection};
use tonic::transport::Channel;
use tonic::Request;

use crate::error::{Error, ErrorHandler, Location};
use crate::helpers::get_timestamp_string;
use crate::location;
use crate::proto::aiguard::ai_guard_client::AiGuardClient;
use crate::proto::aiguard::AiGuardHttpRequest;

pub enum AiEntry {
    HttpRequest((AiGuardHttpRequest, u64)),
}

impl AiEntry {
    pub async fn handle(
        self,
        conn: &Arc<Mutex<Connection>>,
        mut ai_client: AiGuardClient<Channel>,
    ) -> Result<(), Error> {
        let (table_name, id, ai_res) = match self {
            AiEntry::HttpRequest((e, id)) => {
                let ai_res = ai_client
                    .handle_http_request(Request::new(e))
                    .await
                    .handle_err(location!())?
                    .into_inner();
                log::info!("AiGuard server response to HTTP request #{id}: ***{ai_res:?}***");
                (DbTable::HttpRequestAi.to_str(), id, ai_res)
            }
        };

        conn.lock()
            .handle_err(location!())?
            .execute(
                &format!("INSERT INTO {table_name} (id, timestamp, ai_res) VALUES (?1, ?2, ?3)"),
                params![id, get_timestamp_string(), ai_res,],
            )
            .handle_err(location!())?;

        Ok(())
    }
}
