use std::net::ToSocketAddrs;
use std::process::Command;
use std::thread;

use appguard::AppGuardGrpcInterface;
use rusqlite::Connection;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use appguard::config::Config;
use appguard::constants::{ADDR, AI_PORT, PORT, SQLITE_PATH};
use appguard::db::tables::DbTable;
use appguard::entrypoint::start_appguard;
use appguard::proto::aiguard::ai_guard_server::{AiGuard, AiGuardServer};
use appguard::proto::aiguard::{AiGuardHttpRequest, AiGuardResponse};

use crate::config::write_config_to_file;

pub const NUM_ITER: u64 = 3;

pub fn server_setup() {
    server_clean();

    if get_listening_pids(AI_PORT).is_empty() {
        thread::spawn(move || run_ai_guard_server());
    }

    loop {
        if get_listening_pids(AI_PORT).len() > 0 {
            break;
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }

    if get_listening_pids(PORT).is_empty() {
        thread::spawn(move || start_appguard().unwrap());
    }

    loop {
        if get_listening_pids(PORT).len() > 0 {
            break;
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn server_clean() {
    write_config_to_file(&Config::default());

    // empty database tables
    let conn = db_setup();
    for table in DbTable::ALL {
        let table_name = table.to_str();
        conn.execute(&format!("DELETE FROM {table_name}"), [])
            .unwrap();
    }
}

pub async fn client_setup() -> AppGuardGrpcInterface {
    AppGuardGrpcInterface::new(ADDR, PORT, true).await.unwrap()
}

pub fn db_setup() -> Connection {
    Connection::open(SQLITE_PATH.as_str()).unwrap()
}

fn get_listening_pids(port: u16) -> Vec<String> {
    let output = Command::new("lsof")
        .args([&format!("-i:{port}"), "-t", "-sTCP:LISTEN"])
        .output()
        .unwrap();
    let output = String::from_utf8(output.stdout).unwrap();
    output.lines().map(|s| s.to_owned()).collect()
}

pub fn count_rows_in_table(conn: &Connection, table: &str) -> u64 {
    let mut stmt = conn
        .prepare(&format!("SELECT COUNT(*) FROM {table}"))
        .unwrap();

    let count: u64 = stmt.query_row([], |row| row.get(0)).unwrap();

    count
}

#[tokio::main]
async fn run_ai_guard_server() {
    let addr = format!("{ADDR}:{AI_PORT}")
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    Server::builder()
        .add_service(AiGuardServer::new(AiGuardDummyImpl))
        .serve(addr)
        .await
        .unwrap();
}

struct AiGuardDummyImpl;

#[tonic::async_trait]
impl AiGuard for AiGuardDummyImpl {
    async fn handle_http_request(
        &self,
        _request: Request<AiGuardHttpRequest>,
    ) -> Result<Response<AiGuardResponse>, Status> {
        let response = Response::new(AiGuardResponse {
            confidence: 0.5,
            columns: vec!["original_url".to_string(), "user_agent".to_string()],
        });

        Ok(response)
    }
}
