use crate::grpc_impl::AppGuardImpl;
use crate::proto::appguard::app_guard_server::AppGuardServer;
use std::net::ToSocketAddrs;
use tonic::transport::Server;

mod grpc_impl;
mod proto;

#[tokio::main]
async fn main() {
    let addr = "localhost:50051"
        .to_string()
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    Server::builder()
        .add_service(AppGuardServer::new(AppGuardImpl))
        .serve(addr)
        .await
        .unwrap();
}
