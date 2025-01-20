use crate::proto::appguard::app_guard_client::AppGuardClient;
pub use crate::proto::appguard::{SampleMessage, SampleResponse};
use tonic::transport::Channel;
use tonic::Request;

mod proto;

#[derive(Clone)]
pub struct AppGuardGrpcInterface {
    client: AppGuardClient<Channel>,
}

impl AppGuardGrpcInterface {
    pub async fn new(addr: &'static str, port: u16) -> Self {
        let channel = Channel::from_shared(format!("http://{addr}:{port}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        Self {
            client: AppGuardClient::new(channel),
        }
    }

    pub async fn sample(&mut self, message: SampleMessage) -> Option<SampleResponse> {
        self.client
            .sample(Request::new(message))
            .await
            .map(tonic::Response::into_inner)
            .ok()
    }
}
