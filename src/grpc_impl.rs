use crate::proto::appguard::app_guard_server::AppGuard;
use crate::proto::appguard::{SampleMessage, SampleResponse};
use tonic::{Request, Response, Status};

pub struct AppGuardImpl;

#[tonic::async_trait]
impl AppGuard for AppGuardImpl {
    async fn sample(
        &self,
        request: Request<SampleMessage>,
    ) -> Result<Response<SampleResponse>, Status> {
        let SampleMessage { value } = request.into_inner();
        let response = SampleResponse { value };
        Ok(Response::new(response))
    }
}
