use crate::errors::ArrtError;
use crate::ipc;
use crate::protocol::{RpcRequest, RpcResponse};
use crate::service::GatewayService;
use std::sync::Arc;
use tokio::sync::Notify;

pub struct DaemonState {
    service: Arc<GatewayService>,
    pub(crate) shutdown: Notify,
}

impl DaemonState {
    pub fn new() -> Arc<Self> {
        Self::with_service(GatewayService::new())
    }

    pub fn with_service(service: Arc<GatewayService>) -> Arc<Self> {
        Arc::new(Self {
            service,
            shutdown: Notify::new(),
        })
    }

    pub async fn serve(self: Arc<Self>) -> Result<(), ArrtError> {
        self.service.start_maintenance();
        ipc::serve(self).await
    }

    pub fn request_shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    pub async fn graceful_shutdown(&self) {
        self.service.shutdown().await;
    }

    pub async fn handle(self: Arc<Self>, request: RpcRequest) -> RpcResponse {
        let result = self
            .service
            .execute(&request.request_id, request.caller, request.request)
            .await;
        RpcResponse {
            request_id: request.request_id,
            result,
        }
    }
}
