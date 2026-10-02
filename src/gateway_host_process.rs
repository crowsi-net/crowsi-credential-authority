use crowsi_authority_transport::SignedRequest;
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::Duration,
};

use crate::{HostError, gateway_contract::GatewayConfigDocument, host_files};

pub(crate) struct GatewayHostProcess {
    executable: PathBuf,
    executable_digest: String,
    host_config: PathBuf,
    host_config_digest: String,
    gateway_config: PathBuf,
    gateway_config_digest: String,
    timeout: Duration,
    serial: Mutex<()>,
}

impl GatewayHostProcess {
    pub(crate) fn open(
        document: &GatewayConfigDocument,
        gateway_config: &Path,
        gateway_config_digest: String,
    ) -> Result<Self, HostError> {
        host_files::trusted_executable(
            Path::new(&document.host_executable),
            &document.host_executable_sha256,
        )?;
        host_files::pinned_owner_file(
            Path::new(&document.host_config_path),
            262_144,
            &document.host_config_sha256,
        )?;
        host_files::pinned_owner_file(gateway_config, 524_288, &gateway_config_digest)?;
        Ok(Self {
            executable: document.host_executable.clone().into(),
            executable_digest: document.host_executable_sha256.clone(),
            host_config: document.host_config_path.clone().into(),
            host_config_digest: document.host_config_sha256.clone(),
            gateway_config: gateway_config.into(),
            gateway_config_digest,
            timeout: Duration::from_millis(document.host_process_timeout_ms),
            serial: Mutex::new(()),
        })
    }

    pub(crate) fn exchange(&self, request: &SignedRequest) -> Result<Vec<u8>, HostError> {
        let wire = crate::gateway_host_contract::encode(request)?;
        self.run("management-v2", &wire)
    }

    pub(crate) fn peer_status_head(
        &self,
        gateway: &GatewayConfigDocument,
        host: &crate::host_config_types::HostConfigDocument,
    ) -> Result<crate::gateway_peer_head_types::PeerStatusHeadV1, HostError> {
        let (request, wire) =
            crate::gateway_peer_head::request(gateway, &self.gateway_config_digest)?;
        let response = self.run("peer-status-head", &wire)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| HostError::Unavailable)?
            .as_secs();
        crate::gateway_peer_head::verify(&response, &request, &wire, gateway, host, now)
    }

    pub(crate) fn consume_transport_replay(
        &self,
        gateway: &GatewayConfigDocument,
        host: &crate::host_config_types::HostConfigDocument,
        device: &str,
        nonce: &str,
        digest: &str,
    ) -> Result<(), HostError> {
        let now = epoch_seconds()?;
        let (request, wire) = crate::gateway_replay_witness::request(
            gateway,
            &self.gateway_config_digest,
            device,
            nonce,
            digest,
            now,
        )?;
        let response = self.run("consume-transport-replay", &wire)?;
        crate::gateway_replay_witness::verify(
            &response,
            &request,
            &wire,
            gateway,
            host,
            epoch_seconds()?,
        )
    }

    fn run(&self, command_name: &str, wire: &[u8]) -> Result<Vec<u8>, HostError> {
        let _serial = self.serial.lock().map_err(|_| HostError::Unavailable)?;
        let executable = host_files::pin_executable(&self.executable, &self.executable_digest)?;
        let host =
            host_files::pin_owner_file(&self.host_config, 262_144, &self.host_config_digest)?;
        let gateway =
            host_files::pin_owner_file(&self.gateway_config, 524_288, &self.gateway_config_digest)?;
        let host_path = self.host_config.to_str().ok_or(HostError::PathInvalid)?;
        let gateway_path = self.gateway_config.to_str().ok_or(HostError::PathInvalid)?;
        let mut command = Command::new(executable.path());
        command
            .args([
                "handle-once",
                "--config",
                host_path,
                "--config-sha256",
                &self.host_config_digest,
                "--gateway-config",
                gateway_path,
                "--gateway-config-sha256",
                &self.gateway_config_digest,
                "--command",
                command_name,
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let _pinned = (executable.retain(), host.retain(), gateway.retain());
        crate::gateway_host_process_io::run(command, wire, self.timeout)
    }
}

fn epoch_seconds() -> Result<u64, HostError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HostError::Unavailable)
        .map(|value| value.as_secs())
}
