use crowsi_authority_transport::{AuthorityServer, SystemClock};
use std::{
    net::TcpListener,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    HostError, gateway_backend::CredentialAuthorityBackend, gateway_config,
    gateway_host_process::GatewayHostProcess, gateway_peer_guard::GatewayPeerGuard,
    gateway_peer_status::GatewayPeerStatus, gateway_replay::GatewayReplayGuard, host_config,
};

pub fn run_authority_gateway_cli(arguments: impl Iterator<Item = String>) -> Result<(), HostError> {
    let values = arguments.collect::<Vec<_>>();
    if values.len() != 4
        || !matches!(values[1].as_str(), "serve" | "initialize-once")
        || values[2] != "--config"
        || !Path::new(&values[3]).is_absolute()
    {
        return Err(HostError::RequestInvalid);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostError::Unavailable)?
        .as_secs();
    let gateway_path = Path::new(&values[3]);
    let config = gateway_config::load(gateway_path, now)?;
    let host = host_config::load_document(
        Path::new(&config.document.host_config_path),
        Some(&config.document.host_config_sha256),
        now,
    )?;
    if !crate::gateway_validation::compatible(&host, &config.document) {
        return Err(HostError::ConfigInvalid);
    }
    if values[1] == "initialize-once" {
        GatewayReplayGuard::initialize(
            Path::new(&config.document.replay_state_directory),
            Path::new(&config.document.replay_anchor_directory),
            &config.document.deployment_id,
            config.document.authority_epoch,
        )
        .map_err(|_| HostError::ConfigInvalid)?;
        return GatewayPeerStatus::initialize(
            Path::new(&config.document.peer_status_state_directory),
            Path::new(&config.document.peer_status_anchor_directory),
            &config.document.deployment_id,
            config.document.authority_epoch,
            &config.document.peers,
        );
    }
    let connection_capacity = config.document.maximum_connections;
    let authority_epoch = config.document.authority_epoch;
    let peer_status = GatewayPeerStatus::open(
        Path::new(&config.document.peer_status_state_directory),
        Path::new(&config.document.peer_status_anchor_directory),
        &config.document.deployment_id,
        config.document.authority_epoch,
        &config.document.peers,
    )?;
    let process = Arc::new(GatewayHostProcess::open(
        &config.document,
        gateway_path,
        config.source_digest.clone(),
    )?);
    let head = process.peer_status_head(&config.document, &host)?;
    peer_status.reconcile_head(&head)?;
    let replay_authority = crate::gateway_replay_authority::GatewayReplayAuthority::new(
        Arc::clone(&process),
        config.document.clone(),
        host.clone(),
    );
    let replay = GatewayReplayGuard::open_with_authority(
        Path::new(&config.document.replay_state_directory),
        Path::new(&config.document.replay_anchor_directory),
        &config.document.deployment_id,
        config.document.authority_epoch,
        replay_authority,
    )
    .map_err(|_| HostError::ConfigInvalid)?;
    let backend =
        CredentialAuthorityBackend::new(process, peer_status, config.document.clone(), host);
    let peer_guard = GatewayPeerGuard::new(backend.peer_status(), authority_epoch);
    let listener =
        TcpListener::bind(&config.document.listen_address).map_err(|_| HostError::Unavailable)?;
    let server = AuthorityServer::new_with_peer_status(
        config.document.audience,
        authority_epoch,
        config.credential,
        config.peers,
        peer_guard,
        backend,
        replay,
        Duration::from_millis(config.document.timeout_ms),
        SystemClock,
    )
    .map_err(|_| HostError::ConfigInvalid)?;
    server
        .serve_until(&listener, connection_capacity, &AtomicBool::new(false))
        .map_err(|_| HostError::Unavailable)
}
