use std::path::Path;

use crate::{
    HostError, gateway_config, gateway_host_contract, management_v2_handler::ManagementV2Handler,
    management_v2_host_context::ManagementHostContext,
};

pub(crate) fn handle(
    host_path: &Path,
    host_digest: &str,
    gateway_path: &Path,
    gateway_digest: &str,
    wire: &[u8],
    now: u64,
) -> Result<Vec<u8>, HostError> {
    let gateway = gateway_config::load_document(gateway_path, gateway_digest, now)?;
    if gateway.host_config_sha256 != host_digest
        || Path::new(&gateway.host_config_path) != host_path
    {
        return Err(HostError::ConfigInvalid);
    }
    let core = ManagementHostContext::open_pinned(host_path, host_digest, now)?;
    if !crate::gateway_validation::compatible(&core.config.document, &gateway) {
        return Err(HostError::ConfigInvalid);
    }
    let request = gateway_host_contract::decode(wire)?;
    if !gateway.peers.iter().any(|peer| {
        peer.device_id == request.peer.device_id
            && peer.certificate_sha256 == request.peer.certificate_sha256
            && peer.request_key_id == request.peer.request_key_id
            && peer.request_public_key_hex == request.peer.request_public_key_hex
    }) {
        return Err(HostError::EvidenceInvalid);
    }
    let handler = ManagementV2Handler::open(core)?;
    if request.command == "lookup-prepared" {
        handler.lookup_prepared(&request, now)
    } else if request.command == "independent-revocation-pre-final" {
        handler.independent_revocation_pre_final(&request, now)
    } else if request.command == "revocation-execution-reserve" {
        handler.reserve_revocation_execution(&request, now)
    } else if request.command == "revocation-execution-cancel" {
        handler.cancel_pending_revocation_execution(&request, now)
    } else if request.command == "revocation-execution-cancel-finalize" {
        handler.acknowledge_pending_revocation_cancellation(&request, now)
    } else if request.command == "revocation-execution-cancel-cleanup-complete" {
        handler.complete_pending_revocation_cancellation_cleanup(&request, now)
    } else if request.command == "revocation-finalize" {
        handler.finalize_revocation(&request, now)
    } else if request.command == "independent-revocation-finalize" {
        handler.finalize_independent_revocation(&request, now)
    } else {
        handler.handle(&request, now)
    }
}
