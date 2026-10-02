impl GatewayPeerStatus {
    pub(crate) fn deny(&self, device: &str, epoch: u64, now: u64) -> Result<(), HostError> {
        let peer = self
            .peers
            .iter()
            .find(|item| item.device_id == device)
            .ok_or(HostError::ConfigInvalid)?;
        self.locked(|| {
            let mut ledger = self.read_ledger()?;
            if let Some(existing) = ledger
                .entries
                .iter_mut()
                .find(|item| item.device_id == device)
            {
                if existing.certificate_sha256 != peer.certificate_sha256
                    || existing.request_key_id != peer.request_key_id
                    || epoch < existing.device_revocation_epoch
                {
                    return Err(HostError::StateInvalid);
                }
                if epoch == existing.device_revocation_epoch {
                    return existing
                        .revoked
                        .then_some(())
                        .ok_or(HostError::StateInvalid);
                }
                existing.device_revocation_epoch = epoch;
                existing.revoked_at_epoch_s = now;
                existing.registered = true;
                existing.revoked = true;
            } else {
                if epoch == 0 || ledger.entries.len() >= 10_000 {
                    return Err(HostError::StateInvalid);
                }
                ledger.entries.push(PeerStatusEntryV1 {
                    device_id: device.into(),
                    certificate_sha256: peer.certificate_sha256.clone(),
                    request_key_id: peer.request_key_id.clone(),
                    registered: true,
                    revoked: true,
                    device_revocation_epoch: epoch,
                    revoked_at_epoch_s: now,
                });
            }
            ledger.revision = ledger
                .revision
                .checked_add(1)
                .ok_or(HostError::StateInvalid)?;
            crate::gateway_peer_state_io::write(
                &self.root,
                &self.anchor,
                &self.deployment,
                self.authority_epoch,
                &ledger,
            )
        })
    }

    pub(crate) fn allows(
        &self,
        device: &str,
        certificate: &str,
        request_key: &str,
    ) -> Result<bool, HostError> {
        self.peers
            .iter()
            .find(|item| {
                item.device_id == device
                    && item.certificate_sha256 == certificate
                    && item.request_key_id == request_key
            })
            .ok_or(HostError::EvidenceInvalid)?;
        self.locked(|| {
            let ledger = self.read_ledger()?;
            Ok(ledger.entries.iter().any(|item| {
                item.device_id == device
                    && item.certificate_sha256 == certificate
                    && item.request_key_id == request_key
                    && item.registered
                    && !item.revoked
            }))
        })
    }
}
