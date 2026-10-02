impl GatewayPeerStatus {
    pub(crate) fn reconcile_head(
        &self,
        head: &crate::gateway_peer_head_types::PeerStatusHeadV1,
    ) -> Result<(), HostError> {
        self.locked(|| {
            let mut ledger = self.read_ledger()?;
            if head.authority_revision < ledger.authority_revision {
                return Err(HostError::StateInvalid);
            }
            if head.authority_revision == ledger.authority_revision {
                return (head.head_digest_sha256 == ledger.authority_head_sha256)
                    .then_some(())
                    .ok_or(HostError::StateInvalid);
            }
            if ledger
                .entries
                .iter()
                .filter(|item| item.revoked)
                .any(|local| {
                    !head.entries.iter().any(|remote| {
                        remote.revoked
                            && remote.device_id == local.device_id
                            && remote.certificate_sha256 == local.certificate_sha256
                            && remote.request_key_id == local.request_key_id
                            && remote.device_revocation_epoch >= local.device_revocation_epoch
                    })
                })
            {
                return Err(HostError::StateInvalid);
            }
            ledger.entries = head
                .entries
                .iter()
                .map(|remote| from_remote(remote, head.issued_at_epoch_s))
                .collect();
            ledger.authority_revision = head.authority_revision;
            ledger
                .authority_head_sha256
                .clone_from(&head.head_digest_sha256);
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
}
