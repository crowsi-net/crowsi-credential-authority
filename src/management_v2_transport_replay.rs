use crate::{
    HostError, management_v2_journal::ManagementJournalV2, management_v2_record::TransportReplayV1,
};

impl ManagementJournalV2 {
    pub(crate) fn consume_transport_replay(
        &self,
        owner: &str,
        device: &str,
        nonce: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<u64, HostError> {
        if now >= expires_at || expires_at.saturating_sub(now) > 300 {
            return Err(HostError::EvidenceInvalid);
        }
        let digest = replay_digest(device, nonce)?;
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            ledger
                .transport_replays
                .retain(|item| now < item.expires_at_epoch_s);
            if ledger
                .transport_replays
                .iter()
                .any(|item| item.digest == digest)
            {
                return Err(HostError::EvidenceInvalid);
            }
            if ledger.transport_replays.len() >= 8192
                || ledger
                    .transport_replays
                    .iter()
                    .filter(|item| item.device_id == device)
                    .count()
                    >= 256
            {
                return Err(HostError::StateInvalid);
            }
            ledger.transport_replays.push(TransportReplayV1 {
                device_id: device.into(),
                digest,
                expires_at_epoch_s: expires_at,
            });
            ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, owner, &ledger)?;
            Ok(ledger.revision)
        })
    }
}

fn replay_digest(device: &str, nonce: &str) -> Result<String, HostError> {
    let valid = !device.is_empty()
        && device.len() <= 128
        && nonce.len() == 64
        && nonce
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'));
    valid
        .then(|| {
            crate::host_crypto::digest(
                [
                    b"crowsi.gateway.transport-replay.v1\0".as_slice(),
                    device.as_bytes(),
                    b"\0",
                    nonce.as_bytes(),
                ]
                .concat()
                .as_slice(),
            )
        })
        .ok_or(HostError::EvidenceInvalid)
}
