use crate::{
    gateway_peer_state::{PeerDenyLedgerV1, PeerStatusEntryV1},
    gateway_peer_state_io::validate,
};

#[test]
fn ledger_rejects_bad_identifiers_and_duplicate_peer_tuples() {
    let mut value = PeerDenyLedgerV1::empty();
    value.entries.push(entry("device-a", "request-a", 'a'));
    assert!(validate(&value, value.revision).is_ok());
    value.entries.push(entry("device-a", "request-b", 'b'));
    assert!(validate(&value, value.revision).is_err());
    value.entries.pop();
    value.entries[0].request_key_id = " request-a".into();
    assert!(validate(&value, value.revision).is_err());
}

fn entry(device: &str, request_key: &str, certificate: char) -> PeerStatusEntryV1 {
    PeerStatusEntryV1 {
        device_id: device.into(),
        certificate_sha256: format!("sha256:{}", certificate.to_string().repeat(64)),
        request_key_id: request_key.into(),
        registered: true,
        revoked: true,
        device_revocation_epoch: 2,
        revoked_at_epoch_s: 100,
    }
}
