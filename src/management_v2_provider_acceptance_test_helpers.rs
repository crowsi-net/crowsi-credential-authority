fn receipt_document(key: &SigningKey, nonce: &str) -> HostProviderEvidence {
    let payload = serde_json::to_vec(&serde_json::json!({
        "credential_id":"credential-a", "issued_at_epoch_ms":NOW * 1_000,
        "nonce":nonce, "owner_ref":"psa_service-a_01JOWNER000000000000000001",
        "previous_revision":1,
        "provider_account_ref":"provider-a", "receipt_id":"receipt-a", "revision":2,
        "service_id":"service-a", "target_device_id":"device-b",
    }))
    .expect("payload");
    HostProviderEvidence {
        schema: "crowsi://credential-authority/provider-evidence/v1".into(),
        kind: "reissue-receipt".into(),
        key_id: "provider-key".into(),
        signature: crate::host_crypto::sign(
            key,
            &crate::host_crypto::provider_payload("reissue-receipt", &payload),
        ),
        nonce: nonce.into(),
        issued_at_epoch_s: NOW,
        receipt_id: Some("receipt-a".into()),
        operation_ref: None,
        owner_ref: Some("psa_service-a_01JOWNER000000000000000001".into()),
        service_id: Some("service-a".into()),
        provider_account_ref: Some("provider-a".into()),
        credential_ref: Some("credential-a".into()),
        previous_revision: Some(1),
        revision: Some(2),
        target_device_ref: Some("device-b".into()),
    }
}

fn route(key: &SigningKey) -> HostProviderRoute {
    HostProviderRoute {
        service_id: "service-a".into(),
        executable: "/provider".into(),
        executable_sha256: format!("sha256:{}", "1".repeat(64)),
        config_path: "/provider.json".into(),
        config_sha256: format!("sha256:{}", "2".repeat(64)),
        state_directory: "/provider-state".into(),
        response_key_id: "provider-key".into(),
        response_public_key_hex: hex::encode(key.verifying_key().to_bytes()),
    }
}
