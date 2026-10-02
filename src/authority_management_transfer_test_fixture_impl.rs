impl Fixture {
    pub fn acceptance(&self) -> TransferAcceptance {
        TransferAcceptance::new(
            self.transfer.id().clone(),
            self.owner.clone(),
            self.target.clone(),
            target_proof(&self.owner, &self.target),
        )
        .with_provider_receipt(ProviderReissueReceipt::signed(
            "receipt-a",
            self.owner.clone(),
            ServiceId::parse("service-a").expect("service"),
            ProviderAccountRef::parse("provider-a").expect("provider"),
            self.credential.clone(),
            1,
            2,
            self.target.clone(),
            "target-nonce",
            NOW,
            "valid",
        ))
    }

    pub fn prepare_attempt(&mut self, index: u64) -> (crate::TransferReceipt, String) {
        self.prepare_attempt_for(self.target.clone(), index)
    }

    pub fn prepare_attempt_for(
        &mut self,
        target: DeviceId,
        index: u64,
    ) -> (crate::TransferReceipt, String) {
        let service = ServiceId::parse("service-a").expect("service");
        let nonce = format!("target-nonce-{index}");
        let authorization = format!("sha256:{index:064x}");
        let request = TransferRequest::new(
            self.owner.clone(),
            self.credential.clone(),
            self.source.clone(),
            target.clone(),
            self.audience.clone(),
            self.action.clone(),
            TransferMechanism::ProviderReissue,
            30_000,
            StepUpProof::verified(self.owner.clone(), self.source.clone(), NOW, NOW + 30_000),
            TargetKeyProof::verified(
                self.owner.clone(),
                target.clone(),
                key(&target),
                nonce.clone(),
                NOW,
            ),
        );
        let receipt = self
            .authority
            .prepare_management_transfer(
                request,
                &authorization,
                &binding(&self.source, &service),
                &binding(&target, &service),
            )
            .expect("repeated management prepare");
        (receipt, nonce)
    }
}
