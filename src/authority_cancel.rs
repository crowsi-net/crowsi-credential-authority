use crate::validation::step_up;
use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, TransferCancellation,
    TransferCancellationReceipt, TransferState,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn cancel_transfer(
        &mut self,
        request: TransferCancellation,
    ) -> Result<TransferCancellationReceipt, AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            let record = snapshot
                .transfers
                .get(&request.transfer_id)
                .ok_or(AuthorityError::NotFound)?
                .clone();
            if record.state == TransferState::Committed {
                return Err(AuthorityError::TransferAlreadyConsumed);
            }
            if record.state == TransferState::Cancelled {
                return Err(AuthorityError::TransferCancelled);
            }
            if request.owner != record.owner {
                return Err(AuthorityError::WrongOwner);
            }
            if request.source_device != record.source_device {
                return Err(AuthorityError::WrongDevice);
            }
            step_up(
                snapshot,
                &record.owner,
                &record.source_device,
                &request.step_up,
                now,
            )?;
            crate::authority_transfer_cancel::grants(snapshot, &record, now)?;
            snapshot
                .transfers
                .get_mut(&record.id)
                .ok_or(AuthorityError::NotFound)?
                .state = TransferState::Cancelled;
            Ok(TransferCancellationReceipt {
                state: TransferState::Cancelled,
            })
        })
    }
}
