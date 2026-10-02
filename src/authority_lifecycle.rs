use crate::validation::{active_account, step_up};
use crate::{
    AccountClosureReceipt, AccountClosureRequest, AccountState, AuthorityError, AuthorityStore,
    CredentialAuthority, GrantState, OpaqueOwnerRef,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn apply_account_closure(
        &mut self,
        request: AccountClosureRequest,
    ) -> Result<AccountClosureReceipt, AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            active_account(snapshot, &request.owner)?;
            step_up(
                snapshot,
                &request.owner,
                &request.requested_by,
                &request.step_up,
                now,
            )?;
            snapshot
                .accounts
                .insert(request.owner.clone(), request.state);
            for grant in snapshot.grants.values_mut() {
                if grant.owner == request.owner
                    && matches!(grant.state, GrantState::Active | GrantState::Pending)
                {
                    grant.state = GrantState::Revoked;
                }
            }
            Ok(AccountClosureReceipt {
                state: request.state,
                secret_deletion_attempted: false,
            })
        })
    }

    pub fn account_state(&self, owner: &OpaqueOwnerRef) -> Option<AccountState> {
        self.store
            .read(|snapshot| Ok(snapshot.accounts.get(owner).copied()))
            .ok()
            .flatten()
    }

    pub fn custody_secret_deletion_requests(&self) -> usize {
        self.store
            .read(|snapshot| Ok(snapshot.custody_secret_deletion_requests))
            .unwrap_or(0)
    }
}
