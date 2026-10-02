use crate::{AuthorityError, AuthorityStore, CommitFailPoint};

#[cfg(feature = "test-support")]
const MAX_CLOCK_ADVANCE_MS: u64 = 86_400_000;

#[derive(Clone, Debug)]
pub struct CredentialAuthority<S: AuthorityStore> {
    pub(crate) store: S,
    pub(crate) local_clock_ms: u64,
    pub(crate) fail_point: Option<CommitFailPoint>,
}

impl<S: AuthorityStore> CredentialAuthority<S> {
    #[must_use]
    pub const fn with_store(store: S, now_ms: u64) -> Self {
        Self {
            store,
            local_clock_ms: now_ms,
            fail_point: None,
        }
    }

    #[cfg(feature = "test-support")]
    pub fn reopen_from_durable_store(&self) -> Self {
        let clock = self
            .store
            .read(|snapshot| Ok(snapshot.clock_floor_ms))
            .unwrap_or(self.local_clock_ms);
        Self::with_store(self.store.clone(), clock)
    }

    #[cfg(feature = "test-support")]
    pub fn advance_clock(&mut self, delta_ms: u64) {
        let bounded = delta_ms.min(MAX_CLOCK_ADVANCE_MS);
        self.local_clock_ms = self.local_clock_ms.saturating_add(bounded);
        let now = self.local_clock_ms;
        let _ = self.store.transact(|snapshot| {
            snapshot.clock_floor_ms = snapshot.clock_floor_ms.max(now);
            Ok(())
        });
    }

    #[cfg(feature = "test-support")]
    pub fn rewind_clock_to(&mut self, requested_ms: u64) {
        let floor = self
            .store
            .read(|snapshot| Ok(snapshot.clock_floor_ms))
            .unwrap_or(self.local_clock_ms);
        self.local_clock_ms = requested_ms.max(floor);
    }

    #[cfg(feature = "test-support")]
    pub fn fail_next_commit_at(&mut self, fail_point: CommitFailPoint) {
        self.fail_point = Some(fail_point);
    }

    pub(crate) fn now_ms(&self) -> Result<u64, AuthorityError> {
        self.store
            .read(|snapshot| Ok(snapshot.clock_floor_ms.max(self.local_clock_ms)))
    }
}
