use crate::AuthorityError;
use crate::state::DurableSnapshot;
#[cfg(feature = "test-support")]
use std::sync::{Arc, Mutex};

pub trait AuthorityStore: Clone + Send + Sync + 'static {
    fn read<T>(
        &self,
        operation: impl FnOnce(&DurableSnapshot) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError>;

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut DurableSnapshot) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError>;
}

#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
pub struct MemoryStore {
    snapshot: Arc<Mutex<DurableSnapshot>>,
}

#[cfg(feature = "test-support")]
impl MemoryStore {
    #[must_use]
    pub fn new(clock_floor_ms: u64) -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(DurableSnapshot::empty(clock_floor_ms))),
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: DurableSnapshot) -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(snapshot)),
        }
    }

    #[cfg(feature = "test-support")]
    pub fn export_snapshot(&self) -> Result<DurableSnapshot, AuthorityError> {
        self.read(|snapshot| Ok(snapshot.clone()))
    }
}

#[cfg(feature = "test-support")]
impl AuthorityStore for MemoryStore {
    fn read<T>(
        &self,
        operation: impl FnOnce(&DurableSnapshot) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        let guard = self
            .snapshot
            .lock()
            .map_err(|_| AuthorityError::StoreUnavailable)?;
        operation(&guard)
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut DurableSnapshot) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        let mut guard = self
            .snapshot
            .lock()
            .map_err(|_| AuthorityError::StoreUnavailable)?;
        let mut working = guard.clone();
        let result = operation(&mut working)?;
        working.version = guard.version.saturating_add(1);
        *guard = working;
        Ok(result)
    }
}
