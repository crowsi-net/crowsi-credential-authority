use crate::{
    AuthorityError, AuthorityStore, DurableSnapshot, file_store_lock::StoreLock,
    file_store_path::StorePaths,
};
use std::path::Path;
#[cfg(feature = "test-support")]
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct FileAuthorityStore {
    pub(crate) paths: StorePaths,
}

impl FileAuthorityStore {
    pub(crate) fn initialize_anchored(
        state_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        initial_clock_ms: u64,
    ) -> Result<Self, AuthorityError> {
        let paths = StorePaths::prepare(state_directory.as_ref(), anchor_directory.as_ref())?;
        let lock = StoreLock::initialize(&paths)?;
        crate::file_store_codec::initialize(&paths, initial_clock_ms)?;
        lock.validate()?;
        Ok(Self { paths })
    }

    pub fn open_anchored(
        state_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
    ) -> Result<Self, AuthorityError> {
        let paths = StorePaths::prepare(state_directory.as_ref(), anchor_directory.as_ref())?;
        let lock = StoreLock::open(&paths, true)?;
        crate::file_store_codec::recover(&paths)?;
        lock.validate()?;
        Ok(Self { paths })
    }

    #[must_use]
    #[cfg(feature = "test-support")]
    pub fn directory(&self) -> PathBuf {
        self.paths.state.source().to_owned()
    }

    #[must_use]
    #[cfg(feature = "test-support")]
    pub fn anchor_directory(&self) -> PathBuf {
        self.paths.anchor.source().to_owned()
    }

    pub fn export_snapshot(&self) -> Result<DurableSnapshot, AuthorityError> {
        self.read(|snapshot| Ok(snapshot.clone()))
    }
}

impl AuthorityStore for FileAuthorityStore {
    fn read<T>(
        &self,
        operation: impl FnOnce(&DurableSnapshot) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        let lock = StoreLock::open(&self.paths, false)?;
        let loaded = crate::file_store_codec::load(&self.paths)?;
        let result = operation(&loaded.snapshot);
        crate::file_store_codec::load(&self.paths)?;
        lock.validate()?;
        result
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut DurableSnapshot) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        let lock = StoreLock::open(&self.paths, true)?;
        let loaded = crate::file_store_codec::recover(&self.paths)?;
        let mut working = loaded.snapshot.clone();
        let result = operation(&mut working);
        let result = match result {
            Ok(value) => value,
            Err(error) => {
                crate::file_store_codec::load(&self.paths)?;
                lock.validate()?;
                return Err(error);
            }
        };
        working.version = loaded
            .snapshot
            .version
            .checked_add(1)
            .ok_or(AuthorityError::IntegrityViolation)?;
        crate::file_store_codec::persist(&self.paths, &working, &loaded.state_digest)?;
        lock.validate()?;
        Ok(result)
    }
}
