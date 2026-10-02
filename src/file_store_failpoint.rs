use crate::AuthorityError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileStoreFailpoint {
    StateMarkerWritten,
    AnchorMarkerWritten,
    GenerationWritten,
    GenerationSynced,
    AnchorWritten,
    AnchorSynced,
    StateHeadWritten,
    AnchorHeadWritten,
    StatePruned,
    AnchorPruned,
}

#[cfg(feature = "test-support")]
std::thread_local! {
    static ACTIVE: std::cell::Cell<Option<FileStoreFailpoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(feature = "test-support")]
pub fn set_file_store_failpoint(value: Option<FileStoreFailpoint>) {
    ACTIVE.with(|active| active.set(value));
}

#[cfg(feature = "test-support")]
pub(crate) fn hit(value: FileStoreFailpoint) -> Result<(), AuthorityError> {
    ACTIVE.with(|active| {
        if active.get() == Some(value) {
            active.set(None);
            Err(AuthorityError::StoreUnavailable)
        } else {
            Ok(())
        }
    })
}

#[cfg(not(feature = "test-support"))]
// Keep one fallible call shape across production and failpoint builds so every
// durable write site propagates an injected failure at the same boundary.
#[allow(clippy::unnecessary_wraps)]
pub(crate) const fn hit(_value: FileStoreFailpoint) -> Result<(), AuthorityError> {
    Ok(())
}
