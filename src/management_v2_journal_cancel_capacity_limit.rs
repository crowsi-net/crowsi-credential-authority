#[cfg(all(test, feature = "test-support"))]
thread_local! {
    static TEST_MAX_LEDGER_BYTES: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
}

fn maximum_ledger_bytes() -> u64 {
    #[cfg(all(test, feature = "test-support"))]
    if let Some(value) = TEST_MAX_LEDGER_BYTES.get() {
        return value;
    }
    MAX_LEDGER_BYTES
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn with_test_limit<T>(limit: u64, action: impl FnOnce() -> T) -> T {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_MAX_LEDGER_BYTES.set(self.0);
        }
    }
    let prior = TEST_MAX_LEDGER_BYTES.replace(Some(limit));
    let _reset = Reset(prior);
    action()
}
