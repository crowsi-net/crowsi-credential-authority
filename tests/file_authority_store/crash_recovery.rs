use super::*;
use crowsi_credential_authority::test_support::{FileStoreFailpoint, set_file_store_failpoint};

#[test]
fn initialize_once_resumes_every_committed_stage_exactly() {
    for point in [
        FileStoreFailpoint::StateMarkerWritten,
        FileStoreFailpoint::AnchorMarkerWritten,
        FileStoreFailpoint::GenerationWritten,
        FileStoreFailpoint::GenerationSynced,
        FileStoreFailpoint::AnchorWritten,
        FileStoreFailpoint::AnchorSynced,
        FileStoreFailpoint::StateHeadWritten,
        FileStoreFailpoint::AnchorHeadWritten,
    ] {
        let store = TemporaryStore::new(&format!("init-{point:?}"));
        set_file_store_failpoint(Some(point));
        assert!(initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).is_err());
        set_file_store_failpoint(None);
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS)
            .expect("exact initialize recovery");
        FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("open initialized");
        assert_retention(&store);
    }
}

#[test]
fn initialize_once_rejects_a_different_genesis_clock() {
    let store = TemporaryStore::new("different-genesis-clock");
    initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
    assert!(
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS + 1).is_err(),
        "the signed initializer must retry with its stable original clock"
    );
    FileAuthorityStore::open_anchored(store.path(), store.anchor())
        .expect("original remains valid");
}

#[test]
fn pre_head_transaction_crashes_discard_uncommitted_pair() {
    for point in [
        FileStoreFailpoint::GenerationWritten,
        FileStoreFailpoint::GenerationSynced,
        FileStoreFailpoint::AnchorWritten,
        FileStoreFailpoint::AnchorSynced,
    ] {
        let store = TemporaryStore::new(&format!("pre-head-{point:?}"));
        let authority = initialize_file_authority_store(store.path(), store.anchor(), NOW_MS)
            .expect("initialize");
        let old_head = fs::read(store.path().join("authority.head.json")).expect("old head");
        set_file_store_failpoint(Some(point));
        assert!(authority.transact(|_| Ok(())).is_err());
        set_file_store_failpoint(None);
        FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("recover old head");
        assert_eq!(
            fs::read(store.path().join("authority.head.json")).expect("head"),
            old_head
        );
        assert_retention(&store);
    }
}

#[test]
fn head_and_prune_crashes_reconcile_forward() {
    for point in [
        FileStoreFailpoint::StateHeadWritten,
        FileStoreFailpoint::AnchorHeadWritten,
    ] {
        let store = TemporaryStore::new(&format!("head-{point:?}"));
        let authority = initialize_file_authority_store(store.path(), store.anchor(), NOW_MS)
            .expect("initialize");
        set_file_store_failpoint(Some(point));
        assert!(authority.transact(|_| Ok(())).is_err());
        set_file_store_failpoint(None);
        FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("finish head");
        assert_heads_equal(&store);
    }
    for point in [
        FileStoreFailpoint::StatePruned,
        FileStoreFailpoint::AnchorPruned,
    ] {
        let store = TemporaryStore::new(&format!("prune-{point:?}"));
        let authority = initialize_file_authority_store(store.path(), store.anchor(), NOW_MS)
            .expect("initialize");
        authority.transact(|_| Ok(())).expect("generation one");
        authority.transact(|_| Ok(())).expect("generation two");
        set_file_store_failpoint(Some(point));
        assert!(authority.transact(|_| Ok(())).is_err());
        set_file_store_failpoint(None);
        FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("finish prune");
        assert_heads_equal(&store);
        assert_retention(&store);
    }
}

fn assert_heads_equal(store: &TemporaryStore) {
    assert_eq!(
        fs::read(store.path().join("authority.head.json")).expect("state head"),
        fs::read(store.anchor().join("authority.head.json")).expect("anchor head")
    );
}

fn assert_retention(store: &TemporaryStore) {
    for (path, prefix) in [
        (store.path(), "authority-generation-"),
        (store.anchor(), "authority-anchor-"),
    ] {
        let count = fs::read_dir(path)
            .expect("directory")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .count();
        assert!((1..=3).contains(&count));
    }
}
