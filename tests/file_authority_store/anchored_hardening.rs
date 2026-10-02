use super::*;
use nix::{sys::stat::Mode, unistd::mkfifo};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

#[test]
fn retained_files_reject_symlink_hardlink_fifo_and_oversize() {
    for attack in ["symlink", "hardlink", "fifo", "oversize"] {
        let store = TemporaryStore::new(attack);
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
        let generation = retained(store.path(), "authority-generation-");
        let outside = store.root_path().join(format!("{attack}-outside"));
        match attack {
            "symlink" => {
                fs::rename(&generation, &outside).expect("move generation");
                symlink(&outside, &generation).expect("symlink generation");
            }
            "hardlink" => fs::hard_link(&generation, &outside).expect("hardlink generation"),
            "fifo" => {
                fs::rename(&generation, &outside).expect("move generation");
                mkfifo(&generation, Mode::S_IRUSR | Mode::S_IWUSR).expect("fifo generation");
            }
            "oversize" => OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&generation)
                .expect("generation")
                .set_len(4 * 1024 * 1024 + 1)
                .expect("oversize generation"),
            _ => unreachable!(),
        }
        assert!(FileAuthorityStore::open_anchored(store.path(), store.anchor()).is_err());
    }
}

#[test]
fn lock_rejects_link_mode_and_replacement() {
    for attack in ["hardlink", "mode", "symlink"] {
        let store = TemporaryStore::new(attack);
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
        let lock = store.path().join("authority.lock");
        let outside = store.root_path().join(format!("lock-{attack}"));
        match attack {
            "hardlink" => fs::hard_link(&lock, &outside).expect("hardlink lock"),
            "mode" => {
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).expect("lock mode");
            }
            "symlink" => {
                fs::rename(&lock, &outside).expect("move lock");
                symlink(&outside, &lock).expect("symlink lock");
            }
            _ => unreachable!(),
        }
        assert!(FileAuthorityStore::open_anchored(store.path(), store.anchor()).is_err());
    }
}

#[test]
fn directory_chmod_and_swap_during_transaction_fail_closed() {
    let store = TemporaryStore::new("directory-mutation");
    let authority =
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
    let changed = authority.transact(|_| {
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o755)).expect("chmod state");
        Ok(())
    });
    assert!(changed.is_err());
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700)).expect("restore mode");
    FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("unchanged store");

    let authority = FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("open");
    let changed = authority.transact(|_| {
        fs::set_permissions(store.anchor(), fs::Permissions::from_mode(0o750))
            .expect("chmod anchor");
        Ok(())
    });
    assert!(changed.is_err());
    fs::set_permissions(store.anchor(), fs::Permissions::from_mode(0o700))
        .expect("restore anchor mode");
    FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("anchor unchanged");

    let authority = FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("open");
    let original = store.root_path().join("state-original");
    let swapped = authority.transact(|_| {
        fs::rename(store.path(), &original).expect("pin original");
        fs::create_dir(store.path()).expect("impostor");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700))
            .expect("impostor mode");
        Ok(())
    });
    assert!(swapped.is_err());
    fs::remove_dir(store.path()).expect("remove impostor");
    fs::rename(original, store.path()).expect("restore original");
    FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("pinned state intact");
    let authority = FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("open");
    let restored = store.root_path().join("state-restored");
    authority
        .transact(|_| {
            fs::rename(store.path(), &restored).expect("move original");
            fs::create_dir(store.path()).expect("temporary impostor");
            fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700))
                .expect("impostor mode");
            fs::remove_dir(store.path()).expect("remove temporary impostor");
            fs::rename(&restored, store.path()).expect("restore before commit");
            Ok(())
        })
        .expect("retained descriptor makes restored swap safe");
    FileAuthorityStore::open_anchored(store.path(), store.anchor())
        .expect("committed after restore");
}

fn retained(directory: &Path, prefix: &str) -> PathBuf {
    fs::read_dir(directory)
        .expect("directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .expect("retained file")
}
