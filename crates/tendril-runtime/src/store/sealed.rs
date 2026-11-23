//! Codec helpers for sealed runtime state (`rt-roster.sealed`, `rt-groups.sealed`).

use std::fs;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tendril_core::error::CoreError;
use tendril_core::state_seal::{StateKey, StateKind, open_state, seal_state};
use zeroize::Zeroizing;

use crate::error::RuntimeError;

/// Reads, opens, and parses the sealed `kind` file at `path`. The caller has already checked the
/// file is a private regular file.
pub(super) fn load<T: DeserializeOwned>(
    key: &StateKey,
    kind: StateKind,
    path: &Path,
) -> Result<T, RuntimeError> {
    let raw = Zeroizing::new(fs::read(path)?);
    let plain = open_state(key, kind, &raw).map_err(|err| match err {
        CoreError::UnsupportedVersion(v) => {
            RuntimeError::Storage(format!("unsupported sealed state version {v}"))
        }
        _ => RuntimeError::Storage(format!(
            "sealed {} state cannot be opened (corrupt, tampered, wrong kind, or another identity)",
            kind.label()
        )),
    })?;
    serde_json::from_slice(&plain).map_err(|err| {
        RuntimeError::Storage(format!("invalid sealed {} state: {err}", kind.label()))
    })
}

/// Serializes `value` as compact JSON and seals it as a `kind` file.
pub(super) fn seal<T: Serialize>(
    key: &StateKey,
    kind: StateKind,
    value: &T,
) -> Result<Vec<u8>, RuntimeError> {
    let json = Zeroizing::new(serde_json::to_vec(value).map_err(|err| {
        RuntimeError::Storage(format!("serialize {} state failed: {err}", kind.label()))
    })?);
    Ok(seal_state(key, kind, &json)?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tendril_core::crypto::{SigningKeypair, StaticKeypair};
    use tendril_core::grants::{RevocationListUnsigned, sign_crl};
    use tendril_core::group::{
        GroupBook, GroupBuildParams, GroupManifest, GroupMember, GroupSigner, V2GroupSecrets,
        add_member, create_group, group_id_from_root, is_active_member, remove_member,
    };
    use tendril_core::identity::EndpointIdentity;
    use tendril_core::roster::{Roster, V2PeerSecrets};

    use super::*;
    use crate::driver::current_unix_secs;
    use crate::store::{StateStore, fault};

    fn ident(n: u8) -> EndpointIdentity {
        EndpointIdentity::from_keys(
            StaticKeypair::from_scalar([0x40 + n; 32]),
            SigningKeypair::from_seed([0x60 + n; 32]),
        )
    }

    fn member(id: &EndpointIdentity, gid: &str) -> GroupMember {
        GroupMember::new(
            id.static_key().public_bytes(),
            "m",
            id.signing_key().public_key(),
            vec!["direct:127.0.0.1:1".to_owned()],
            vec![format!("group.recv:{gid}"), format!("group.send:{gid}")],
        )
    }

    struct Group {
        root: EndpointIdentity,
        gid: String,
        manifest: GroupManifest,
        secrets: V2GroupSecrets,
    }

    impl Group {
        fn new(root: EndpointIdentity, members: &[&EndpointIdentity]) -> Self {
            let gid = group_id_from_root(root.signing_key().public_key());
            let params = GroupBuildParams::new(current_unix_secs());
            let (mut manifest, mut secrets) =
                create_group(root.signing_key(), "sealed", 1, member(&root, &gid), params).unwrap();
            for m in members {
                (manifest, secrets) = add_member(
                    &manifest,
                    &GroupSigner::root(root.signing_key()),
                    member(m, &gid),
                    &secrets,
                    params,
                )
                .unwrap();
            }
            Self {
                root,
                gid,
                manifest,
                secrets,
            }
        }

        fn remove(&mut self, m: &EndpointIdentity) -> GroupManifest {
            let params = GroupBuildParams::new(current_unix_secs());
            (self.manifest, self.secrets) = remove_member(
                &self.manifest,
                &GroupSigner::root(self.root.signing_key()),
                &m.device_id(),
                &self.secrets,
                params,
            )
            .unwrap();
            self.manifest.clone()
        }
    }

    fn ingest(store: &StateStore, manifest: &GroupManifest) {
        store
            .update_group_book(|book| {
                book.ingest_group_manifest(manifest, current_unix_secs(), None)?;
                Ok(())
            })
            .unwrap();
    }

    fn is_member(store: &StateStore, gid: &str, id: &EndpointIdentity) -> bool {
        let book = store.load_group_book().unwrap();
        is_active_member(book.manifest(gid).unwrap(), &id.device_id())
    }

    fn pin(roster: &mut Roster, id: &EndpointIdentity) -> Result<(), RuntimeError> {
        roster.insert_pinned_host(
            id.device_id(),
            "p".to_owned(),
            *id.static_key().public_bytes(),
            Some(id.signing_key().public_key().clone()),
            0,
            vec![],
        )?;
        Ok(())
    }

    fn pin_static(roster: &mut Roster, scalar: [u8; 32]) -> Result<(), RuntimeError> {
        let key = StaticKeypair::from_scalar(scalar);
        roster.insert_pinned_host(
            key.device_id(),
            "p".to_owned(),
            *key.public_bytes(),
            None,
            0,
            vec![],
        )?;
        Ok(())
    }

    fn state_dir() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        (tmp, dir)
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn storage_err<T: std::fmt::Debug>(res: Result<T, RuntimeError>, needle: &str) {
        let err = res.expect_err("expected an error").to_string();
        assert!(err.contains(needle), "{err:?} does not contain {needle:?}");
    }

    #[test]
    fn sealed_store_roundtrip_and_layout() {
        let (_tmp, dir) = state_dir();
        let me = ident(1);
        let peer = ident(4);
        let sibling = ident(3);
        let pairwise = V2PeerSecrets::new([0x71; 32], [0x72; 32]);
        let group = Group::new(ident(2), &[&me, &sibling]);
        let store = StateStore::open_sealed(&dir, &me).unwrap();
        assert!(store.is_sealed());

        store
            .update_group_book(|book| {
                let by = BTreeSet::from(["peer-handle".to_owned()]);
                book.ingest_first_contact_manifest(
                    &group.manifest,
                    current_unix_secs(),
                    None,
                    &by,
                )?;
                book.install_secrets(&group.gid, group.secrets.clone())?;
                book.set_pairwise_secrets(&group.gid, &sibling.device_id(), pairwise.clone())?;
                Ok(())
            })
            .unwrap();
        store.update_roster(|r| pin(r, &peer)).unwrap();

        let before = serde_json::to_value(store.load_group_book().unwrap()).unwrap();
        assert!(before.to_string().contains("pinned_by"));

        let reopened = StateStore::open_sealed(&dir, &me).unwrap();
        let reopened_book = reopened.load_group_book().unwrap();
        assert!(
            reopened_book.pairwise_secrets(&group.gid, &sibling.device_id()) == Some(&pairwise)
        );
        let after = serde_json::to_value(reopened_book).unwrap();
        assert_eq!(before, after);
        assert!(
            reopened
                .load_roster()
                .unwrap()
                .get(&peer.device_id())
                .is_some()
        );

        assert_eq!(
            listing(&dir),
            [
                ".groups.lock",
                ".roster.lock",
                "rt-groups.sealed",
                "rt-roster.sealed"
            ]
        );
        for name in ["rt-groups.sealed", "rt-roster.sealed"] {
            let mode = fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
        let raw = fs::read(dir.join("rt-groups.sealed")).unwrap();
        assert!(
            !raw.windows(group.gid.len())
                .any(|w| w == group.gid.as_bytes())
        );

        storage_err(store.load_identity(), "binding-sealed");
        storage_err(store.save_identity(&me), "binding-sealed");
        storage_err(store.load_or_generate_identity(None), "binding-sealed");
        assert!(!dir.join("identity.json").exists());

        storage_err(StateStore::open_sealed(&dir, &ident(9)), "cannot be opened");

        let groups = dir.join("rt-groups.sealed");
        fs::set_permissions(&groups, fs::Permissions::from_mode(0o644)).unwrap();
        storage_err(StateStore::open_sealed(&dir, &me), "insecure mode");
        fs::set_permissions(&groups, fs::Permissions::from_mode(0o600)).unwrap();

        let roster = dir.join("rt-roster.sealed");
        let moved = dir.join("moved");
        fs::rename(&roster, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &roster).unwrap();
        storage_err(StateStore::open_sealed(&dir, &me), "symlink");
        fs::remove_file(&roster).unwrap();
        fs::rename(&moved, &roster).unwrap();

        let key = StateKey::derive(me.static_key());
        fs::write(
            &groups,
            seal_state(&key, StateKind::Groups, b"not json").unwrap(),
        )
        .unwrap();
        storage_err(
            StateStore::open_sealed(&dir, &me),
            "invalid sealed groups state",
        );
        fs::write(
            &groups,
            seal(&key, StateKind::Groups, &GroupBook::new()).unwrap(),
        )
        .unwrap();
        StateStore::open_sealed(&dir, &me).unwrap();
    }

    #[test]
    fn sealed_store_independent_opens_do_not_lose_updates() {
        let (_tmp, dir) = state_dir();
        let me = ident(1);
        let removed = ident(3);
        let issuer = ident(5);
        let floor_peer = ident(6);
        let mut group = Group::new(ident(2), &[&me, &removed]);

        let seed = StateStore::open_sealed(&dir, &me).unwrap();
        ingest(&seed, &group.manifest);
        seed.update_roster(|r| {
            pin(r, &issuer)?;
            pin(r, &floor_peer)
        })
        .unwrap();

        let h1 = StateStore::open_sealed(&dir, &me).unwrap();
        let h2 = StateStore::open_sealed(&dir, &me).unwrap();

        ingest(&h1, &group.remove(&removed));
        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: issuer.device_id(),
                seq: 1,
                revoked_devices: vec![ident(7).device_id()],
                revoked_nonces: vec![],
                ts: "2026-11-23T00:00:00Z".to_owned(),
            },
            issuer.signing_key(),
        )
        .unwrap();
        h1.update_roster(|r| {
            r.ingest_crl(crl, &issuer.device_id(), issuer.signing_key().public_key())?;
            Ok(())
        })
        .unwrap();

        // h2's group write does not carry the removal, so only a reload inside the lock keeps it.
        let secrets = group.secrets.clone();
        h2.update_group_book(|book| {
            book.install_secrets(&group.gid, secrets)?;
            Ok(())
        })
        .unwrap();
        h2.update_roster(|r| {
            r.set_peer_min_wire_version(&floor_peer.device_id(), 2)?;
            Ok(())
        })
        .unwrap();

        let check = StateStore::open_sealed(&dir, &me).unwrap();
        assert!(!is_member(&check, &group.gid, &removed));
        assert!(
            check
                .load_group_book()
                .unwrap()
                .secrets(&group.gid)
                .is_some()
        );
        let roster = check.load_roster().unwrap();
        assert!(roster.crl(&issuer.device_id()).is_some(), "CRL lost");
        assert_eq!(
            roster
                .get(&floor_peer.device_id())
                .unwrap()
                .min_wire_version,
            2
        );

        let workers: Vec<_> = (0u8..2)
            .map(|t| {
                let dir = dir.clone();
                let me = ident(1);
                std::thread::spawn(move || {
                    let handle = StateStore::open_sealed(&dir, &me).unwrap();
                    for i in 0u8..20 {
                        handle
                            .update_roster(|r| pin_static(r, [0x80 + t * 20 + i; 32]))
                            .unwrap();
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        let roster = StateStore::open_sealed(&dir, &me)
            .unwrap()
            .load_roster()
            .unwrap();
        for n in 0u8..40 {
            let id = StaticKeypair::from_scalar([0x80 + n; 32]).device_id();
            assert!(roster.get(&id).is_some(), "insert {n} lost");
        }
    }

    fn reset_faults() {
        fault::FAIL_AT.with(|f| f.set(None));
        fault::DIR_SYNCS.with(|n| n.set(0));
        fault::SYNCED_DIRS.with(std::cell::RefCell::take);
    }

    fn synced_dirs() -> Vec<PathBuf> {
        fault::SYNCED_DIRS.with(std::cell::RefCell::take)
    }

    /// `dir` and its canonical ancestors up to the first one this process cannot open.
    fn openable_chain(dir: &Path) -> Vec<PathBuf> {
        fs::canonicalize(dir)
            .unwrap()
            .ancestors()
            .take_while(|p| fs::File::open(p).is_ok())
            .map(Path::to_path_buf)
            .collect()
    }

    fn temp_files(dir: &Path) -> Vec<String> {
        listing(dir)
            .into_iter()
            .filter(|n| n.contains(".tmp."))
            .collect()
    }

    #[test]
    fn atomic_write_failure_semantics() {
        let (_tmp, dir) = state_dir();
        let store = StateStore::open_sealed(&dir, &ident(1)).unwrap();
        reset_faults();
        store.update_roster(|r| pin_static(r, [0x91; 32])).unwrap();
        let target = dir.join("rt-roster.sealed");
        let committed = fs::read(&target).unwrap();

        for (n, step) in [
            (0x92u8, fault::Step::WriteTemp),
            (0x93, fault::Step::Rename),
        ] {
            fault::FAIL_AT.with(|f| f.set(Some(step)));
            storage_err(
                store.update_roster(|r| pin_static(r, [n; 32])),
                "injected fault",
            );
            reset_faults();
            assert_eq!(fs::read(&target).unwrap(), committed, "{step:?}");
            assert!(temp_files(&dir).is_empty(), "{step:?}");
        }

        fault::FAIL_AT.with(|f| f.set(Some(fault::Step::SyncDir)));
        storage_err(
            store.update_roster(|r| pin_static(r, [0x94; 32])),
            "state commit not durable",
        );
        reset_faults();
        assert!(temp_files(&dir).is_empty());
        assert_ne!(
            fs::read(&target).unwrap(),
            committed,
            "renamed bytes stay visible"
        );

        store.update_roster(|r| pin_static(r, [0x95; 32])).unwrap();
        assert_eq!(fault::DIR_SYNCS.with(std::cell::Cell::get), 1);

        let plain_dir = dir.with_file_name("plain");
        let plain = StateStore::open_or_create(&plain_dir).unwrap();
        reset_faults();
        plain.update_roster(|r| pin_static(r, [0x96; 32])).unwrap();
        assert_eq!(fault::DIR_SYNCS.with(std::cell::Cell::get), 1);
        reset_faults();
    }

    #[test]
    fn sealed_seed_needs_both_runtime_files_absent() {
        let (_tmp, dir) = state_dir();
        let me = ident(1);
        let mut seed = Roster::new();
        pin_static(&mut seed, [0xa1; 32]).unwrap();

        let writer = StateStore::open_sealed(&dir, &me).unwrap();
        ingest(&writer, &Group::new(ident(2), &[&me]).manifest);
        assert!(!dir.join("rt-roster.sealed").exists());

        let opener = StateStore::open_sealed(&dir, &me).unwrap();
        assert!(!opener.seed_roster_if_absent(&seed).unwrap());
        assert!(!dir.join("rt-roster.sealed").exists());
        assert_eq!(opener.load_roster().unwrap().entries().count(), 0);

        let (_tmp2, fresh) = state_dir();
        let store = StateStore::open_sealed(&fresh, &me).unwrap();
        assert!(store.seed_roster_if_absent(&seed).unwrap());
        assert!(!store.seed_roster_if_absent(&Roster::new()).unwrap());
        assert_eq!(store.load_roster().unwrap().entries().count(), 1);
    }

    #[test]
    fn sealed_migration_retry_after_unacknowledged_seed() {
        let (_tmp, dir) = state_dir();
        let me = ident(1);
        let mut seed = Roster::new();
        pin_static(&mut seed, [0xa2; 32]).unwrap();

        let store = StateStore::open_sealed(&dir, &me).unwrap();
        fault::FAIL_AT.with(|f| f.set(Some(fault::Step::SyncDir)));
        storage_err(
            store.seed_roster_if_absent(&seed),
            "state commit not durable",
        );
        reset_faults();
        assert!(
            dir.join("rt-roster.sealed").exists(),
            "visible, not acknowledged"
        );

        let retry = StateStore::open_sealed(&dir, &me).unwrap();
        assert!(
            fault::DIR_SYNCS.with(std::cell::Cell::get) >= 1,
            "reopen syncs the directory before the caller deletes the legacy copy"
        );
        assert!(!retry.seed_roster_if_absent(&Roster::new()).unwrap());
        assert_eq!(retry.load_roster().unwrap().entries().count(), 1);
        reset_faults();
    }

    #[test]
    fn reopen_syncs_every_ancestor_after_interrupted_first_open() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let b = root.join("a").join("b");
        let nested = b.join("state");
        // An earlier open created the tree and died before any sync.
        fs::create_dir_all(&nested).unwrap();
        let expected = openable_chain(&nested);
        for (kind, sealed) in [("sealed", true), ("plain", false)] {
            reset_faults();
            if sealed {
                StateStore::open_sealed(&nested, &ident(1)).unwrap();
            } else {
                StateStore::open_or_create(&nested).unwrap();
            }
            let synced = synced_dirs();
            assert_eq!(synced, expected, "{kind}");
            for dir in [&nested, &b, &root.join("a"), &root] {
                assert!(synced.contains(dir), "{kind}: {} not synced", dir.display());
            }
        }

        reset_faults();
        let fresh = root.join("c").join("state");
        StateStore::open_sealed(&fresh, &ident(1)).unwrap();
        assert_eq!(synced_dirs(), openable_chain(&fresh));

        fault::FAIL_AT.with(|f| f.set(Some(fault::Step::SyncDir)));
        storage_err(
            StateStore::open_sealed(root.join("other"), &ident(1)),
            "state directory not durable",
        );
        reset_faults();
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_walk_stops_at_unreadable_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let locked = fs::canonicalize(tmp.path()).unwrap().join("locked");
        let app = locked.join("app");
        let nested = app.join("state");
        fs::create_dir_all(&nested).unwrap();
        // Searchable but not readable, like the parent of an app sandbox.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o311)).unwrap();
        let readable = fs::File::open(&locked).is_ok();
        reset_faults();
        let opened = StateStore::open_sealed(&nested, &ident(1));
        let synced = synced_dirs();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        opened.unwrap();
        if readable {
            return; // privileged process: permission bits do not apply
        }
        assert_eq!(synced, vec![nested, app]);
    }

    #[test]
    fn sealed_store_whole_file_replay_is_accepted() {
        let (_tmp, dir) = state_dir();
        let me = ident(1);
        let removed = ident(3);
        let mut group = Group::new(ident(2), &[&me, &removed]);
        let store = StateStore::open_sealed(&dir, &me).unwrap();
        ingest(&store, &group.manifest);
        let path = dir.join("rt-groups.sealed");
        let old = fs::read(&path).unwrap();

        let newer = group.remove(&removed);
        ingest(&store, &newer);
        assert!(!is_member(&store, &group.gid, &removed));

        fs::write(&path, &old).unwrap();
        let replayed = StateStore::open_sealed(&dir, &me).unwrap();
        assert!(
            is_member(&replayed, &group.gid, &removed),
            "whole-file replay is accepted by policy (Local state replay)"
        );
        ingest(&replayed, &newer);
        assert!(!is_member(&replayed, &group.gid, &removed));
    }
}
