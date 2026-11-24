//! Atomic, permission-restricted local persistence for endpoint identities and rosters.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_decode_array, b64url_encode};
use tendril_core::group::GroupBook;
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::roster::{PeerState, Roster};
use tendril_core::state_seal::{StateKey, StateKind};
use zeroize::{Zeroize, Zeroizing};

use crate::error::RuntimeError;
use crate::redact::redact_json_error;

mod sealed;

const IDENTITY_FILE: &str = "identity.json";
const IDENTITY_LOCK_FILE: &str = ".identity.lock";
const ROSTER_FILE: &str = "roster.json";
const ROSTER_LOCK_FILE: &str = ".roster.lock";
const GROUPS_FILE: &str = "groups.json";
const GROUPS_LOCK_FILE: &str = ".groups.lock";
const SEALED_ROSTER_FILE: &str = "rt-roster.sealed";
const SEALED_GROUPS_FILE: &str = "rt-groups.sealed";

/// Snapshot metadata identifying the on-disk state of `roster.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterStamp {
    pub len: u64,
    pub modified: Option<SystemTime>,
    #[cfg(unix)]
    pub ino: u64,
}

#[derive(Serialize, Deserialize)]
struct PersistedIdentity {
    version: u32,
    host_id: String,
    static_secret_b64: String,
    signing_seed_b64: String,
    pq_signing_seed_b64: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rotation_chain: Vec<RotationRecord>,
    #[serde(default)]
    rotation_seq: u64,
}

impl Drop for PersistedIdentity {
    fn drop(&mut self) {
        self.static_secret_b64.zeroize();
        self.signing_seed_b64.zeroize();
        self.pq_signing_seed_b64.zeroize();
    }
}

/// Serializes `identity` as versioned JSON with zeroized secret buffers.
pub fn serialize_identity_json(
    identity: &EndpointIdentity,
) -> Result<Zeroizing<String>, RuntimeError> {
    let static_b64 = Zeroizing::new(b64url_encode(identity.static_key().secret_bytes()));
    let signing_b64 = Zeroizing::new(b64url_encode(identity.signing_key().seed_bytes()));
    let pq_signing_b64 = Zeroizing::new(b64url_encode(identity.signing_key().mldsa_seed_bytes()));
    let payload = PersistedIdentity {
        version: 1,
        host_id: identity.host_id().to_owned(),
        static_secret_b64: static_b64.to_string(),
        signing_seed_b64: signing_b64.to_string(),
        pq_signing_seed_b64: pq_signing_b64.to_string(),
        rotation_chain: identity.rotation_chain().to_vec(),
        rotation_seq: identity.rotation_seq(),
    };
    let mut buf = Zeroizing::new(Vec::new());
    serde_json::to_writer_pretty(&mut *buf, &payload)
        .map_err(|err| RuntimeError::Storage(format!("serialize identity failed: {err}")))?;
    let json = String::from_utf8(std::mem::take(&mut *buf))
        .map_err(|err| RuntimeError::Storage(format!("serialize identity utf8 failed: {err}")))?;
    Ok(Zeroizing::new(json))
}

/// Deserializes and validates a versioned [`EndpointIdentity`] JSON document.
pub fn deserialize_identity_json(raw: &str) -> Result<EndpointIdentity, RuntimeError> {
    let disk: PersistedIdentity = serde_json::from_str(raw).map_err(|err| {
        RuntimeError::Storage(format!(
            "invalid identity json: {}",
            redact_json_error(&err)
        ))
    })?;
    if disk.version != 1 {
        return Err(RuntimeError::Storage(format!(
            "unsupported identity version {}",
            disk.version
        )));
    }
    let static_scalar = Zeroizing::new(b64url_decode_array::<32>(&disk.static_secret_b64)?);
    let signing_seed = Zeroizing::new(b64url_decode_array::<32>(&disk.signing_seed_b64)?);
    let pq_signing_seed = Zeroizing::new(b64url_decode_array::<32>(&disk.pq_signing_seed_b64)?);
    let static_key = StaticKeypair::from_scalar(*static_scalar);
    let signing_key = SigningKeypair::from_seeds(*signing_seed, *pq_signing_seed);
    let identity = EndpointIdentity::from_persisted(
        disk.host_id.clone(),
        static_key,
        signing_key,
        disk.rotation_chain.clone(),
        disk.rotation_seq,
    )?;
    Ok(identity)
}

/// On-disk encoding of the roster and group book.
#[derive(Debug, Clone)]
enum Codec {
    /// `roster.json` and `groups.json` in clear text, identity in `identity.json`.
    Plain,
    /// `rt-roster.sealed` and `rt-groups.sealed` sealed under a key derived from an identity the
    /// caller keeps sealed itself.
    Sealed(Arc<StateKey>),
}

/// Persistent identity and roster store rooted at a caller-supplied directory.
///
/// Every roster and group transaction takes an advisory file lock and reloads the file inside it,
/// so clones, independent opens, and other processes on the same directory never lose updates.
#[derive(Debug, Clone)]
pub struct StateStore {
    dir: PathBuf,
    codec: Codec,
}

impl StateStore {
    /// Opens or creates `dir` with `0o700` permissions on Unix.
    pub fn open_or_create(dir: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let dir = dir.as_ref().to_path_buf();
        create_durable_dir(&dir)?;
        Ok(Self {
            dir,
            codec: Codec::Plain,
        })
    }

    /// Opens or creates `dir` as a sealed store whose roster and group book live in
    /// `rt-roster.sealed` and `rt-groups.sealed`, sealed under a key derived from `identity`.
    ///
    /// Existing sealed files are opened eagerly so a corrupt, tampered, or foreign file fails
    /// here. The directory is synced first, so a caller-saved identity file and any earlier
    /// rename that was visible but unacknowledged are durable before this returns. The identity
    /// itself is never written; identity methods return an error.
    pub fn open_sealed(
        dir: impl AsRef<Path>,
        identity: &EndpointIdentity,
    ) -> Result<Self, RuntimeError> {
        let dir = dir.as_ref().to_path_buf();
        create_durable_dir(&dir)?;
        let store = Self {
            dir,
            codec: Codec::Sealed(Arc::new(StateKey::derive(identity.static_key()))),
        };
        store.load_roster()?;
        store.load_group_book()?;
        Ok(store)
    }

    /// Reports whether `dir` already holds sealed runtime state.
    pub fn sealed_state_exists(dir: impl AsRef<Path>) -> Result<bool, RuntimeError> {
        let dir = dir.as_ref();
        for name in [SEALED_ROSTER_FILE, SEALED_GROUPS_FILE] {
            match fs::symlink_metadata(dir.join(name)) {
                Ok(_) => return Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(RuntimeError::Io(err)),
            }
        }
        Ok(false)
    }

    /// Reports whether this store seals its roster and group book.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        matches!(self.codec, Codec::Sealed(_))
    }

    /// Persists `roster` only when neither the roster nor the group book file exists yet, so a
    /// legacy seed never lands in a store that is already initialized. Holds the exclusive roster
    /// lock, then the shared groups lock (the only place both are held). Returns whether it wrote.
    pub fn seed_roster_if_absent(&self, roster: &Roster) -> Result<bool, RuntimeError> {
        self.seed_roster_if_absent_with(|| Ok(roster))
    }

    /// Like [`Self::seed_roster_if_absent`], but builds the seed only once both runtime files are
    /// known to be absent, so an unused seed is never parsed or checked.
    pub fn seed_roster_if_absent_with<R: std::borrow::Borrow<Roster>>(
        &self,
        seed: impl FnOnce() -> Result<R, RuntimeError>,
    ) -> Result<bool, RuntimeError> {
        let _roster_lock = self.lock_roster_file(true)?;
        let _groups_lock = self.lock_groups_file(false)?;
        for path in [self.roster_path(), self.groups_path()] {
            match fs::symlink_metadata(path) {
                Ok(_) => return Ok(false),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(RuntimeError::Io(err)),
            }
        }
        self.save_roster_unlocked(seed()?.borrow())?;
        Ok(true)
    }

    fn refuse_identity_on_sealed(&self) -> Result<(), RuntimeError> {
        if self.is_sealed() {
            return Err(RuntimeError::Storage(
                "identity is binding-sealed".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the root directory backing this store.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the path to `identity.json`.
    #[must_use]
    pub fn identity_path(&self) -> PathBuf {
        self.dir.join(IDENTITY_FILE)
    }

    /// Returns the path to the active roster file (`roster.json`, or `rt-roster.sealed` on a
    /// sealed store).
    #[must_use]
    pub fn roster_path(&self) -> PathBuf {
        match self.codec {
            Codec::Plain => self.dir.join(ROSTER_FILE),
            Codec::Sealed(_) => self.dir.join(SEALED_ROSTER_FILE),
        }
    }

    /// Returns the path to the advisory lock file guarding `roster.json`.
    #[must_use]
    pub fn roster_lock_path(&self) -> PathBuf {
        self.dir.join(ROSTER_LOCK_FILE)
    }

    /// Returns the path to the active group book file (`groups.json`, or `rt-groups.sealed` on a
    /// sealed store).
    #[must_use]
    pub fn groups_path(&self) -> PathBuf {
        match self.codec {
            Codec::Plain => self.dir.join(GROUPS_FILE),
            Codec::Sealed(_) => self.dir.join(SEALED_GROUPS_FILE),
        }
    }

    /// Returns the path to the advisory lock file guarding `groups.json`.
    #[must_use]
    pub fn groups_lock_path(&self) -> PathBuf {
        self.dir.join(GROUPS_LOCK_FILE)
    }

    /// Loads [`EndpointIdentity`] from `identity.json`.
    pub fn load_identity(&self) -> Result<EndpointIdentity, RuntimeError> {
        self.refuse_identity_on_sealed()?;
        let path = self.identity_path();
        verify_private_file_0600(&path)?;
        let raw = Zeroizing::new(fs::read_to_string(&path)?);
        deserialize_identity_json(&raw)
    }

    /// Atomically persists [`EndpointIdentity`] with `0o600` file mode on Unix.
    pub fn save_identity(&self, identity: &EndpointIdentity) -> Result<(), RuntimeError> {
        self.refuse_identity_on_sealed()?;
        let json = serialize_identity_json(identity)?;
        self.atomic_write_0600(&self.identity_path(), json.as_bytes())
    }

    /// Loads the existing identity or generates, optionally assigns `host_id`, and saves one
    /// under an exclusive `.identity.lock` advisory lock.
    pub fn load_or_generate_identity(
        &self,
        host_id: Option<&str>,
    ) -> Result<EndpointIdentity, RuntimeError> {
        self.refuse_identity_on_sealed()?;
        let lock = open_lock_0600(&self.dir.join(IDENTITY_LOCK_FILE))?;
        flock(&lock, true)?;
        let path = self.identity_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => return self.load_identity(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(RuntimeError::Io(err)),
        }
        let mut identity = EndpointIdentity::generate()?;
        if let Some(id) = host_id
            && !id.is_empty()
        {
            identity = identity.with_host_id(id);
        }
        self.save_identity(&identity)?;
        Ok(identity)
    }

    /// Returns lightweight filesystem metadata identifying the current `roster.json` generation.
    pub fn roster_stamp(&self) -> Result<Option<RosterStamp>, RuntimeError> {
        match fs::metadata(self.roster_path()) {
            Ok(meta) => Ok(Some(RosterStamp {
                len: meta.len(),
                modified: meta.modified().ok(),
                #[cfg(unix)]
                ino: std::os::unix::fs::MetadataExt::ino(&meta),
            })),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(RuntimeError::Io(err)),
        }
    }

    /// Loads [`Roster`] from `roster.json` under a shared advisory lock, or returns a fresh
    /// default-deny [`Roster`] if absent.
    pub fn load_roster(&self) -> Result<Roster, RuntimeError> {
        let (roster, _) = self.load_roster_with_stamp()?;
        Ok(roster)
    }

    /// Loads [`Roster`] and its matching [`RosterStamp`] atomically under a shared advisory lock.
    pub fn load_roster_with_stamp(&self) -> Result<(Roster, Option<RosterStamp>), RuntimeError> {
        let _lock = self.lock_roster_file(false)?;
        let roster = self.load_roster_unlocked()?;
        let stamp = self.roster_stamp()?;
        Ok((roster, stamp))
    }

    /// Atomically persists [`Roster`] under an exclusive advisory lock with `0o600` file mode on Unix.
    pub fn save_roster(&self, roster: &Roster) -> Result<(), RuntimeError> {
        let _lock = self.lock_roster_file(true)?;
        self.save_roster_unlocked(roster)
    }

    /// Executes `f` transactionally against the latest on-disk [`Roster`] under an exclusive
    /// advisory lock (`flock`), persisting updates atomically on `Ok` and returning the updated
    /// roster with its matching [`RosterStamp`].
    pub fn update_roster_with_state<T, F>(
        &self,
        f: F,
    ) -> Result<(T, Roster, Option<RosterStamp>), RuntimeError>
    where
        F: FnOnce(&mut Roster) -> Result<T, RuntimeError>,
    {
        let _lock = self.lock_roster_file(true)?;
        let mut roster = self.load_roster_unlocked()?;
        let out = f(&mut roster)?;
        self.save_roster_unlocked(&roster)?;
        let stamp = self.roster_stamp()?;
        Ok((out, roster, stamp))
    }

    /// Executes `f` transactionally against the latest on-disk [`Roster`] under an exclusive
    /// advisory lock (`flock`), persisting updates atomically on `Ok`.
    pub fn update_roster<T, F>(&self, f: F) -> Result<T, RuntimeError>
    where
        F: FnOnce(&mut Roster) -> Result<T, RuntimeError>,
    {
        let (out, _, _) = self.update_roster_with_state(f)?;
        Ok(out)
    }

    /// Like [`Self::update_roster`], but when `f` fails, any peer that `f` transitioned to
    /// [`PeerState::Revoked`] is still persisted (and nothing else) before the error is returned,
    /// so a detected fork or revocation cannot be lost to the transactional rollback.
    pub fn update_roster_persisting_revocations<T, F>(&self, f: F) -> Result<T, RuntimeError>
    where
        F: FnOnce(&mut Roster) -> Result<T, RuntimeError>,
    {
        let _lock = self.lock_roster_file(true)?;
        let original = self.load_roster_unlocked()?;
        let mut working = original.clone();
        match f(&mut working) {
            Ok(out) => {
                self.save_roster_unlocked(&working)?;
                Ok(out)
            }
            Err(err) => {
                let newly_revoked: Vec<String> = working
                    .entries()
                    .filter(|(id, entry)| {
                        entry.state == PeerState::Revoked
                            && original
                                .get(id)
                                .is_some_and(|prev| prev.state != PeerState::Revoked)
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                if !newly_revoked.is_empty() {
                    let mut persisted = original;
                    for id in &newly_revoked {
                        let _ = persisted.revoke_peer(id);
                    }
                    self.save_roster_unlocked(&persisted)?;
                }
                Err(err)
            }
        }
    }

    /// Returns lightweight filesystem metadata identifying the current `groups.json` generation.
    pub fn groups_stamp(&self) -> Result<Option<RosterStamp>, RuntimeError> {
        match fs::metadata(self.groups_path()) {
            Ok(meta) => Ok(Some(RosterStamp {
                len: meta.len(),
                modified: meta.modified().ok(),
                #[cfg(unix)]
                ino: std::os::unix::fs::MetadataExt::ino(&meta),
            })),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(RuntimeError::Io(err)),
        }
    }

    /// Loads the [`GroupBook`] from `groups.json` under a shared advisory lock, or returns an empty
    /// book if absent. The file holds group rendezvous keys and carries the same `0o600`
    /// protection as the roster.
    pub fn load_group_book(&self) -> Result<GroupBook, RuntimeError> {
        let _lock = self.lock_groups_file(false)?;
        self.load_group_book_unlocked()
    }

    /// Atomically persists `book` under an exclusive advisory lock with `0o600` file mode on Unix.
    pub fn save_group_book(&self, book: &GroupBook) -> Result<(), RuntimeError> {
        let _lock = self.lock_groups_file(true)?;
        self.save_group_book_unlocked(book)
    }

    /// Executes `f` transactionally against the latest on-disk [`GroupBook`] under an exclusive
    /// advisory lock, persisting atomically only when `f` returns `Ok`.
    pub fn update_group_book<T, F>(&self, f: F) -> Result<T, RuntimeError>
    where
        F: FnOnce(&mut GroupBook) -> Result<T, RuntimeError>,
    {
        let _lock = self.lock_groups_file(true)?;
        let mut book = self.load_group_book_unlocked()?;
        let out = f(&mut book)?;
        self.save_group_book_unlocked(&book)?;
        Ok(out)
    }

    fn lock_groups_file(&self, exclusive: bool) -> Result<File, RuntimeError> {
        let file = open_lock_0600(&self.groups_lock_path())?;
        flock(&file, exclusive)?;
        Ok(file)
    }

    fn load_group_book_unlocked(&self) -> Result<GroupBook, RuntimeError> {
        let path = self.groups_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_private_file_0600(&path)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(GroupBook::new());
            }
            Err(err) => return Err(RuntimeError::Io(err)),
        }
        match &self.codec {
            Codec::Plain => {
                let raw = Zeroizing::new(fs::read_to_string(&path)?);
                serde_json::from_str(&raw)
                    .map_err(|err| RuntimeError::Storage(format!("invalid groups json: {err}")))
            }
            Codec::Sealed(key) => sealed::load(key, StateKind::Groups, &path),
        }
    }

    fn save_group_book_unlocked(&self, book: &GroupBook) -> Result<(), RuntimeError> {
        let bytes = match &self.codec {
            Codec::Plain => {
                let mut json = Zeroizing::new(Vec::new());
                serde_json::to_writer_pretty(&mut *json, book).map_err(|err| {
                    RuntimeError::Storage(format!("serialize groups failed: {err}"))
                })?;
                json
            }
            Codec::Sealed(key) => Zeroizing::new(sealed::seal(key, StateKind::Groups, book)?),
        };
        self.atomic_write_0600(&self.groups_path(), &bytes)
    }

    fn lock_roster_file(&self, exclusive: bool) -> Result<File, RuntimeError> {
        let file = open_lock_0600(&self.roster_lock_path())?;
        flock(&file, exclusive)?;
        Ok(file)
    }

    /// Runs `f` under the exclusive roster file lock, the first lock of the global order
    /// (`crate::announce` module docs); `f` reads and writes through the `*_unlocked` helpers.
    pub(crate) fn with_roster_lock<T>(
        &self,
        f: impl FnOnce(&Self) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let _lock = self.lock_roster_file(true)?;
        f(self)
    }

    pub(crate) fn load_roster_unlocked(&self) -> Result<Roster, RuntimeError> {
        let path = self.roster_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_private_file_0600(&path)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Roster::new()),
            Err(err) => return Err(RuntimeError::Io(err)),
        }
        match &self.codec {
            Codec::Plain => {
                let raw = Zeroizing::new(fs::read_to_string(&path)?);
                serde_json::from_str(&raw).map_err(|err| {
                    RuntimeError::Storage(format!(
                        "invalid roster json: {}",
                        redact_json_error(&err)
                    ))
                })
            }
            Codec::Sealed(key) => sealed::load(key, StateKind::Roster, &path),
        }
    }

    pub(crate) fn save_roster_unlocked(&self, roster: &Roster) -> Result<(), RuntimeError> {
        let bytes = match &self.codec {
            Codec::Plain => {
                let mut json = Zeroizing::new(Vec::new());
                serde_json::to_writer_pretty(&mut *json, roster).map_err(|err| {
                    RuntimeError::Storage(format!("serialize roster failed: {err}"))
                })?;
                json
            }
            Codec::Sealed(key) => Zeroizing::new(sealed::seal(key, StateKind::Roster, roster)?),
        };
        self.atomic_write_0600(&self.roster_path(), &bytes)
    }

    /// Writes `bytes` to a `0o600` temp file, syncs it, renames it over `target`, then syncs the
    /// directory. Success means the new bytes are durable; an error after the rename means they
    /// are visible but not acknowledged.
    fn atomic_write_0600(&self, target: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
        static NEXT_TMP_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT_TMP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_name = format!(
            ".{}.tmp.{}.{}",
            target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("state"),
            std::process::id(),
            seq,
        );
        let tmp_path = self.dir.join(tmp_name);
        let staged = (|| -> Result<(), RuntimeError> {
            let mut file = open_temp_0600(&tmp_path)?;
            file.write_all(bytes)?;
            fault::inject(fault::Step::WriteTemp)?;
            file.sync_all()?;
            drop(file);
            fault::inject(fault::Step::Rename)?;
            fs::rename(&tmp_path, target)?;
            Ok(())
        })();
        if staged.is_err() {
            let _ = fs::remove_file(&tmp_path);
            return staged;
        }
        sync_dir(&self.dir)
            .map_err(|err| RuntimeError::Storage(format!("state commit not durable: {err}")))
    }
}

/// Creates `dir` (`0o700`) if needed, then syncs `dir` and every ancestor of its canonical path
/// up to the filesystem root, on every open. Existence is not proof of durability: an earlier
/// open may have created the tree and died before syncing it. The walk stops without error at
/// the first ancestor the process may not open for reading (`EACCES`/`EPERM`, as in app
/// sandboxes); the platform guarantees the durability of directories above that point. Any other
/// error is a hard failure.
fn create_durable_dir(dir: &Path) -> Result<(), RuntimeError> {
    crate::providers::create_private_dir_0700(dir)?;
    let not_durable =
        |err: std::io::Error| RuntimeError::Storage(format!("state directory not durable: {err}"));
    sync_dir(dir).map_err(not_durable)?;
    let canonical = fs::canonicalize(dir).map_err(not_durable)?;
    for ancestor in canonical.ancestors().skip(1) {
        match sync_dir(ancestor) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => break,
            Err(err) => return Err(not_durable(err)),
        }
    }
    Ok(())
}

/// Syncs directory `dir`. Opening it for reading is the only step that may fail with
/// [`std::io::ErrorKind::PermissionDenied`]; `create_durable_dir` relies on that.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fault::inject(fault::Step::SyncDir)?;
    File::open(dir)?.sync_all()?;
    #[cfg(test)]
    fault::SYNCED_DIRS.with(|dirs| dirs.borrow_mut().push(dir.to_path_buf()));
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    fault::inject(fault::Step::SyncDir)
}

/// Per-thread storage fault injection for the commit steps of `atomic_write_0600`.
mod fault {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Step {
        WriteTemp,
        Rename,
        SyncDir,
    }

    #[cfg(test)]
    thread_local! {
        pub(super) static FAIL_AT: std::cell::Cell<Option<Step>> = const { std::cell::Cell::new(None) };
        pub(super) static DIR_SYNCS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        pub(super) static SYNCED_DIRS: std::cell::RefCell<Vec<std::path::PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    #[cfg(test)]
    pub(super) fn inject(step: Step) -> std::io::Result<()> {
        if step == Step::SyncDir {
            DIR_SYNCS.with(|n| n.set(n.get() + 1));
        }
        if FAIL_AT.with(std::cell::Cell::get) == Some(step) {
            return Err(std::io::Error::other(format!("injected fault at {step:?}")));
        }
        Ok(())
    }

    #[cfg(not(test))]
    #[inline]
    pub(super) const fn inject(_step: Step) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
fn verify_private_file_0600(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(RuntimeError::Storage(format!(
            "state file '{}' must be a regular file, not a symlink",
            path.display()
        )));
    }
    let mode = meta.permissions().mode() & 0o777;
    if (mode & 0o077) != 0 {
        return Err(RuntimeError::Storage(format!(
            "state file '{}' has insecure mode {mode:#o}; expected group/other zeroed",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_file_0600(_path: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

/// Takes an advisory `flock` on `file`, released when the file is closed.
#[cfg(not(target_os = "android"))]
fn flock(file: &File, exclusive: bool) -> std::io::Result<()> {
    if exclusive {
        file.lock()
    } else {
        file.lock_shared()
    }
}

/// Takes an advisory `flock` on `file`, released when the file is closed. std `File::lock` is
/// unsupported on Android.
#[cfg(target_os = "android")]
fn flock(file: &File, exclusive: bool) -> std::io::Result<()> {
    use rustix::fs::FlockOperation;
    let op = if exclusive {
        FlockOperation::LockExclusive
    } else {
        FlockOperation::LockShared
    };
    rustix::fs::flock(file, op).map_err(std::io::Error::from)
}

fn open_lock_0600(path: &Path) -> Result<File, RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(RuntimeError::Storage(format!(
                    "lock file '{}' must be a regular file, not a symlink",
                    path.display()
                )));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(RuntimeError::Io(err)),
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}

#[cfg(unix)]
fn open_temp_0600(path: &Path) -> Result<File, RuntimeError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_temp_0600(path: &Path) -> Result<File, RuntimeError> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    Ok(file)
}
