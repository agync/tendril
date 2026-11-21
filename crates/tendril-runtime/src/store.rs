//! Atomic, permission-restricted local persistence for endpoint identities and rosters.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_decode_array, b64url_encode};
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::roster::Roster;
use zeroize::{Zeroize, Zeroizing};

use crate::error::RuntimeError;

const IDENTITY_FILE: &str = "identity.json";
const IDENTITY_LOCK_FILE: &str = ".identity.lock";
const ROSTER_FILE: &str = "roster.json";
const ROSTER_LOCK_FILE: &str = ".roster.lock";

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
    let disk: PersistedIdentity = serde_json::from_str(raw)
        .map_err(|err| RuntimeError::Storage(format!("invalid identity json: {err}")))?;
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

/// Persistent identity and roster store rooted at a caller-supplied directory.
#[derive(Debug, Clone)]
pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    /// Opens or creates `dir` with `0o700` permissions on Unix.
    pub fn open_or_create(dir: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let dir = dir.as_ref().to_path_buf();
        crate::providers::create_private_dir_0700(&dir)?;
        Ok(Self { dir })
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

    /// Returns the path to `roster.json`.
    #[must_use]
    pub fn roster_path(&self) -> PathBuf {
        self.dir.join(ROSTER_FILE)
    }

    /// Returns the path to the advisory lock file guarding `roster.json`.
    #[must_use]
    pub fn roster_lock_path(&self) -> PathBuf {
        self.dir.join(ROSTER_LOCK_FILE)
    }

    /// Loads [`EndpointIdentity`] from `identity.json`.
    pub fn load_identity(&self) -> Result<EndpointIdentity, RuntimeError> {
        let path = self.identity_path();
        verify_private_file_0600(&path)?;
        let raw = Zeroizing::new(fs::read_to_string(&path)?);
        deserialize_identity_json(&raw)
    }

    /// Atomically persists [`EndpointIdentity`] with `0o600` file mode on Unix.
    pub fn save_identity(&self, identity: &EndpointIdentity) -> Result<(), RuntimeError> {
        let json = serialize_identity_json(identity)?;
        self.atomic_write_0600(&self.identity_path(), json.as_bytes())
    }

    /// Loads the existing identity or generates, optionally assigns `host_id`, and saves one
    /// under an exclusive `.identity.lock` advisory lock.
    pub fn load_or_generate_identity(
        &self,
        host_id: Option<&str>,
    ) -> Result<EndpointIdentity, RuntimeError> {
        let lock = open_lock_0600(&self.dir.join(IDENTITY_LOCK_FILE))?;
        lock.lock()?;
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

    fn lock_roster_file(&self, exclusive: bool) -> Result<File, RuntimeError> {
        let file = open_lock_0600(&self.roster_lock_path())?;
        if exclusive {
            file.lock()?;
        } else {
            file.lock_shared()?;
        }
        Ok(file)
    }

    fn load_roster_unlocked(&self) -> Result<Roster, RuntimeError> {
        let path = self.roster_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_private_file_0600(&path)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Roster::new()),
            Err(err) => return Err(RuntimeError::Io(err)),
        }
        let raw = Zeroizing::new(fs::read_to_string(&path)?);
        serde_json::from_str(&raw)
            .map_err(|err| RuntimeError::Storage(format!("invalid roster json: {err}")))
    }

    fn save_roster_unlocked(&self, roster: &Roster) -> Result<(), RuntimeError> {
        let mut json = Zeroizing::new(Vec::new());
        serde_json::to_writer_pretty(&mut *json, roster)
            .map_err(|err| RuntimeError::Storage(format!("serialize roster failed: {err}")))?;
        self.atomic_write_0600(&self.roster_path(), &json)
    }

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
        let write_res = (|| -> Result<(), RuntimeError> {
            let mut file = open_temp_0600(&tmp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp_path, target)?;
            Ok(())
        })();
        if write_res.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        write_res
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
