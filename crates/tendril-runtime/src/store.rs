//! Atomic, permission-restricted local persistence for endpoint identities and rosters.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tendril_core::crypto::{SigningKeypair, StaticKeypair, b64url_decode_array, b64url_encode};
use tendril_core::identity::{EndpointIdentity, RotationRecord};
use tendril_core::roster::Roster;
use zeroize::{Zeroize, Zeroizing};

use crate::error::RuntimeError;

const IDENTITY_FILE: &str = "identity.json";
const ROSTER_FILE: &str = "roster.json";

#[derive(Serialize, Deserialize)]
struct PersistedIdentity {
    version: u32,
    host_id: String,
    static_secret_b64: String,
    signing_seed_b64: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rotation_chain: Vec<RotationRecord>,
    #[serde(default)]
    rotation_seq: u64,
}

impl Drop for PersistedIdentity {
    fn drop(&mut self) {
        self.static_secret_b64.zeroize();
        self.signing_seed_b64.zeroize();
    }
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
        fs::create_dir_all(&dir)?;
        set_dir_mode_0700(&dir)?;
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

    /// Loads [`EndpointIdentity`] from `identity.json`.
    pub fn load_identity(&self) -> Result<EndpointIdentity, RuntimeError> {
        let raw = Zeroizing::new(fs::read_to_string(self.identity_path())?);
        let disk: PersistedIdentity = serde_json::from_str(&raw)
            .map_err(|err| RuntimeError::Storage(format!("invalid identity json: {err}")))?;
        if disk.version != 1 {
            return Err(RuntimeError::Storage(format!(
                "unsupported identity version {}",
                disk.version
            )));
        }
        let static_scalar = Zeroizing::new(b64url_decode_array::<32>(&disk.static_secret_b64)?);
        let signing_seed = Zeroizing::new(b64url_decode_array::<32>(&disk.signing_seed_b64)?);
        let static_key = StaticKeypair::from_scalar(*static_scalar);
        let signing_key = SigningKeypair::from_seed(*signing_seed);
        let identity = EndpointIdentity::from_persisted(
            disk.host_id.clone(),
            static_key,
            signing_key,
            disk.rotation_chain.clone(),
            disk.rotation_seq,
        )?;
        Ok(identity)
    }

    /// Atomically persists [`EndpointIdentity`] with `0o600` file mode on Unix.
    pub fn save_identity(&self, identity: &EndpointIdentity) -> Result<(), RuntimeError> {
        let static_b64 = Zeroizing::new(b64url_encode(identity.static_key().secret_bytes()));
        let signing_b64 = Zeroizing::new(b64url_encode(identity.signing_key().seed_bytes()));
        let payload = PersistedIdentity {
            version: 1,
            host_id: identity.host_id().to_owned(),
            static_secret_b64: static_b64.to_string(),
            signing_seed_b64: signing_b64.to_string(),
            rotation_chain: identity.rotation_chain().to_vec(),
            rotation_seq: identity.rotation_seq(),
        };
        let json =
            Zeroizing::new(serde_json::to_vec_pretty(&payload).map_err(|err| {
                RuntimeError::Storage(format!("serialize identity failed: {err}"))
            })?);
        self.atomic_write_0600(&self.identity_path(), &json)
    }

    /// Loads the existing identity or generates, optionally assigns `host_id`, and saves one.
    pub fn load_or_generate_identity(
        &self,
        host_id: Option<&str>,
    ) -> Result<EndpointIdentity, RuntimeError> {
        let path = self.identity_path();
        if path.exists() {
            return self.load_identity();
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

    /// Loads [`Roster`] from `roster.json`, or returns a fresh default-deny [`Roster`] if absent.
    pub fn load_roster(&self) -> Result<Roster, RuntimeError> {
        let path = self.roster_path();
        if !path.exists() {
            return Ok(Roster::new());
        }
        let raw = fs::read_to_string(&path)?;
        serde_json::from_str(&raw)
            .map_err(|err| RuntimeError::Storage(format!("invalid roster json: {err}")))
    }

    /// Atomically persists [`Roster`] with `0o600` file mode on Unix.
    pub fn save_roster(&self, roster: &Roster) -> Result<(), RuntimeError> {
        let json = serde_json::to_vec_pretty(roster)
            .map_err(|err| RuntimeError::Storage(format!("serialize roster failed: {err}")))?;
        self.atomic_write_0600(&self.roster_path(), &json)
    }

    fn atomic_write_0600(&self, target: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
        let tmp_name = format!(
            ".{}.tmp.{}",
            target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("state"),
            std::process::id()
        );
        let tmp_path = self.dir.join(tmp_name);
        let mut file = open_temp_0600(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, target)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_dir_mode_0700(dir: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_dir: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

#[cfg(unix)]
fn open_temp_0600(path: &Path) -> Result<File, RuntimeError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_temp_0600(path: &Path) -> Result<File, RuntimeError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    Ok(file)
}
