//! Browser group book: manifest ingestion, membership, and capability authorization.
//!
//! All group policy is evaluated by `tendril_core::group` over the persisted [`GroupBook`]. The
//! host JS layer only moves bytes: it hands over manifests and `0x0B` frames received on an
//! authenticated session and asks this module who may send or receive. Rendezvous keys and
//! group-scoped pairwise secrets stay inside this module; the only way they reach JS is the
//! vault-bound state export, which follows the same pattern as the roster export.
//!
//! Root-side `create`, `add_member`, and `remove_member` are not available in the browser.

use serde_json::{Value, json};
use tendril_core::crypto::HybridSigningPublicKey;
use tendril_core::error::CoreError;
use tendril_core::grants::{Capability, RevocationList};
use tendril_core::group::{
    GroupBook, GroupIngestOutcome, GroupIngestStatus, GroupManifest, GroupRendezvousFrame,
    check_first_contact, check_group_capacity, check_rendezvous_local_membership,
    drop_secrets_if_left, is_active_member, root_crl as resolve_root_crl, root_device_in,
};
pub use tendril_core::group::{MAX_GROUPS_PER_SIGNER, MAX_LOCAL_GROUPS, MAX_STORED_GROUPS};
use tendril_core::roster::Roster;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{WasmIdentity, WasmRoster, copy_zeroizing_bytes_to_js, f64_to_u64, to_js_err};

/// Maximum undelivered `0x0B` frames a session buffers before the oldest is dropped.
pub const MAX_PENDING_RENDEZVOUS: usize = 16;

fn invalid(msg: &str) -> String {
    CoreError::GroupUnauthorized(msg.to_owned()).to_string()
}

/// Resolves the effective revocation list of the founding root of `manifest` with
/// [`tendril_core::group::root_crl`], matching the runtime: every stored list signed by the
/// pinned root key applies, whatever label the roster stores it under, and a root that rotated
/// away from that key fails closed. The browser is never a group root, so no list it mints
/// itself can be root-signed and no local label is passed.
fn root_crl(
    roster: &Roster,
    manifest: &GroupManifest,
    root_pub: &HybridSigningPublicKey,
) -> Result<Option<RevocationList>, String> {
    let Some(root_id) = root_device_in(manifest, root_pub) else {
        return Ok(None);
    };
    resolve_root_crl(roster, &root_id, root_pub, None).map_err(|e| e.to_string())
}

fn crl_revokes(crl: Option<&RevocationList>, device_id: &str) -> bool {
    crl.is_some_and(|c| c.revoked_devices.iter().any(|d| d == device_id))
}

fn group_json(manifest: &GroupManifest) -> Value {
    let members: Vec<Value> = manifest
        .members
        .iter()
        .filter(|m| is_active_member(manifest, &m.device_id))
        .map(|m| {
            json!({
                "device_id": m.device_id,
                "name": m.name,
                "caps": m.caps,
                "endpoints": m.endpoints,
            })
        })
        .collect();
    json!({
        "group_id": manifest.group_id,
        "name": manifest.name,
        "seq": manifest.seq,
        "min_wire_version": manifest.min_wire_version,
        "expires_at": manifest.expires_at,
        "members": members,
        "revoked": manifest.revoked_members,
    })
}

fn outcome_json(outcome: &GroupIngestOutcome) -> Value {
    let status = match outcome.status {
        GroupIngestStatus::Created => "created",
        GroupIngestStatus::Updated => "updated",
        GroupIngestStatus::Unchanged => "unchanged",
    };
    json!({
        "group_id": outcome.group_id,
        "seq": outcome.seq,
        "status": status,
        "newly_revoked": outcome.newly_revoked,
        "newly_joined": outcome.newly_joined,
        "removed": outcome.removed,
    })
}

/// Persisted group state of one browser endpoint plus the local device id it acts as.
#[wasm_bindgen]
pub struct WasmGroupBook {
    local_device_id: String,
    pub(crate) inner: GroupBook,
}

impl WasmGroupBook {
    pub(crate) fn from_parts(local_device_id: String, inner: GroupBook) -> Self {
        Self {
            local_device_id,
            inner,
        }
    }

    /// Verifies and ingests a manifest pushed by the authenticated session peer.
    ///
    /// A known group follows the normal ingest rules. An unknown group is pinned only when the
    /// sender is the manifest signer, an active paired peer whose pinned signing key equals the
    /// manifest signing key, the local device is an active member, and fewer than
    /// [`MAX_GROUPS_PER_SIGNER`] stored records are attributed to that peer. Gossip never pins.
    pub(crate) fn ingest_manifest_inner(
        &mut self,
        roster: &Roster,
        sender_device_id: &str,
        manifest: &GroupManifest,
        now_unix: u64,
    ) -> Result<GroupIngestOutcome, String> {
        let known = self.inner.manifest(&manifest.group_id).is_some();
        let pinned_by = if known {
            None
        } else {
            Some(
                check_first_contact(roster, &self.local_device_id, sender_device_id, manifest)
                    .map_err(|e| e.to_string())?,
            )
        };
        check_group_capacity(&self.inner, &self.local_device_id, &manifest.group_id)
            .map_err(|e| e.to_string())?;
        let crl = match (
            self.inner.manifest(&manifest.group_id),
            self.inner.root_signing_pub(&manifest.group_id),
        ) {
            (Some(stored), Some(root_pub)) => root_crl(roster, stored, root_pub)?,
            _ => match HybridSigningPublicKey::from_b64url(&manifest.root_signing_pub) {
                Ok(root_pub) => root_crl(roster, manifest, &root_pub)?,
                Err(_) => None,
            },
        };
        let outcome = match &pinned_by {
            Some(handles) => {
                self.inner
                    .ingest_first_contact_manifest(manifest, now_unix, crl.as_ref(), handles)
            }
            None => self
                .inner
                .ingest_group_manifest(manifest, now_unix, crl.as_ref()),
        }
        .map_err(|e| e.to_string())?;
        drop_secrets_if_left(&mut self.inner, &self.local_device_id, &manifest.group_id);
        Ok(outcome)
    }

    pub(crate) fn authorize_inner(
        &self,
        roster: &Roster,
        group_id: &str,
        peer_device_id: &str,
        cap: &str,
        now_unix: u64,
    ) -> Result<(), String> {
        let cap = Capability::parse(cap).map_err(|e| e.to_string())?;
        self.authorize_cap(roster, group_id, peer_device_id, &cap, now_unix)
    }

    fn authorize_cap(
        &self,
        roster: &Roster,
        group_id: &str,
        peer_device_id: &str,
        cap: &Capability,
        now_unix: u64,
    ) -> Result<(), String> {
        let manifest = self
            .inner
            .manifest(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()).to_string())?;
        let root_pub = self
            .inner
            .root_signing_pub(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()).to_string())?;
        let crl = root_crl(roster, manifest, root_pub)?;
        self.inner
            .authorize_group(group_id, peer_device_id, cap, now_unix, crl.as_ref())
            .map_err(|e| e.to_string())
    }

    /// Fails unless the local device is an active member of `group_id` that the founding root's
    /// CRL does not revoke.
    fn local_active(&self, roster: &Roster, group_id: &str) -> Result<(), String> {
        let manifest = self
            .inner
            .manifest(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()).to_string())?;
        if !is_active_member(manifest, &self.local_device_id) {
            return Err(invalid("local device is not an active member"));
        }
        let crl = match self.inner.root_signing_pub(group_id) {
            Some(root_pub) => root_crl(roster, manifest, root_pub)?,
            None => None,
        };
        if crl_revokes(crl.as_ref(), &self.local_device_id) {
            return Err(CoreError::GroupMemberRevoked(self.local_device_id.clone()).to_string());
        }
        Ok(())
    }

    /// Fails unless the local device is an active, unrevoked member (manifest and root CRL).
    pub(crate) fn check_local_member_inner(
        &self,
        roster: &Roster,
        group_id: &str,
    ) -> Result<(), String> {
        self.local_active(roster, group_id)
    }

    /// Decides whether inbound `cap` data from `sender_device_id` may be surfaced.
    ///
    /// Mirrors the runtime: the local device must itself be an active, unrevoked member before
    /// the sender is authorized.
    pub(crate) fn authorize_inbound_inner(
        &self,
        roster: &Roster,
        group_id: &str,
        sender_device_id: &str,
        cap: &str,
        now_unix: u64,
    ) -> Result<(), String> {
        self.local_active(roster, group_id)?;
        self.authorize_inner(roster, group_id, sender_device_id, cap, now_unix)
    }

    pub(crate) fn members_inner(&self, group_id: &str) -> Result<Value, String> {
        self.inner
            .manifest(group_id)
            .map(group_json)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()).to_string())
    }

    /// Returns the active non-self members that hold `group.recv:<group_id>`, after checking
    /// that the local member holds `required_cap` (default `group.send:<group_id>`).
    pub(crate) fn broadcast_targets_inner(
        &self,
        roster: &Roster,
        group_id: &str,
        required_cap: Option<&str>,
        now_unix: u64,
    ) -> Result<Vec<String>, String> {
        let send_cap = match required_cap {
            Some(raw) if !raw.is_empty() => raw.to_owned(),
            _ => format!("group.send:{group_id}"),
        };
        let recv_cap =
            Capability::parse(&format!("group.recv:{group_id}")).map_err(|e| e.to_string())?;
        let (Some(manifest), Some(root_pub)) = (
            self.inner.manifest(group_id),
            self.inner.root_signing_pub(group_id),
        ) else {
            return Err(CoreError::GroupNotFound(group_id.to_owned()).to_string());
        };
        root_crl(roster, manifest, root_pub)?;
        if self.local_active(roster, group_id).is_err() {
            return Ok(Vec::new());
        }
        self.authorize_inner(roster, group_id, &self.local_device_id, &send_cap, now_unix)?;
        let manifest = self
            .inner
            .manifest(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()).to_string())?;
        Ok(manifest
            .members
            .iter()
            .filter(|m| m.device_id != self.local_device_id)
            .filter(|m| {
                self.authorize_cap(roster, group_id, &m.device_id, &recv_cap, now_unix)
                    .is_ok()
            })
            .map(|m| m.device_id.clone())
            .collect())
    }

    /// Applies buffered `0x0B` frames delivered by the authenticated session peer.
    ///
    /// The core accepts a key only from the founding root or a live co-admin and only for the
    /// stored manifest `seq`. The result never contains key material.
    pub(crate) fn apply_rendezvous_inner(
        &mut self,
        roster: &Roster,
        sender_device_id: Option<&str>,
        frames: &[GroupRendezvousFrame],
        now_unix: u64,
    ) -> Value {
        let mut applied = Vec::new();
        let mut rejected = Vec::new();
        for frame in frames {
            let outcome = match sender_device_id {
                None => Err("session has no authenticated peer".to_owned()),
                Some(sender) => self.apply_one_rendezvous(roster, sender, frame, now_unix),
            };
            match outcome {
                Ok(()) => applied.push(json!({"group_id": frame.group_id, "seq": frame.seq})),
                Err(error) => rejected.push(json!({
                    "group_id": frame.group_id,
                    "seq": frame.seq,
                    "error": error,
                })),
            }
        }
        json!({"applied": applied, "rejected": rejected})
    }

    fn apply_one_rendezvous(
        &mut self,
        roster: &Roster,
        sender: &str,
        frame: &GroupRendezvousFrame,
        now_unix: u64,
    ) -> Result<(), String> {
        check_rendezvous_local_membership(&self.inner, &self.local_device_id, &frame.group_id)
            .map_err(|e| e.to_string())?;
        let crl = match (
            self.inner.manifest(&frame.group_id),
            self.inner.root_signing_pub(&frame.group_id),
        ) {
            (Some(manifest), Some(root_pub)) => root_crl(roster, manifest, root_pub)?,
            _ => None,
        };
        self.inner
            .ingest_group_rendezvous_frame(sender, frame, now_unix, crl.as_ref())
            .map_err(|e| e.to_string())
    }

    pub(crate) fn ingest_event_inner(
        &mut self,
        roster: &Roster,
        sender_device_id: &str,
        event_json: &str,
        now_unix: u64,
    ) -> Result<GroupIngestOutcome, String> {
        let event: Value = serde_json::from_str(event_json).map_err(|e| e.to_string())?;
        if event.get("event").and_then(Value::as_str) != Some("group_manifest_unverified") {
            return Err(invalid("not a group_manifest_unverified event"));
        }
        let manifest_json = event
            .get("manifest_json")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("event carries no manifest_json"))?;
        let manifest =
            GroupManifest::from_wire_bytes(manifest_json.as_bytes()).map_err(|e| e.to_string())?;
        self.ingest_manifest_inner(roster, sender_device_id, &manifest, now_unix)
    }
}

#[wasm_bindgen]
impl WasmGroupBook {
    /// Creates an empty book for the local `identity`.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(identity: &WasmIdentity) -> Self {
        Self::from_parts(identity.inner.device_id(), GroupBook::new())
    }

    /// Restores a book from its vault export.
    #[wasm_bindgen]
    pub fn from_json(identity: &WasmIdentity, json: &str) -> Result<WasmGroupBook, JsValue> {
        let inner: GroupBook = serde_json::from_str(json).map_err(to_js_err)?;
        Ok(Self::from_parts(identity.inner.device_id(), inner))
    }

    /// Restores a book from vault bytes, zeroizing the input.
    #[wasm_bindgen]
    pub fn from_json_bytes(
        identity: &WasmIdentity,
        json_bytes: &mut [u8],
    ) -> Result<WasmGroupBook, JsValue> {
        let res = serde_json::from_slice::<GroupBook>(json_bytes).map_err(to_js_err);
        json_bytes.zeroize();
        Ok(Self::from_parts(identity.inner.device_id(), res?))
    }

    /// Vault-bound state export. Contains local rendezvous secrets; never log or transmit it.
    #[wasm_bindgen(unchecked_return_type = "string")]
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        let serialized = Zeroizing::new(serde_json::to_string(&self.inner).map_err(to_js_err)?);
        Ok(JsValue::from_str(&serialized))
    }

    /// Vault-bound state export as bytes. Contains local rendezvous secrets.
    #[wasm_bindgen(unchecked_return_type = "Uint8Array")]
    pub fn to_json_bytes(&self) -> Result<JsValue, JsValue> {
        let serialized = Zeroizing::new(serde_json::to_vec(&self.inner).map_err(to_js_err)?);
        copy_zeroizing_bytes_to_js(serialized)
    }

    /// Replaces the stored state from vault bytes, zeroizing the input.
    #[wasm_bindgen]
    pub fn replace_from_json_bytes(&mut self, json_bytes: &mut [u8]) -> Result<(), JsValue> {
        let res = serde_json::from_slice::<GroupBook>(json_bytes).map_err(to_js_err);
        json_bytes.zeroize();
        self.inner = res?;
        Ok(())
    }

    /// Lists stored group ids as a JSON array.
    #[wasm_bindgen]
    #[must_use]
    pub fn group_ids_json(&self) -> String {
        json!(self.inner.group_ids()).to_string()
    }

    /// Returns the device id this book acts as.
    #[wasm_bindgen]
    #[must_use]
    pub fn local_device_id(&self) -> String {
        self.local_device_id.clone()
    }

    /// Fails unless `group_id` is stored and the local device is an active member of it that the
    /// founding root's CRL does not revoke.
    #[wasm_bindgen]
    pub fn check_local_member(&self, roster: &WasmRoster, group_id: &str) -> Result<(), JsValue> {
        self.check_local_member_inner(&roster.inner, group_id)
            .map_err(to_js_err)
    }

    /// Fails unless the local device is an active unrevoked member and `sender_device_id` holds
    /// `cap`. Gate for surfacing inbound group data.
    #[wasm_bindgen]
    pub fn authorize_inbound(
        &self,
        roster: &WasmRoster,
        group_id: &str,
        sender_device_id: &str,
        cap: &str,
        now_unix: f64,
    ) -> Result<(), JsValue> {
        let now = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        self.authorize_inbound_inner(&roster.inner, group_id, sender_device_id, cap, now)
            .map_err(to_js_err)
    }

    /// Returns the stored manifest summary and active members of `group_id` as JSON.
    #[wasm_bindgen]
    pub fn members(&self, group_id: &str) -> Result<String, JsValue> {
        self.members_inner(group_id)
            .map(|v| v.to_string())
            .map_err(to_js_err)
    }

    /// Verifies and ingests `manifest_json` received from the authenticated peer
    /// `sender_device_id`, returning the ingest outcome as JSON.
    #[wasm_bindgen]
    pub fn ingest_manifest(
        &mut self,
        roster: &WasmRoster,
        sender_device_id: &str,
        manifest_json: &str,
        now_unix: f64,
    ) -> Result<String, JsValue> {
        let now = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        let manifest =
            GroupManifest::from_wire_bytes(manifest_json.as_bytes()).map_err(to_js_err)?;
        self.ingest_manifest_inner(&roster.inner, sender_device_id, &manifest, now)
            .map(|o| outcome_json(&o).to_string())
            .map_err(to_js_err)
    }

    /// Like [`Self::ingest_manifest`] for a `group_manifest_unverified` session event object.
    #[wasm_bindgen]
    pub fn ingest_manifest_event(
        &mut self,
        roster: &WasmRoster,
        sender_device_id: &str,
        event_json: &str,
        now_unix: f64,
    ) -> Result<String, JsValue> {
        let now = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        self.ingest_event_inner(&roster.inner, sender_device_id, event_json, now)
            .map(|o| outcome_json(&o).to_string())
            .map_err(to_js_err)
    }

    /// Fails unless `peer_device_id` is an active, unrevoked member holding `cap`.
    #[wasm_bindgen]
    pub fn authorize_peer(
        &self,
        roster: &WasmRoster,
        group_id: &str,
        peer_device_id: &str,
        cap: &str,
        now_unix: f64,
    ) -> Result<(), JsValue> {
        let now = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        self.authorize_inner(&roster.inner, group_id, peer_device_id, cap, now)
            .map_err(to_js_err)
    }

    /// Returns the device ids a broadcast under `required_cap` may be sent to, as JSON.
    #[wasm_bindgen]
    pub fn broadcast_targets(
        &self,
        roster: &WasmRoster,
        group_id: &str,
        required_cap: Option<String>,
        now_unix: f64,
    ) -> Result<String, JsValue> {
        let now = f64_to_u64(now_unix, "now_unix").map_err(to_js_err)?;
        self.broadcast_targets_inner(&roster.inner, group_id, required_cap.as_deref(), now)
            .map(|ids| json!(ids).to_string())
            .map_err(to_js_err)
    }
}

#[cfg(test)]
mod tests;
