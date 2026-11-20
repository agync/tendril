//! Peer roster state machine, pin verification, minting, rotation, and CRL tracking.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    b64url_encode, device_id, is_valid_ed25519_public_key, is_valid_x25519_public_key,
};
use crate::error::CoreError;
use crate::grants::{
    Capability, Grant, GrantUnsigned, RevocationList, sign_grant, verify_crl_signature,
};
use crate::identity::{
    EndpointIdentity, RotationRecord, format_rfc3339_utc, verify_rotation_chain,
};

/// Lifecycle state of a peer entry on a Tendril endpoint roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Pending,
    Active,
    Revoked,
}

/// Persistent trust state for one paired peer or pinned host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    pub device_id: String,
    pub name: String,
    pub kind: String,
    pub static_pub: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_pub: Option<[u8; 32]>,
    pub rotation_seq: u64,
    pub state: PeerState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pairing_sas: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_hints: Vec<String>,
}

impl RosterEntry {
    /// Confirms this entry pins a valid full-order X25519 static public key.
    pub fn require_static_pin(&self) -> Result<[u8; 32], CoreError> {
        if !is_valid_x25519_public_key(&self.static_pub) {
            return Err(CoreError::IncompletePin(self.device_id.clone()));
        }
        Ok(self.static_pub)
    }

    /// Confirms both X25519 `static_pub` and Ed25519 `signing_pub` pins are present and valid.
    pub fn require_complete_pin(&self) -> Result<([u8; 32], [u8; 32]), CoreError> {
        let static_pub = self.require_static_pin()?;
        let Some(signing_pub) = self.signing_pub.filter(is_valid_ed25519_public_key) else {
            return Err(CoreError::IncompletePin(self.device_id.clone()));
        };
        Ok((static_pub, signing_pub))
    }
}

/// Authoritative in-memory peer roster and verified CRL store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Roster {
    entries: BTreeMap<String, RosterEntry>,
    crls: BTreeMap<String, RevocationList>,
}

impl Roster {
    /// Creates an empty default-deny roster.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up an entry by roster key (`host_id` or `device_id`).
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&RosterEntry> {
        self.entries.get(id)
    }

    /// Iterates over all entries ordered by key.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &RosterEntry)> {
        self.entries.iter()
    }

    /// Returns the highest verified [`RevocationList`] persisted for `issuer`.
    #[must_use]
    pub fn crl(&self, issuer: &str) -> Option<&RevocationList> {
        self.crls.get(issuer)
    }

    /// Inserts or updates a verified client-side `Active` pin for a remote host before session connect.
    ///
    /// Refuses to overwrite a `Revoked` entry or any existing entry whose `static_pub`,
    /// `signing_pub`, or `rotation_seq` conflicts with the supplied pin, and never retains grants
    /// across differing keys.
    pub fn insert_pinned_host(
        &mut self,
        host_id: String,
        name: String,
        static_pub: [u8; 32],
        signing_pub: Option<[u8; 32]>,
        rotation_seq: u64,
        relay_hints: Vec<String>,
    ) -> Result<&RosterEntry, CoreError> {
        if host_id.is_empty() || !is_valid_x25519_public_key(&static_pub) {
            return Err(CoreError::IncompletePin(host_id));
        }
        if matches!(signing_pub, Some(sig) if !is_valid_ed25519_public_key(&sig)) {
            return Err(CoreError::IncompletePin(host_id));
        }
        if let Some(existing) = self.entries.get_mut(&host_id) {
            if existing.state == PeerState::Revoked {
                return Err(CoreError::PeerRevoked(host_id));
            }
            let signing_conflict = match (existing.signing_pub, signing_pub) {
                (Some(prev), Some(next)) => prev != next,
                (Some(_), None) => true,
                _ => false,
            };
            if existing.static_pub != static_pub
                || signing_conflict
                || rotation_seq < existing.rotation_seq
            {
                return Err(CoreError::ProtocolViolation(
                    "cannot overwrite pinned host keys; rotate or revoke existing pin first",
                ));
            }
            existing.name = name;
            if existing.signing_pub.is_none() {
                existing.signing_pub = signing_pub;
            }
            existing.rotation_seq = existing.rotation_seq.max(rotation_seq);
            existing.state = PeerState::Active;
            if !relay_hints.is_empty() {
                existing.relay_hints = relay_hints;
            }
            return Ok(&self.entries[&host_id]);
        }

        let entry = RosterEntry {
            device_id: host_id.clone(),
            name,
            kind: "host".to_string(),
            static_pub,
            signing_pub,
            rotation_seq,
            state: PeerState::Active,
            last_pairing_sas: None,
            grants: Vec::new(),
            relay_hints,
        };
        self.entries.insert(host_id.clone(), entry);
        Ok(&self.entries[&host_id])
    }

    /// Records an unpinned host from manual pairing in `Pending` state awaiting SAS confirmation.
    ///
    /// Rejects `Revoked` entries and refuses to overwrite any existing entry carrying distinct keys.
    /// Never auto-promotes `Pending` to `Active`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_pending_host(
        &mut self,
        host_id: String,
        name: String,
        static_pub: [u8; 32],
        signing_pub: [u8; 32],
        rotation_seq: u64,
        pairing_sas: String,
        relay_hints: Vec<String>,
    ) -> Result<&RosterEntry, CoreError> {
        if host_id.is_empty()
            || !is_valid_x25519_public_key(&static_pub)
            || !is_valid_ed25519_public_key(&signing_pub)
        {
            return Err(CoreError::IncompletePin(host_id));
        }
        if let Some(existing) = self.entries.get_mut(&host_id) {
            if existing.state == PeerState::Revoked {
                return Err(CoreError::PeerRevoked(host_id));
            }
            let signing_conflict =
                matches!(existing.signing_pub, Some(prev) if prev != signing_pub);
            if existing.static_pub != static_pub
                || signing_conflict
                || rotation_seq < existing.rotation_seq
            {
                return Err(CoreError::ProtocolViolation(
                    "host_id collision with distinct pinned keys",
                ));
            }
            existing.name = name;
            existing.signing_pub = Some(signing_pub);
            existing.rotation_seq = existing.rotation_seq.max(rotation_seq);
            existing.last_pairing_sas = Some(pairing_sas);
            if !relay_hints.is_empty() {
                existing.relay_hints = relay_hints;
            }
            return Ok(&self.entries[&host_id]);
        }

        let entry = RosterEntry {
            device_id: host_id.clone(),
            name,
            kind: "host".to_string(),
            static_pub,
            signing_pub: Some(signing_pub),
            rotation_seq,
            state: PeerState::Pending,
            last_pairing_sas: Some(pairing_sas),
            grants: Vec::new(),
            relay_hints,
        };
        self.entries.insert(host_id.clone(), entry);
        Ok(&self.entries[&host_id])
    }

    /// Removes a `Pending` (unconfirmed) peer or host entry, refusing to drop `Active` or `Revoked` entries.
    pub fn remove_pending_peer(&mut self, peer_id: &str) -> Result<(), CoreError> {
        let state = self
            .entries
            .get(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?
            .state;
        match state {
            PeerState::Pending => {
                self.entries.remove(peer_id);
                Ok(())
            }
            PeerState::Revoked => Err(CoreError::PeerRevoked(peer_id.to_string())),
            PeerState::Active => Err(CoreError::ProtocolViolation(
                "cannot remove active peer; revoke instead",
            )),
        }
    }

    /// Records a newly paired device in `Pending` state after verifying `code_mac`.
    ///
    /// Never promotes a `Pending` peer to `Active` and never un-revokes a `Revoked` peer.
    pub fn record_pending_pair(
        &mut self,
        static_pub: [u8; 32],
        signing_pub: Option<[u8; 32]>,
        name: String,
        kind: String,
        pairing_sas: String,
    ) -> Result<&RosterEntry, CoreError> {
        if !is_valid_x25519_public_key(&static_pub) {
            return Err(CoreError::IncompletePin(
                "invalid or low-order static_pub".to_string(),
            ));
        }
        if matches!(signing_pub, Some(sig) if !is_valid_ed25519_public_key(&sig)) {
            return Err(CoreError::IncompletePin("invalid signing_pub".to_string()));
        }
        let id = device_id(&static_pub);
        if let Some(existing) = self.entries.get_mut(&id) {
            if existing.static_pub != static_pub {
                return Err(CoreError::ProtocolViolation(
                    "device_id collision with distinct static key",
                ));
            }
            if existing.state == PeerState::Revoked {
                return Err(CoreError::PeerRevoked(id));
            }
            existing.name = name;
            existing.kind = kind;
            existing.last_pairing_sas = Some(pairing_sas);
            if let Some(sig) = signing_pub {
                existing.signing_pub = Some(sig);
            }
            return Ok(&self.entries[&id]);
        }

        let entry = RosterEntry {
            device_id: id.clone(),
            name,
            kind,
            static_pub,
            signing_pub,
            rotation_seq: 0,
            state: PeerState::Pending,
            last_pairing_sas: Some(pairing_sas),
            grants: Vec::new(),
            relay_hints: Vec::new(),
        };
        self.entries.insert(id.clone(), entry);
        Ok(&self.entries[&id])
    }

    /// Confirms a `Pending` peer (`pair.confirm`), optionally enforcing SAS match, and moves it
    /// to `Active` with zero non-session capabilities (default deny).
    pub fn confirm_peer(
        &mut self,
        peer_id: &str,
        expected_sas: Option<&str>,
    ) -> Result<&RosterEntry, CoreError> {
        let entry = self
            .entries
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.state == PeerState::Revoked {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        entry.require_static_pin()?;
        if let Some(sas) = expected_sas
            && entry.last_pairing_sas.as_deref() != Some(sas)
        {
            return Err(CoreError::ProtocolViolation("pairing SAS mismatch"));
        }
        entry.state = PeerState::Active;
        Ok(&self.entries[peer_id])
    }

    /// Mints a signed [`Grant`] (`pair.mint`) for an already `Active` peer on this roster.
    pub fn mint_grant(
        &mut self,
        issuer: &EndpointIdentity,
        subject_device_id: &str,
        caps: Vec<String>,
        not_before_unix: u64,
        not_after_unix: u64,
        nonce: [u8; 16],
    ) -> Result<Grant, CoreError> {
        let entry = self
            .entries
            .get_mut(subject_device_id)
            .ok_or_else(|| CoreError::PeerNotFound(subject_device_id.to_string()))?;
        match entry.state {
            PeerState::Pending => {
                return Err(CoreError::PeerPending(subject_device_id.to_string()));
            }
            PeerState::Revoked => {
                return Err(CoreError::PeerRevoked(subject_device_id.to_string()));
            }
            PeerState::Active => {}
        }
        entry.require_static_pin()?;

        if not_before_unix >= not_after_unix {
            return Err(CoreError::InvalidTimestamp(
                "not_before must be strictly earlier than not_after".to_string(),
            ));
        }
        for cap in &caps {
            Capability::parse(cap)?;
        }

        let signing_key = issuer.signing_key().signing_key();
        let grant = sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: issuer.host_id().to_string(),
                subject: subject_device_id.to_string(),
                caps,
                not_before: format_rfc3339_utc(not_before_unix)?,
                not_after: format_rfc3339_utc(not_after_unix)?,
                nonce: b64url_encode(&nonce),
                delegated_from: Vec::new(),
                uses: None,
                machine: None,
            },
            &signing_key,
        )?;
        entry.grants.push(grant.clone());
        Ok(grant)
    }

    /// Updates cached `relay_hints` for an existing non-revoked peer without modifying cryptographic pins or grants.
    pub fn update_relay_hints(
        &mut self,
        peer_id: &str,
        relay_hints: Vec<String>,
    ) -> Result<&RosterEntry, CoreError> {
        let entry = self
            .entries
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
        if entry.state == PeerState::Revoked {
            return Err(CoreError::PeerRevoked(peer_id.to_string()));
        }
        entry.relay_hints = relay_hints;
        Ok(&self.entries[peer_id])
    }

    fn revoke_siblings_by_keys(
        &mut self,
        revoked_static: [u8; 32],
        revoked_signing: Option<[u8; 32]>,
    ) {
        let has_signing = revoked_signing.is_some_and(|k| k != [0u8; 32]);
        for other in self.entries.values_mut() {
            let shares_static = revoked_static != [0u8; 32] && other.static_pub == revoked_static;
            let shares_signing = has_signing
                && matches!((revoked_signing, other.signing_pub), (Some(a), Some(b)) if a == b);
            if shares_static || shares_signing {
                other.state = PeerState::Revoked;
                other.grants.clear();
            }
        }
    }

    /// Marks `peer_id` (and any sibling entry sharing its cryptographic keys) as `Revoked`
    /// and clears any stored grants.
    pub fn revoke_peer(&mut self, peer_id: &str) -> Result<(), CoreError> {
        let (revoked_static, revoked_signing) = {
            let entry = self
                .entries
                .get_mut(peer_id)
                .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
            entry.state = PeerState::Revoked;
            entry.grants.clear();
            (entry.static_pub, entry.signing_pub)
        };
        self.revoke_siblings_by_keys(revoked_static, revoked_signing);
        Ok(())
    }

    /// Verifies `HostHello.rotation` against `peer_id`'s pinned keys and advances pins on success.
    ///
    /// A confirmed trust-root rotation fork immediately transitions the entry to `Revoked` and
    /// clears its grants before returning [`CoreError::RotationForkDetected`].
    pub fn apply_verified_rotation(
        &mut self,
        peer_id: &str,
        chain: &[RotationRecord],
        presented_static: &[u8; 32],
        presented_signing: &[u8; 32],
    ) -> Result<u64, CoreError> {
        let (pinned_static, pinned_signing, pinned_seq) = {
            let entry = self
                .entries
                .get(peer_id)
                .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
            match entry.state {
                PeerState::Pending => return Err(CoreError::PeerPending(peer_id.to_string())),
                PeerState::Revoked => return Err(CoreError::PeerRevoked(peer_id.to_string())),
                PeerState::Active => {}
            }
            let (stat, sig) = entry.require_complete_pin()?;
            (stat, sig, entry.rotation_seq)
        };

        match verify_rotation_chain(
            &pinned_signing,
            &pinned_static,
            pinned_seq,
            chain,
            presented_static,
            presented_signing,
        ) {
            Ok(new_seq) => {
                if new_seq > pinned_seq {
                    let entry = self
                        .entries
                        .get_mut(peer_id)
                        .ok_or_else(|| CoreError::PeerNotFound(peer_id.to_string()))?;
                    entry.static_pub = *presented_static;
                    entry.signing_pub = Some(*presented_signing);
                    entry.rotation_seq = new_seq;
                }
                Ok(new_seq)
            }
            Err(err @ CoreError::RotationForkDetected { .. }) => {
                let keys = self.entries.get_mut(peer_id).map(|entry| {
                    entry.state = PeerState::Revoked;
                    entry.grants.clear();
                    (entry.static_pub, entry.signing_pub)
                });
                if let Some((revoked_static, revoked_signing)) = keys {
                    self.revoke_siblings_by_keys(revoked_static, revoked_signing);
                }
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    /// Validates a signed [`RevocationList`], enforces monotonic `seq`, updates revoked peers, and
    /// persists the latest CRL for `expected_issuer`.
    pub fn ingest_crl(
        &mut self,
        crl: RevocationList,
        expected_issuer: &str,
        issuer_signing_pub: &[u8; 32],
    ) -> Result<(), CoreError> {
        if crl.v != 1 {
            return Err(CoreError::CrlUnsupportedVersion(crl.v));
        }
        if crl.issuer != expected_issuer {
            return Err(CoreError::CrlIssuerMismatch {
                expected: expected_issuer.to_string(),
                got: crl.issuer,
            });
        }
        verify_crl_signature(&crl, issuer_signing_pub)?;

        if let Some(existing) = self.crls.get(expected_issuer) {
            if existing == &crl {
                return Ok(());
            }
            if crl.seq <= existing.seq {
                return Err(CoreError::CrlStaleSeq {
                    current: existing.seq,
                    got: crl.seq,
                });
            }
        }

        let mut revoked_keys = Vec::new();
        for revoked_id in &crl.revoked_devices {
            if let Some(entry) = self.entries.get_mut(revoked_id) {
                entry.state = PeerState::Revoked;
                entry.grants.clear();
                revoked_keys.push((entry.static_pub, entry.signing_pub));
            }
            for entry in self.entries.values_mut() {
                if &entry.device_id == revoked_id {
                    entry.state = PeerState::Revoked;
                    entry.grants.clear();
                    revoked_keys.push((entry.static_pub, entry.signing_pub));
                }
            }
        }
        for (revoked_static, revoked_signing) in revoked_keys {
            self.revoke_siblings_by_keys(revoked_static, revoked_signing);
        }

        self.crls.insert(expected_issuer.to_string(), crl);
        Ok(())
    }

    /// Finds an active peer matching `static_pub`, rejecting unknown, pending, or revoked peers.
    pub fn lookup_active_by_static(
        &self,
        static_pub: &[u8; 32],
    ) -> Result<&RosterEntry, CoreError> {
        if !is_valid_x25519_public_key(static_pub) {
            return Err(CoreError::IncompletePin(
                "invalid or low-order static_pub".to_string(),
            ));
        }
        let mut active: Option<&RosterEntry> = None;
        let mut pending: Option<&RosterEntry> = None;
        for entry in self
            .entries
            .values()
            .filter(|e| e.static_pub == *static_pub)
        {
            match entry.state {
                PeerState::Revoked => return Err(CoreError::PeerRevoked(entry.device_id.clone())),
                PeerState::Pending => pending = Some(entry),
                PeerState::Active => active = Some(entry),
            }
        }
        if let Some(entry) = active {
            entry.require_static_pin()?;
            return Ok(entry);
        }
        if let Some(entry) = pending {
            return Err(CoreError::PeerPending(entry.device_id.clone()));
        }
        Err(CoreError::PeerNotFound(device_id(static_pub)))
    }

    /// Returns the pinned Ed25519 signing public key of an `Active` peer for grant verification,
    /// enforcing revocation precedence across sibling entries and ingested CRLs.
    #[must_use]
    pub fn lookup_active_signing_key(&self, issuer_id: &str) -> Option<[u8; 32]> {
        if self.entries.iter().any(|(k, e)| {
            (k == issuer_id || e.device_id == issuer_id) && e.state == PeerState::Revoked
        }) {
            return None;
        }
        let entry = self
            .entries
            .get(issuer_id)
            .filter(|e| e.state == PeerState::Active)
            .or_else(|| {
                self.entries
                    .values()
                    .find(|e| e.device_id == issuer_id && e.state == PeerState::Active)
            })?;
        let sig_pub = entry.signing_pub.filter(is_valid_ed25519_public_key)?;
        let cand_derived_id = device_id(&entry.static_pub);

        let sibling_revoked = self.entries.values().any(|other| {
            other.state == PeerState::Revoked
                && (other.device_id == issuer_id
                    || other.device_id == entry.device_id
                    || other.device_id == cand_derived_id
                    || other.static_pub == entry.static_pub
                    || other.signing_pub == Some(sig_pub))
        });
        if sibling_revoked {
            return None;
        }

        let crl_revoked = self.crls.values().any(|crl| {
            crl.revoked_devices
                .iter()
                .any(|d| d == issuer_id || d == &entry.device_id || d == &cand_derived_id)
        });
        if crl_revoked {
            return None;
        }

        Some(sig_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_duplicate_static_pub_takes_precedence_and_blocks_session_lookup() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut roster = Roster::new();
        let pub_k = *StaticKeypair::from_scalar([0x33u8; 32]).public_bytes();
        let sig_k = *SigningKeypair::from_seed([0x44u8; 32]).public_bytes();
        roster
            .insert_pinned_host(
                "aa_revoked_host".to_string(),
                "Revoked".to_string(),
                pub_k,
                Some(sig_k),
                0,
                vec![],
            )
            .unwrap();
        roster.revoke_peer("aa_revoked_host").unwrap();

        roster
            .insert_pinned_host(
                "zz_active_host".to_string(),
                "Active".to_string(),
                pub_k,
                Some(sig_k),
                0,
                vec![],
            )
            .unwrap();

        assert!(matches!(
            roster.lookup_active_by_static(&pub_k),
            Err(CoreError::PeerRevoked(_))
        ));
    }

    #[test]
    fn update_relay_hints_preserves_pins_and_rejects_revoked_or_missing() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut roster = Roster::new();
        let pub_k = *StaticKeypair::from_scalar([0x55u8; 32]).public_bytes();
        let sig_k = *SigningKeypair::from_seed([0x66u8; 32]).public_bytes();
        roster
            .insert_pinned_host(
                "host-a".to_string(),
                "Host A".to_string(),
                pub_k,
                Some(sig_k),
                3,
                vec!["wss://relay1.example/v1/relay".to_string()],
            )
            .unwrap();

        let updated = roster
            .update_relay_hints("host-a", vec!["wss://relay2.example/v1/relay".to_string()])
            .unwrap();
        assert_eq!(updated.static_pub, pub_k);
        assert_eq!(updated.signing_pub, Some(sig_k));
        assert_eq!(updated.rotation_seq, 3);
        assert_eq!(
            updated.relay_hints,
            vec!["wss://relay2.example/v1/relay".to_string()]
        );

        assert!(matches!(
            roster.update_relay_hints("missing", vec![]),
            Err(CoreError::PeerNotFound(_))
        ));
        roster.revoke_peer("host-a").unwrap();
        assert!(matches!(
            roster.update_relay_hints("host-a", vec![]),
            Err(CoreError::PeerRevoked(_))
        ));
    }

    #[test]
    fn sec01_insert_and_pending_host_refuse_overwrite_and_gate_on_confirm() {
        use crate::crypto::{SigningKeypair, StaticKeypair};

        let mut roster = Roster::new();
        let k1 = *StaticKeypair::from_scalar([0x21; 32]).public_bytes();
        let s1 = *SigningKeypair::from_seed([0x22; 32]).public_bytes();
        let k2 = *StaticKeypair::from_scalar([0x23; 32]).public_bytes();
        let s2 = *SigningKeypair::from_seed([0x24; 32]).public_bytes();

        roster
            .insert_pinned_host("host-x".into(), "Host X".into(), k1, Some(s1), 0, vec![])
            .unwrap();
        assert!(matches!(
            roster.insert_pinned_host("host-x".into(), "Evil".into(), k2, Some(s2), 0, vec![]),
            Err(CoreError::ProtocolViolation(_))
        ));
        assert!(matches!(
            roster.record_pending_host(
                "host-x".into(),
                "Evil".into(),
                k2,
                s2,
                0,
                "evil sas1".into(),
                vec![],
            ),
            Err(CoreError::ProtocolViolation(_))
        ));
        assert_eq!(roster.get("host-x").unwrap().static_pub, k1);

        // Fresh unpinned manual host enters Pending and requires matching SAS confirm_peer.
        let pend = roster
            .record_pending_host(
                "host-y".into(),
                "Host Y".into(),
                k1,
                s1,
                0,
                "abcd 1234 efgh 5678".into(),
                vec![],
            )
            .unwrap();
        assert_eq!(pend.state, PeerState::Pending);
        assert!(matches!(
            roster.confirm_peer("host-y", Some("wrong sas")),
            Err(CoreError::ProtocolViolation(_))
        ));
        assert!(matches!(
            roster.remove_pending_peer("host-x"),
            Err(CoreError::ProtocolViolation(_))
        ));
        roster
            .confirm_peer("host-y", Some("abcd 1234 efgh 5678"))
            .unwrap();
        assert_eq!(roster.get("host-y").unwrap().state, PeerState::Active);

        // Unconfirmed pending host can be cleanly discarded via remove_pending_peer.
        roster
            .record_pending_host(
                "host-z".into(),
                "Host Z".into(),
                k2,
                s2,
                0,
                "bad sas".into(),
                vec![],
            )
            .unwrap();
        roster.remove_pending_peer("host-z").unwrap();
        assert!(roster.get("host-z").is_none());
    }

    #[test]
    fn rejects_weak_ed25519_keys_across_roster_pins() {
        use crate::crypto::StaticKeypair;

        let valid_static = *StaticKeypair::from_scalar([0x21; 32]).public_bytes();
        let zero_sig = [0u8; 32];
        let mut weak_sig = [0u8; 32];
        weak_sig[0] = 1;

        assert!(!is_valid_ed25519_public_key(&zero_sig));
        assert!(!is_valid_ed25519_public_key(&weak_sig));

        let mut roster = Roster::new();
        for bad_sig in [zero_sig, weak_sig] {
            assert!(matches!(
                roster.insert_pinned_host(
                    "host-bad".into(),
                    "Bad".into(),
                    valid_static,
                    Some(bad_sig),
                    0,
                    vec![],
                ),
                Err(CoreError::IncompletePin(_))
            ));
            assert!(matches!(
                roster.record_pending_host(
                    "host-bad".into(),
                    "Bad".into(),
                    valid_static,
                    bad_sig,
                    0,
                    "sas 1234".into(),
                    vec![],
                ),
                Err(CoreError::IncompletePin(_))
            ));
            assert!(matches!(
                roster.record_pending_pair(
                    valid_static,
                    Some(bad_sig),
                    "Bad".into(),
                    "cli".into(),
                    "sas 1234".into(),
                ),
                Err(CoreError::IncompletePin(_))
            ));
        }
    }

    #[test]
    fn crl_and_rotation_fork_propagate_revocation_to_sibling_entries() {
        use crate::crypto::StaticKeypair;
        use crate::grants::{RevocationListUnsigned, sign_crl};
        use crate::identity::sign_rotation;

        let root_sk = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let root_pub = root_sk.verifying_key().to_bytes();

        let alias_static = *StaticKeypair::from_scalar([0x22; 32]).public_bytes();
        let alias_sk = ed25519_dalek::SigningKey::from_bytes(&[0x23; 32]);
        let alias_sig = alias_sk.verifying_key().to_bytes();

        let mut roster = Roster::new();
        roster
            .insert_pinned_host(
                "alias-a".into(),
                "Alias A".into(),
                alias_static,
                Some(alias_sig),
                0,
                vec![],
            )
            .unwrap();
        roster
            .insert_pinned_host(
                "alias-b".into(),
                "Alias B".into(),
                alias_static,
                Some(alias_sig),
                0,
                vec![],
            )
            .unwrap();

        let crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: "root-id".into(),
                seq: 1,
                revoked_devices: vec!["alias-a".into()],
                revoked_nonces: vec![],
                ts: "2026-11-20T00:00:00Z".into(),
            },
            &root_sk,
        )
        .unwrap();
        roster.ingest_crl(crl, "root-id", &root_pub).unwrap();
        assert_eq!(roster.get("alias-a").unwrap().state, PeerState::Revoked);
        assert_eq!(roster.get("alias-b").unwrap().state, PeerState::Revoked);

        let fork_static = *StaticKeypair::from_scalar([0x31; 32]).public_bytes();
        let fork_sk = ed25519_dalek::SigningKey::from_bytes(&[0x32; 32]);
        let fork_pub = fork_sk.verifying_key().to_bytes();
        roster
            .insert_pinned_host(
                "fork-a".into(),
                "Fork A".into(),
                fork_static,
                Some(fork_pub),
                0,
                vec![],
            )
            .unwrap();
        roster
            .insert_pinned_host(
                "fork-b".into(),
                "Fork B".into(),
                fork_static,
                Some(fork_pub),
                0,
                vec![],
            )
            .unwrap();

        let next_stat_1 = *StaticKeypair::from_scalar([0x41; 32]).public_bytes();
        let next_sig_1 = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
            .verifying_key()
            .to_bytes();
        let next_stat_2 = *StaticKeypair::from_scalar([0x51; 32]).public_bytes();
        let next_sig_2 = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32])
            .verifying_key()
            .to_bytes();
        let rec1 = sign_rotation(1, &fork_sk, &next_sig_1, &next_stat_1, 1_795_133_000).unwrap();
        let rec2 = sign_rotation(1, &fork_sk, &next_sig_2, &next_stat_2, 1_795_133_001).unwrap();

        let fork_res =
            roster.apply_verified_rotation("fork-a", &[rec1, rec2], &next_stat_1, &next_sig_1);
        assert!(matches!(
            fork_res,
            Err(CoreError::RotationForkDetected { seq: 1 })
        ));
        assert_eq!(roster.get("fork-a").unwrap().state, PeerState::Revoked);
        assert_eq!(roster.get("fork-b").unwrap().state, PeerState::Revoked);
    }
}
