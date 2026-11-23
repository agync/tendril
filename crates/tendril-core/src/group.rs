//! Small peer mesh groups: root-signed `GroupManifest`, ingestion rules, and rendezvous keys.
//!
//! This module is Sans-I/O. It never touches the network or storage; runtimes feed received
//! `0x0A GROUP_MANIFEST` and `0x0B GROUP_RENDEZVOUS` frames into a [`GroupBook`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    ED25519_PUBLIC_LEN, HYBRID_SIGNING_HASH_LEN, HybridSigningPublicKey, SigningKeypair,
    b64url_decode, b64url_decode_array, b64url_encode, device_id, hkdf_sha256_32,
    is_valid_ed25519_public_key, is_valid_x25519_public_key, random_bytes,
};
use crate::error::CoreError;
use crate::grants::{
    Capability, Grant, GrantUnsigned, MAX_CLOCK_SKEW_SECS, RevocationList, canonical_json,
    sign_grant, sign_grant_deterministic, verify_crl_signature, verify_grant_with_chain,
};
use crate::identity::{format_rfc3339_utc, parse_rfc3339_utc};
use crate::pairing::is_valid_pairing_endpoint_hint;
use crate::roster::{PeerState, Roster, RosterEntry, V2PeerSecrets};

/// Domain prefix prepended to JCS canonical manifest bytes before signing (`17` bytes).
pub const GROUP_MANIFEST_DOMAIN: &[u8] = b"tendril-group-v1\0";

/// Supported `GroupManifest.v` value.
pub const GROUP_MANIFEST_VERSION: u8 = 1;

/// Largest `seq` a manifest or `0x0B` frame may carry (`2^53 - 1`, exactly representable in JS).
pub const MAX_GROUP_SEQ: u64 = (1 << 53) - 1;

/// Largest `seq` increase accepted when ingesting a manifest for a known group.
pub const MAX_GROUP_SEQ_JUMP: u64 = 1024;

/// Maximum number of active members in one group.
pub const MAX_GROUP_MEMBERS: usize = 32;

/// Maximum number of co-admins the root may issue `group.admin` grants to (builder enforced).
pub const MAX_GROUP_CO_ADMINS: usize = 8;

/// Maximum endpoint hints per member.
pub const MAX_MEMBER_ENDPOINTS: usize = 8;

/// Maximum characters per endpoint hint.
pub const MAX_ENDPOINT_HINT_LEN: usize = 256;

/// Maximum capability strings per member.
pub const MAX_MEMBER_CAPS: usize = 16;

/// Maximum entries in `revoked_members`.
pub const MAX_REVOKED_MEMBERS: usize = 256;

/// Maximum compact JSON length of a serialized manifest in bytes.
pub const MAX_GROUP_MANIFEST_LEN: usize = 32_768;

/// Maximum span between `ts` and `expires_at` in seconds (`90` days).
pub const MAX_MANIFEST_VALIDITY_SECS: u64 = 90 * 86_400;

/// Default validity applied by the builder helpers in seconds (`30` days).
pub const DEFAULT_MANIFEST_VALIDITY_SECS: u64 = 30 * 86_400;

/// Maximum groups one endpoint is an active member or root of; further groups are refused.
pub const MAX_LOCAL_GROUPS: usize = 16;

/// Hard cap on stored group records, including groups the local device was removed from.
pub const MAX_STORED_GROUPS: usize = 64;

/// Maximum entries in `SessionHello.groups`.
pub const MAX_GOSSIP_GROUPS: usize = 16;

/// Exact payload length of a `0x0B GROUP_RENDEZVOUS` frame (`20 + 8 + 32`).
pub const GROUP_RENDEZVOUS_FRAME_LEN: usize = 60;

/// Maximum characters in a group or member name.
pub const MAX_GROUP_NAME_CHARS: usize = 64;

const GROUP_ID_LEN: usize = 20;
const DEVICE_ID_LEN: usize = 20;
const PAIR_BOOTSTRAP_INFO: &[u8] = b"tendril-group-v2-rendezvous\0";
const GROUP_MAILBOX_INFO: &[u8] = b"tendril-group-v2-mailbox";
const ADMIN_NAMESPACE: &str = "group";
const ADMIN_VERB: &str = "admin";

/// Derives `group_id = "grp_" || hex_lower(SHA-256(root_signing_pub)[0..8])`.
#[must_use]
pub fn group_id_from_root(root_signing_pub: &HybridSigningPublicKey) -> String {
    let sum = Sha256::digest(root_signing_pub.as_bytes());
    format!("grp_{}", hex::encode(&sum[..8]))
}

/// Reports whether `s` is a well-formed `grp_` identifier (`grp_` plus 16 lowercase hex chars).
#[must_use]
pub fn is_valid_group_id(s: &str) -> bool {
    s.len() == GROUP_ID_LEN
        && s.strip_prefix("grp_")
            .is_some_and(|rest| rest.bytes().all(is_lower_hex))
}

fn is_valid_device_id_format(s: &str) -> bool {
    s.len() == DEVICE_ID_LEN
        && s.strip_prefix("dev_")
            .is_some_and(|rest| rest.bytes().all(is_lower_hex))
}

const fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b >= b'a' && b <= b'f')
}

fn invalid(msg: impl Into<String>) -> CoreError {
    CoreError::InvalidGroupManifest(msg.into())
}

fn deserialize_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("null field must be omitted from canonical JSON"))
        .map(Some)
}

fn check_seq(seq: u64) -> Result<(), CoreError> {
    if (1..=MAX_GROUP_SEQ).contains(&seq) {
        Ok(())
    } else {
        Err(invalid("seq must be in 1..=2^53-1"))
    }
}

/// Returns the exact keyed admin capability string for a co-admin signing key.
fn admin_cap_for(group_id: &str, signer_pub: &HybridSigningPublicKey) -> String {
    format!(
        "{ADMIN_NAMESPACE}.{ADMIN_VERB}:{group_id}/{}",
        hex::encode(signer_pub.sha256_hash())
    )
}

/// One entry of the `SessionHello.groups` gossip summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSeq {
    pub group_id: String,
    pub seq: u64,
}

/// Validates a gossip summary: at most [`MAX_GOSSIP_GROUPS`], well-formed unique ids, `seq >= 1`.
pub fn validate_group_seqs(groups: &[GroupSeq]) -> Result<(), CoreError> {
    if groups.len() > MAX_GOSSIP_GROUPS {
        return Err(invalid("too many groups in gossip summary"));
    }
    let mut seen = BTreeSet::new();
    for entry in groups {
        if !is_valid_group_id(&entry.group_id) || !(1..=MAX_GROUP_SEQ).contains(&entry.seq) {
            return Err(invalid("malformed group gossip entry"));
        }
        if !seen.insert(entry.group_id.as_str()) {
            return Err(invalid("duplicate group in gossip summary"));
        }
    }
    Ok(())
}

/// One active group member pinned by key hash and relay key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMember {
    pub device_id: String,
    pub name: String,
    pub static_pub: String,
    pub signing_pub_hash: String,
    pub relay_pub: String,
    pub endpoints: Vec<String>,
    pub caps: Vec<String>,
}

impl GroupMember {
    /// Builds a member entry from raw keys, deriving `device_id`, `signing_pub_hash`, and `relay_pub`.
    #[must_use]
    pub fn new(
        static_pub: &[u8; 32],
        name: impl Into<String>,
        signing_pub: &HybridSigningPublicKey,
        endpoints: Vec<String>,
        caps: Vec<String>,
    ) -> Self {
        Self {
            device_id: device_id(static_pub),
            name: name.into(),
            static_pub: b64url_encode(static_pub),
            signing_pub_hash: b64url_encode(&signing_pub.sha256_hash()),
            relay_pub: b64url_encode(signing_pub.ed25519_bytes()),
            endpoints,
            caps,
        }
    }
}

/// Unsigned manifest body used for canonical serialization and signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupManifestUnsigned {
    pub v: u8,
    pub group_id: String,
    pub name: String,
    pub seq: u64,
    pub min_wire_version: u8,
    pub ts: String,
    pub expires_at: String,
    pub root_signing_pub: String,
    pub signer_device_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some"
    )]
    pub signer_signing_pub: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some"
    )]
    pub admin_grant: Option<Grant>,
    pub members: Vec<GroupMember>,
    pub revoked_members: Vec<String>,
}

/// Signed group manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupManifest {
    pub v: u8,
    pub group_id: String,
    pub name: String,
    pub seq: u64,
    pub min_wire_version: u8,
    pub ts: String,
    pub expires_at: String,
    pub root_signing_pub: String,
    pub signer_device_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some"
    )]
    pub signer_signing_pub: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some"
    )]
    pub admin_grant: Option<Grant>,
    pub members: Vec<GroupMember>,
    pub revoked_members: Vec<String>,
    pub sig: String,
}

impl GroupManifest {
    /// Extracts the unsigned portion of this manifest.
    #[must_use]
    pub fn unsigned(&self) -> GroupManifestUnsigned {
        GroupManifestUnsigned {
            v: self.v,
            group_id: self.group_id.clone(),
            name: self.name.clone(),
            seq: self.seq,
            min_wire_version: self.min_wire_version,
            ts: self.ts.clone(),
            expires_at: self.expires_at.clone(),
            root_signing_pub: self.root_signing_pub.clone(),
            signer_device_id: self.signer_device_id.clone(),
            signer_signing_pub: self.signer_signing_pub.clone(),
            admin_grant: self.admin_grant.clone(),
            members: self.members.clone(),
            revoked_members: self.revoked_members.clone(),
        }
    }

    /// Serializes this manifest as compact JSON, the exact `0x0A` frame payload.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let bytes = serde_json::to_vec(self).map_err(|err| CoreError::Json(err.to_string()))?;
        if bytes.len() > MAX_GROUP_MANIFEST_LEN {
            return Err(CoreError::GroupManifestTooLarge {
                len: bytes.len(),
                max: MAX_GROUP_MANIFEST_LEN,
            });
        }
        Ok(bytes)
    }

    /// Parses a `0x0A` frame payload without verifying it.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() > MAX_GROUP_MANIFEST_LEN {
            return Err(CoreError::GroupManifestTooLarge {
                len: bytes.len(),
                max: MAX_GROUP_MANIFEST_LEN,
            });
        }
        serde_json::from_slice(bytes).map_err(|err| CoreError::Json(err.to_string()))
    }
}

/// Builds `"tendril-group-v1\0" || RFC8785_JCS(unsigned)`.
pub fn group_manifest_signed_bytes(unsigned: &GroupManifestUnsigned) -> Result<Vec<u8>, CoreError> {
    let jcs = canonical_json(unsigned)?;
    let mut out = Vec::with_capacity(GROUP_MANIFEST_DOMAIN.len() + jcs.len());
    out.extend_from_slice(GROUP_MANIFEST_DOMAIN);
    out.extend_from_slice(jcs.as_bytes());
    Ok(out)
}

/// Signs a manifest with `signing_key`, enforcing [`MAX_GROUP_MANIFEST_LEN`].
pub fn sign_group_manifest(
    unsigned: GroupManifestUnsigned,
    signing_key: &SigningKeypair,
) -> Result<GroupManifest, CoreError> {
    sign_group_manifest_impl(unsigned, signing_key, false)
}

/// Deterministically signs a manifest for reproducible test vectors.
pub fn sign_group_manifest_deterministic(
    unsigned: GroupManifestUnsigned,
    signing_key: &SigningKeypair,
) -> Result<GroupManifest, CoreError> {
    sign_group_manifest_impl(unsigned, signing_key, true)
}

fn sign_group_manifest_impl(
    unsigned: GroupManifestUnsigned,
    signing_key: &SigningKeypair,
    deterministic: bool,
) -> Result<GroupManifest, CoreError> {
    check_seq(unsigned.seq)?;
    let msg = group_manifest_signed_bytes(&unsigned)?;
    let sig = if deterministic {
        signing_key.sign_deterministic(&msg)?
    } else {
        signing_key.sign(&msg)?
    };
    let manifest = GroupManifest {
        v: unsigned.v,
        group_id: unsigned.group_id,
        name: unsigned.name,
        seq: unsigned.seq,
        min_wire_version: unsigned.min_wire_version,
        ts: unsigned.ts,
        expires_at: unsigned.expires_at,
        root_signing_pub: unsigned.root_signing_pub,
        signer_device_id: unsigned.signer_device_id,
        signer_signing_pub: unsigned.signer_signing_pub,
        admin_grant: unsigned.admin_grant,
        members: unsigned.members,
        revoked_members: unsigned.revoked_members,
        sig: b64url_encode(&sig),
    };
    manifest.to_wire_bytes()?;
    Ok(manifest)
}

/// Result of a successful [`verify_group_manifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGroupManifest {
    manifest: GroupManifest,
    root_signing_pub: HybridSigningPublicKey,
    root_device_id: String,
    signed_bytes: Vec<u8>,
    expires_at_unix: u64,
}

impl VerifiedGroupManifest {
    #[must_use]
    pub const fn manifest(&self) -> &GroupManifest {
        &self.manifest
    }

    #[must_use]
    pub fn into_manifest(self) -> GroupManifest {
        self.manifest
    }

    #[must_use]
    pub const fn root_signing_pub(&self) -> &HybridSigningPublicKey {
        &self.root_signing_pub
    }

    #[must_use]
    pub fn root_device_id(&self) -> &str {
        &self.root_device_id
    }

    /// Returns the exact bytes covered by the signature.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }

    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Reports whether the signer is a co-admin rather than the founding root.
    #[must_use]
    pub fn signed_by_co_admin(&self) -> bool {
        self.manifest.signer_device_id != self.root_device_id
    }
}

fn validate_name(name: &str, what: &str) -> Result<(), CoreError> {
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_GROUP_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(invalid(format!("{what} must be 1..=64 printable chars")));
    }
    Ok(())
}

fn validate_endpoint_hints(endpoints: &[String]) -> Result<(), CoreError> {
    if endpoints.len() > MAX_MEMBER_ENDPOINTS {
        return Err(invalid("too many member endpoints"));
    }
    for ep in endpoints {
        if ep.len() > MAX_ENDPOINT_HINT_LEN
            || ep.starts_with("local:")
            || ep.starts_with("unix://")
            || !is_valid_pairing_endpoint_hint(ep)
        {
            return Err(invalid("invalid member endpoint hint"));
        }
    }
    Ok(())
}

fn check_group_scope(cap: &Capability, group_id: &str) -> Result<(), CoreError> {
    let Some(resource) = cap.resource.as_deref() else {
        return Err(CoreError::InvalidGroupCapabilityScope(format!(
            "unscoped capability {cap}"
        )));
    };
    if resource.contains(['%', '\\']) {
        return Err(CoreError::InvalidGroupCapabilityScope(format!(
            "capability {cap} has an escape character"
        )));
    }
    if resource == group_id {
        return Ok(());
    }
    let rest = resource
        .strip_prefix(group_id)
        .and_then(|tail| tail.strip_prefix('/'))
        .ok_or_else(|| {
            CoreError::InvalidGroupCapabilityScope(format!("capability {cap} escapes {group_id}"))
        })?;
    if rest
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(CoreError::InvalidGroupCapabilityScope(format!(
            "capability {cap} has an unsafe path segment"
        )));
    }
    Ok(())
}

fn validate_member_caps(caps: &[String], group_id: &str) -> Result<(), CoreError> {
    if caps.len() > MAX_MEMBER_CAPS {
        return Err(invalid("too many member capabilities"));
    }
    for raw in caps {
        let cap = Capability::parse(raw)?;
        if cap.namespace == ADMIN_NAMESPACE && cap.verb == ADMIN_VERB {
            return Err(CoreError::InvalidGroupCapabilityScope(
                "group.admin must not appear in member caps".to_string(),
            ));
        }
        check_group_scope(&cap, group_id)?;
    }
    Ok(())
}

struct ParsedMember<'a> {
    member: &'a GroupMember,
    signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN],
    relay_pub: [u8; ED25519_PUBLIC_LEN],
}

fn parse_member<'a>(
    member: &'a GroupMember,
    group_id: &str,
) -> Result<ParsedMember<'a>, CoreError> {
    validate_name(&member.name, "member name")?;
    let static_pub: [u8; 32] = b64url_decode_array(&member.static_pub)
        .map_err(|_| invalid("member static_pub must be 32 bytes b64url"))?;
    if !is_valid_x25519_public_key(&static_pub) {
        return Err(invalid("member static_pub is not a valid X25519 key"));
    }
    if member.device_id != device_id(&static_pub) {
        return Err(invalid("member device_id does not match static_pub"));
    }
    let signing_pub_hash: [u8; HYBRID_SIGNING_HASH_LEN] =
        b64url_decode_array(&member.signing_pub_hash)
            .map_err(|_| invalid("member signing_pub_hash must be 32 bytes b64url"))?;
    let relay_pub: [u8; ED25519_PUBLIC_LEN] = b64url_decode_array(&member.relay_pub)
        .map_err(|_| invalid("member relay_pub must be 32 bytes b64url"))?;
    if !is_valid_ed25519_public_key(&relay_pub) {
        return Err(invalid("member relay_pub is not a valid Ed25519 key"));
    }
    validate_endpoint_hints(&member.endpoints)?;
    validate_member_caps(&member.caps, group_id)?;
    Ok(ParsedMember {
        member,
        signing_pub_hash,
        relay_pub,
    })
}

fn validate_revoked(revoked: &[String]) -> Result<BTreeSet<&str>, CoreError> {
    if revoked.len() > MAX_REVOKED_MEMBERS {
        return Err(invalid("too many revoked members"));
    }
    let mut set = BTreeSet::new();
    for id in revoked {
        if !is_valid_device_id_format(id) || !set.insert(id.as_str()) {
            return Err(invalid("malformed or duplicate revoked member id"));
        }
    }
    Ok(set)
}

fn expect_signer_matches(
    parsed: &ParsedMember<'_>,
    signer_pub: &HybridSigningPublicKey,
) -> Result<(), CoreError> {
    let hash_ok = bool::from(parsed.signing_pub_hash.ct_eq(&signer_pub.sha256_hash()));
    let relay_ok = bool::from(parsed.relay_pub.ct_eq(signer_pub.ed25519_bytes()));
    if hash_ok && relay_ok {
        Ok(())
    } else {
        Err(invalid("signer key does not match its member entry"))
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_admin_grant(
    grant: &Grant,
    signer_device_id: &str,
    root_device_id: &str,
    root_pub: &HybridSigningPublicKey,
    signer_pub: &HybridSigningPublicKey,
    group_id: &str,
    now_unix: u64,
    root_crl: Option<&RevocationList>,
) -> Result<(), CoreError> {
    let deny = |msg: String| CoreError::GroupUnauthorized(format!("admin_grant rejected: {msg}"));
    if !grant.delegated_from.is_empty() {
        return Err(deny(
            "must be signed directly by the group root".to_string(),
        ));
    }
    verify_grant_with_chain(
        grant,
        signer_device_id,
        root_device_id,
        now_unix,
        None,
        |issuer| (issuer == root_device_id).then(|| root_pub.clone()),
    )
    .map_err(|err| deny(err.to_string()))?;
    if let Some(list) = root_crl {
        if list
            .revoked_devices
            .iter()
            .any(|d| d == signer_device_id || d == root_device_id)
        {
            return Err(deny("device is revoked".to_string()));
        }
        if list.revoked_nonces.iter().any(|n| n == &grant.nonce) {
            return Err(deny("grant nonce is revoked".to_string()));
        }
    }
    let needed = admin_cap_for(group_id, signer_pub);
    if !grant.caps.contains(&needed) {
        return Err(deny(
            "does not carry the keyed group.admin capability for the signer key".to_string(),
        ));
    }
    Ok(())
}

/// Verifies every structural, scope, time, signature, and co-admin rule of a manifest.
///
/// Ordered checks: size, version, identifiers, `group_id` derivation, name, wire floor, validity
/// window, members, revoked set, founding root presence, signer role, `admin_grant`, signature.
/// `MAX_GROUP_CO_ADMINS` is not enforced here; the root enforces it when issuing grants.
/// `root_crl` is the output of [`root_crl`]: its authority is not re-checked here.
pub fn verify_group_manifest(
    manifest: &GroupManifest,
    now_unix: u64,
    root_crl: Option<&RevocationList>,
) -> Result<VerifiedGroupManifest, CoreError> {
    manifest.to_wire_bytes()?;
    if manifest.v != GROUP_MANIFEST_VERSION {
        return Err(invalid("unsupported manifest version"));
    }
    if !is_valid_group_id(&manifest.group_id) {
        return Err(invalid("malformed group_id"));
    }
    check_seq(manifest.seq)?;
    if !matches!(manifest.min_wire_version, 1 | 2) {
        return Err(invalid("min_wire_version must be 1 or 2"));
    }
    validate_name(&manifest.name, "group name")?;

    let root_pub = HybridSigningPublicKey::from_b64url(&manifest.root_signing_pub)
        .map_err(|_| invalid("root_signing_pub is not a valid hybrid signing key"))?;
    if group_id_from_root(&root_pub) != manifest.group_id {
        return Err(invalid("group_id does not match root_signing_pub"));
    }

    let ts = parse_rfc3339_utc(&manifest.ts)?;
    let expires = parse_rfc3339_utc(&manifest.expires_at)?;
    if ts >= expires || expires - ts > MAX_MANIFEST_VALIDITY_SECS {
        return Err(invalid("expires_at must be in (ts, ts + 90d]"));
    }
    if now_unix >= expires {
        return Err(invalid("manifest expired"));
    }
    if ts > now_unix.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(invalid("manifest ts is in the future"));
    }

    if manifest.members.is_empty() || manifest.members.len() > MAX_GROUP_MEMBERS {
        return Err(invalid("members must contain 1..=32 entries"));
    }
    let mut ids = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut parsed = Vec::with_capacity(manifest.members.len());
    for member in &manifest.members {
        let p = parse_member(member, &manifest.group_id)?;
        if !ids.insert(member.device_id.as_str()) || !hashes.insert(p.signing_pub_hash) {
            return Err(invalid("duplicate member"));
        }
        parsed.push(p);
    }
    let revoked = validate_revoked(&manifest.revoked_members)?;
    if let Some(id) = ids.iter().find(|id| revoked.contains(**id)) {
        return Err(CoreError::GroupMemberRevoked((*id).to_string()));
    }

    let root_hash = root_pub.sha256_hash();
    let root_entry = parsed
        .iter()
        .find(|p| bool::from(p.signing_pub_hash.ct_eq(&root_hash)))
        .ok_or_else(|| invalid("founding root device missing from members"))?;
    if !bool::from(root_entry.relay_pub.ct_eq(root_pub.ed25519_bytes())) {
        return Err(invalid("founding root relay_pub mismatch"));
    }
    let root_device_id = root_entry.member.device_id.clone();

    let signer_pub = if manifest.signer_device_id == root_device_id {
        if manifest.signer_signing_pub.is_some() || manifest.admin_grant.is_some() {
            return Err(invalid(
                "root-signed manifest must omit signer key and grant",
            ));
        }
        root_pub.clone()
    } else {
        let entry = parsed
            .iter()
            .find(|p| p.member.device_id == manifest.signer_device_id)
            .ok_or_else(|| invalid("signer is not an active member"))?;
        let encoded = manifest
            .signer_signing_pub
            .as_deref()
            .ok_or_else(|| invalid("co-admin manifest requires signer_signing_pub"))?;
        let signer_pub = HybridSigningPublicKey::from_b64url(encoded)
            .map_err(|_| invalid("signer_signing_pub is not a valid hybrid signing key"))?;
        expect_signer_matches(entry, &signer_pub)?;
        let grant = manifest.admin_grant.as_ref().ok_or_else(|| {
            CoreError::GroupUnauthorized("co-admin manifest requires admin_grant".to_string())
        })?;
        verify_admin_grant(
            grant,
            &manifest.signer_device_id,
            &root_device_id,
            &root_pub,
            &signer_pub,
            &manifest.group_id,
            now_unix,
            root_crl,
        )?;
        signer_pub
    };

    let unsigned = manifest.unsigned();
    let signed_bytes = group_manifest_signed_bytes(&unsigned)?;
    let sig = b64url_decode(&manifest.sig)?;
    signer_pub.verify(&signed_bytes, &sig)?;

    Ok(VerifiedGroupManifest {
        manifest: manifest.clone(),
        root_signing_pub: root_pub,
        root_device_id,
        signed_bytes,
        expires_at_unix: expires,
    })
}

/// Zeroizing group rendezvous key bound to the manifest `seq` it was issued for.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct V2GroupSecrets {
    group_rendezvous_key: [u8; 32],
    seq: u64,
}

impl V2GroupSecrets {
    #[must_use]
    pub const fn new(group_rendezvous_key: [u8; 32], seq: u64) -> Self {
        Self {
            group_rendezvous_key,
            seq,
        }
    }

    /// Generates a fresh CSPRNG key for `seq`.
    pub fn generate(seq: u64) -> Result<Self, CoreError> {
        let key = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self::new(*key, seq))
    }

    #[must_use]
    pub const fn group_rendezvous_key(&self) -> &[u8; 32] {
        &self.group_rendezvous_key
    }

    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the same key re-bound to `seq` (used when membership grows without rotation).
    #[must_use]
    pub fn rebound(&self, seq: u64) -> Self {
        Self::new(self.group_rendezvous_key, seq)
    }

    /// Encodes the exact 60-byte `0x0B` payload for `group_id`.
    pub fn to_rendezvous_frame(
        &self,
        group_id: &str,
    ) -> Result<Zeroizing<[u8; GROUP_RENDEZVOUS_FRAME_LEN]>, CoreError> {
        encode_group_rendezvous_frame(group_id, self.seq, &self.group_rendezvous_key)
    }
}

impl PartialEq for V2GroupSecrets {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.group_rendezvous_key.ct_eq(&other.group_rendezvous_key))
            && self.seq == other.seq
    }
}

impl Eq for V2GroupSecrets {}

impl fmt::Debug for V2GroupSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2GroupSecrets")
            .field("group_rendezvous_key", &"<redacted>")
            .field("seq", &self.seq)
            .finish()
    }
}

struct SecretString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|s| Self(Zeroizing::new(s)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2GroupSecretsDe {
    group_rendezvous_key: SecretString,
    seq: u64,
}

#[derive(Serialize)]
struct V2GroupSecretsSerde<'a> {
    group_rendezvous_key: &'a str,
    seq: u64,
}

impl Serialize for V2GroupSecrets {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(b64url_encode(&self.group_rendezvous_key));
        V2GroupSecretsSerde {
            group_rendezvous_key: &encoded,
            seq: self.seq,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for V2GroupSecrets {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = V2GroupSecretsDe::deserialize(deserializer)?;
        let key = Zeroizing::new(
            b64url_decode_array::<32>(&repr.group_rendezvous_key.0)
                .map_err(serde::de::Error::custom)?,
        );
        Ok(Self::new(*key, repr.seq))
    }
}

/// Decoded `0x0B GROUP_RENDEZVOUS` payload.
#[derive(Clone, ZeroizeOnDrop)]
pub struct GroupRendezvousFrame {
    #[zeroize(skip)]
    pub group_id: String,
    #[zeroize(skip)]
    pub seq: u64,
    key: [u8; 32],
}

impl GroupRendezvousFrame {
    #[must_use]
    pub const fn group_rendezvous_key(&self) -> &[u8; 32] {
        &self.key
    }

    #[must_use]
    pub fn secrets(&self) -> V2GroupSecrets {
        V2GroupSecrets::new(self.key, self.seq)
    }
}

impl PartialEq for GroupRendezvousFrame {
    fn eq(&self, other: &Self) -> bool {
        self.group_id == other.group_id
            && self.seq == other.seq
            && bool::from(self.key.ct_eq(&other.key))
    }
}

impl Eq for GroupRendezvousFrame {}

impl fmt::Debug for GroupRendezvousFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupRendezvousFrame")
            .field("group_id", &self.group_id)
            .field("seq", &self.seq)
            .field("group_rendezvous_key", &"<redacted>")
            .finish()
    }
}

/// Encodes `20 B ASCII group_id || 8 B uint64_be seq || 32 B key` (exactly 60 bytes).
pub fn encode_group_rendezvous_frame(
    group_id: &str,
    seq: u64,
    key: &[u8; 32],
) -> Result<Zeroizing<[u8; GROUP_RENDEZVOUS_FRAME_LEN]>, CoreError> {
    if !is_valid_group_id(group_id) {
        return Err(invalid("malformed group_id in rendezvous frame"));
    }
    check_seq(seq)?;
    let mut out = Zeroizing::new([0u8; GROUP_RENDEZVOUS_FRAME_LEN]);
    out[..GROUP_ID_LEN].copy_from_slice(group_id.as_bytes());
    out[GROUP_ID_LEN..GROUP_ID_LEN + 8].copy_from_slice(&seq.to_be_bytes());
    out[GROUP_ID_LEN + 8..].copy_from_slice(key);
    Ok(out)
}

/// Strictly decodes a `0x0B` payload, rejecting any length other than 60 bytes.
pub fn decode_group_rendezvous_frame(payload: &[u8]) -> Result<GroupRendezvousFrame, CoreError> {
    if payload.len() != GROUP_RENDEZVOUS_FRAME_LEN {
        return Err(CoreError::InvalidInnerFramePayload(
            "GROUP_RENDEZVOUS payload must be exactly 60 bytes",
        ));
    }
    let group_id = std::str::from_utf8(&payload[..GROUP_ID_LEN])
        .map_err(|_| invalid("rendezvous group_id is not ASCII"))?;
    if !is_valid_group_id(group_id) {
        return Err(invalid("malformed group_id in rendezvous frame"));
    }
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&payload[GROUP_ID_LEN..GROUP_ID_LEN + 8]);
    let seq = u64::from_be_bytes(seq);
    check_seq(seq)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&payload[GROUP_ID_LEN + 8..]);
    Ok(GroupRendezvousFrame {
        group_id: group_id.to_string(),
        seq,
        key: *key,
    })
}

/// Derives the first-contact bootstrap secret shared by two members at `seq`.
///
/// `HKDF-SHA256(ikm = key, salt = uint64_be(seq), info = "tendril-group-v2-rendezvous\0" ||
/// min(id_a, id_b) || "\0" || max(id_a, id_b))`.
#[must_use]
pub fn derive_pair_bootstrap(
    group_rendezvous_key: &[u8; 32],
    seq: u64,
    id_a: &str,
    id_b: &str,
) -> Zeroizing<[u8; 32]> {
    let (lo, hi) = if id_a.as_bytes() <= id_b.as_bytes() {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut info = Vec::with_capacity(PAIR_BOOTSTRAP_INFO.len() + lo.len() + 1 + hi.len());
    info.extend_from_slice(PAIR_BOOTSTRAP_INFO);
    info.extend_from_slice(lo.as_bytes());
    info.push(0);
    info.extend_from_slice(hi.as_bytes());
    hkdf_sha256_32(group_rendezvous_key, &seq.to_be_bytes(), &info)
}

/// Derives the group discovery mailbox secret of `member_device_id` at `seq`.
///
/// `HKDF-SHA256(ikm = key, salt = uint64_be(seq), info = "tendril-group-v2-mailbox" ||
/// member_device_id)`.
#[must_use]
pub fn derive_group_mailbox_secret(
    group_rendezvous_key: &[u8; 32],
    seq: u64,
    member_device_id: &str,
) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(GROUP_MAILBOX_INFO.len() + member_device_id.len());
    info.extend_from_slice(GROUP_MAILBOX_INFO);
    info.extend_from_slice(member_device_id.as_bytes());
    hkdf_sha256_32(group_rendezvous_key, &seq.to_be_bytes(), &info)
}

/// How an ingested manifest changed the stored state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupIngestStatus {
    /// First manifest for this group; the root key is now pinned.
    Created,
    /// A higher `seq` replaced the stored manifest.
    Updated,
    /// Identical bytes to the stored manifest; nothing changed.
    Unchanged,
}

/// Diff produced by [`GroupBook::ingest_group_manifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupIngestOutcome {
    pub group_id: String,
    pub seq: u64,
    pub status: GroupIngestStatus,
    pub newly_revoked: Vec<String>,
    pub newly_joined: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupRecord {
    root_signing_pub: HybridSigningPublicKey,
    manifest: GroupManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secrets: Option<V2GroupSecrets>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    rotation_required: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pairwise: BTreeMap<String, V2PeerSecrets>,
}

impl GroupRecord {
    fn prune_pairwise(&mut self) {
        let manifest = &self.manifest;
        self.pairwise.retain(|id, _| is_active_member(manifest, id));
    }
}

/// Returns whether `device_id` is listed in `manifest.members` and not in its revoked list.
#[must_use]
pub fn is_active_member(manifest: &GroupManifest, device_id: &str) -> bool {
    manifest.members.iter().any(|m| m.device_id == device_id)
        && !manifest.revoked_members.iter().any(|r| r == device_id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupBookRepr {
    groups: BTreeMap<String, GroupRecord>,
}

/// Serializable per-endpoint store of pinned groups, current manifests, and local secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "GroupBookRepr")]
pub struct GroupBook {
    groups: BTreeMap<String, GroupRecord>,
}

impl TryFrom<GroupBookRepr> for GroupBook {
    type Error = CoreError;

    fn try_from(mut repr: GroupBookRepr) -> Result<Self, Self::Error> {
        for record in repr.groups.values_mut() {
            record.prune_pairwise();
        }
        for (id, record) in &repr.groups {
            if *id != record.manifest.group_id
                || group_id_from_root(&record.root_signing_pub) != *id
                || record.manifest.root_signing_pub != record.root_signing_pub.to_b64url()
            {
                return Err(invalid("persisted group record is inconsistent"));
            }
            if record
                .secrets
                .as_ref()
                .is_some_and(|s| s.seq() > record.manifest.seq)
            {
                return Err(invalid("persisted group secrets are ahead of the manifest"));
            }
        }
        Ok(Self {
            groups: repr.groups,
        })
    }
}

impl GroupBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the stored manifest for `group_id`.
    #[must_use]
    pub fn manifest(&self, group_id: &str) -> Option<&GroupManifest> {
        self.groups.get(group_id).map(|r| &r.manifest)
    }

    /// Returns the pinned founding root key for `group_id`.
    #[must_use]
    pub fn root_signing_pub(&self, group_id: &str) -> Option<&HybridSigningPublicKey> {
        self.groups.get(group_id).map(|r| &r.root_signing_pub)
    }

    /// Returns the local rendezvous secrets for `group_id`, if any.
    #[must_use]
    pub fn secrets(&self, group_id: &str) -> Option<&V2GroupSecrets> {
        self.groups.get(group_id).and_then(|r| r.secrets.as_ref())
    }

    /// Lists stored group ids in sorted order.
    #[must_use]
    pub fn group_ids(&self) -> Vec<String> {
        self.groups.keys().cloned().collect()
    }

    /// Drops all state for `group_id`, including every pairwise secret, returning whether it
    /// existed.
    pub fn forget_group(&mut self, group_id: &str) -> bool {
        self.groups.remove(group_id).is_some()
    }

    /// Drops the rendezvous secrets and every pairwise secret of `group_id` while keeping the
    /// pinned root and the current manifest, so seq and fork checks keep working. Returns whether
    /// the group exists.
    pub fn drop_secrets(&mut self, group_id: &str) -> bool {
        let Some(record) = self.groups.get_mut(group_id) else {
            return false;
        };
        record.secrets = None;
        record.rotation_required = false;
        record.pairwise.clear();
        true
    }

    /// Returns the group-scoped pairwise v2 secrets shared with sibling `peer_device_id`.
    ///
    /// These secrets never enter the global trust roster and are dropped when the sibling is
    /// revoked or removed by any ingested manifest, or when the group is forgotten.
    #[must_use]
    pub fn pairwise_secrets(&self, group_id: &str, peer_device_id: &str) -> Option<&V2PeerSecrets> {
        self.groups
            .get(group_id)
            .and_then(|r| r.pairwise.get(peer_device_id))
    }

    /// Stores group-scoped pairwise v2 secrets for an active sibling, replacing any previous ones.
    pub fn set_pairwise_secrets(
        &mut self,
        group_id: &str,
        peer_device_id: &str,
        secrets: V2PeerSecrets,
    ) -> Result<(), CoreError> {
        let record = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_string()))?;
        if !is_active_member(&record.manifest, peer_device_id) {
            return Err(CoreError::GroupMemberRevoked(peer_device_id.to_string()));
        }
        record.pairwise.insert(peer_device_id.to_string(), secrets);
        Ok(())
    }

    /// Removes the pairwise secrets stored for `peer_device_id`, returning whether any existed.
    pub fn remove_pairwise_secrets(&mut self, group_id: &str, peer_device_id: &str) -> bool {
        self.groups
            .get_mut(group_id)
            .is_some_and(|r| r.pairwise.remove(peer_device_id).is_some())
    }

    /// Installs locally generated secrets (creator or admin) for the stored manifest `seq`.
    pub fn install_secrets(
        &mut self,
        group_id: &str,
        secrets: V2GroupSecrets,
    ) -> Result<(), CoreError> {
        let record = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_string()))?;
        if secrets.seq() != record.manifest.seq {
            return Err(invalid("secrets seq must equal the stored manifest seq"));
        }
        if record.rotation_required
            && let Some(existing) = &record.secrets
            && bool::from(
                existing
                    .group_rendezvous_key()
                    .ct_eq(secrets.group_rendezvous_key()),
            )
        {
            return Err(invalid(
                "rendezvous key must rotate after a revocation at this seq",
            ));
        }
        record.secrets = Some(secrets);
        record.rotation_required = false;
        Ok(())
    }

    /// Reports whether `device_id` holds live admin authority in `group_id` at `now_unix`.
    ///
    /// The founding root always qualifies while the stored manifest is unexpired. A co-admin
    /// qualifies only while its stored `admin_grant` still verifies against `root_crl`, the
    /// output of [`root_crl`].
    #[must_use]
    pub fn is_group_admin(
        &self,
        group_id: &str,
        device_id: &str,
        now_unix: u64,
        root_crl: Option<&RevocationList>,
    ) -> bool {
        self.groups
            .get(group_id)
            .is_some_and(|record| is_group_admin(record, device_id, now_unix, root_crl))
    }

    /// Returns up to [`MAX_GOSSIP_GROUPS`] `(group_id, seq)` pairs in sorted order.
    #[must_use]
    pub fn gossip_summary(&self) -> Vec<GroupSeq> {
        self.groups
            .iter()
            .take(MAX_GOSSIP_GROUPS)
            .map(|(id, r)| GroupSeq {
                group_id: id.clone(),
                seq: r.manifest.seq,
            })
            .collect()
    }

    /// Verifies and ingests `manifest`, pinning the root key on the first ingest of a group.
    ///
    /// Accepts iff the signature is valid and `seq` exceeds the stored `seq`. An identical
    /// manifest is a no-op, a different manifest at the same `seq` is [`CoreError::GroupManifestFork`],
    /// and a lower `seq` is [`CoreError::GroupSeqRollback`]. The first ingest of an unknown group
    /// is trust-on-first-use and MUST come from an explicit administrative push. `root_crl` is
    /// the output of [`root_crl`].
    pub fn ingest_group_manifest(
        &mut self,
        manifest: &GroupManifest,
        now_unix: u64,
        root_crl: Option<&RevocationList>,
    ) -> Result<GroupIngestOutcome, CoreError> {
        self.ingest_inner(manifest, now_unix, root_crl, true)
    }

    /// Like [`Self::ingest_group_manifest`] but fails with [`CoreError::GroupNotFound`] for a group
    /// that is not already pinned, so gossip can never create groups.
    pub fn ingest_gossiped_manifest(
        &mut self,
        manifest: &GroupManifest,
        now_unix: u64,
        root_crl: Option<&RevocationList>,
    ) -> Result<GroupIngestOutcome, CoreError> {
        self.ingest_inner(manifest, now_unix, root_crl, false)
    }

    fn ingest_inner(
        &mut self,
        manifest: &GroupManifest,
        now_unix: u64,
        root_crl: Option<&RevocationList>,
        allow_pin: bool,
    ) -> Result<GroupIngestOutcome, CoreError> {
        let existing = self.groups.get(&manifest.group_id);
        if existing.is_none() && !allow_pin {
            return Err(CoreError::GroupNotFound(manifest.group_id.clone()));
        }
        if let Some(record) = existing {
            if manifest.root_signing_pub != record.root_signing_pub.to_b64url() {
                return Err(invalid("root_signing_pub differs from the pinned root"));
            }
            if manifest.seq == record.manifest.seq && *manifest == record.manifest {
                if is_expired(&record.manifest, now_unix)? {
                    return Err(invalid("manifest expired"));
                }
                return Ok(GroupIngestOutcome {
                    group_id: manifest.group_id.clone(),
                    seq: manifest.seq,
                    status: GroupIngestStatus::Unchanged,
                    newly_revoked: Vec::new(),
                    newly_joined: Vec::new(),
                    removed: Vec::new(),
                });
            }
        }

        let verified = verify_group_manifest(manifest, now_unix, root_crl)?;

        let Some(record) = self.groups.get_mut(&manifest.group_id) else {
            let outcome = GroupIngestOutcome {
                group_id: manifest.group_id.clone(),
                seq: manifest.seq,
                status: GroupIngestStatus::Created,
                newly_revoked: manifest.revoked_members.clone(),
                newly_joined: manifest
                    .members
                    .iter()
                    .map(|m| m.device_id.clone())
                    .collect(),
                removed: Vec::new(),
            };
            self.groups.insert(
                manifest.group_id.clone(),
                GroupRecord {
                    root_signing_pub: verified.root_signing_pub().clone(),
                    manifest: manifest.clone(),
                    secrets: None,
                    rotation_required: false,
                    pairwise: BTreeMap::new(),
                },
            );
            return Ok(outcome);
        };

        let prev = &record.manifest;
        if manifest.seq < prev.seq {
            return Err(CoreError::GroupSeqRollback {
                current: prev.seq,
                got: manifest.seq,
            });
        }
        if manifest.seq == prev.seq {
            let prev_signed = group_manifest_signed_bytes(&prev.unsigned())?;
            if prev_signed == verified.signed_bytes() {
                return Ok(GroupIngestOutcome {
                    group_id: manifest.group_id.clone(),
                    seq: manifest.seq,
                    status: GroupIngestStatus::Unchanged,
                    newly_revoked: Vec::new(),
                    newly_joined: Vec::new(),
                    removed: Vec::new(),
                });
            }
            return Err(CoreError::GroupManifestFork { seq: prev.seq });
        }
        if manifest.seq - prev.seq > MAX_GROUP_SEQ_JUMP {
            return Err(invalid("seq jump exceeds the per-ingest bound"));
        }
        if manifest.min_wire_version < prev.min_wire_version {
            return Err(CoreError::GroupWireDowngrade {
                current: prev.min_wire_version,
                got: manifest.min_wire_version,
            });
        }
        let prev_revoked: BTreeSet<&str> =
            prev.revoked_members.iter().map(String::as_str).collect();
        let new_revoked: BTreeSet<&str> = manifest
            .revoked_members
            .iter()
            .map(String::as_str)
            .collect();
        if let Some(id) = prev_revoked.difference(&new_revoked).next() {
            return Err(if manifest.members.iter().any(|m| m.device_id == *id) {
                CoreError::GroupMemberRevoked((*id).to_string())
            } else {
                invalid("revoked_members must be a superset of the previous set")
            });
        }

        let prev_members: BTreeSet<&str> =
            prev.members.iter().map(|m| m.device_id.as_str()).collect();
        let new_members: BTreeSet<&str> = manifest
            .members
            .iter()
            .map(|m| m.device_id.as_str())
            .collect();
        if prev_members
            .difference(&new_members)
            .any(|id| !new_revoked.contains(id))
        {
            return Err(invalid("removed members must appear in revoked_members"));
        }
        let root_pub = &record.root_signing_pub;
        let (Some(prev_root), Some(new_root)) = (
            find_root_member(prev, root_pub),
            find_root_member(manifest, root_pub),
        ) else {
            return Err(invalid("founding root device missing from members"));
        };
        if prev_root.device_id != new_root.device_id || prev_root.static_pub != new_root.static_pub
        {
            return Err(invalid(
                "founding root identity differs from the pinned one",
            ));
        }
        if verified.signed_by_co_admin() && prev_root != new_root {
            return Err(CoreError::GroupUnauthorized(
                "co-admin must not alter the founding root entry".to_string(),
            ));
        }
        let outcome = GroupIngestOutcome {
            group_id: manifest.group_id.clone(),
            seq: manifest.seq,
            status: GroupIngestStatus::Updated,
            newly_revoked: new_revoked
                .difference(&prev_revoked)
                .map(|s| (*s).to_string())
                .collect(),
            newly_joined: new_members
                .difference(&prev_members)
                .map(|s| (*s).to_string())
                .collect(),
            removed: prev_members
                .difference(&new_members)
                .map(|s| (*s).to_string())
                .collect(),
        };
        record.rotation_required |= !outcome.newly_revoked.is_empty();
        record.manifest = manifest.clone();
        record.prune_pairwise();
        Ok(outcome)
    }

    /// Checks that `sender_device_id` is an active member of `group_id` holding `cap`.
    ///
    /// Fails closed when the group is unknown, the stored manifest has expired at `now_unix`, the
    /// sender is revoked by the manifest or listed in `root_crl` (the output of [`root_crl`]), the
    /// sender is absent, or no member capability covers `cap`. `group.admin:<group_id>` is
    /// satisfied only by the founding root device or the signer holding a valid `admin_grant` in
    /// the stored manifest.
    pub fn authorize_group(
        &self,
        group_id: &str,
        sender_device_id: &str,
        cap: &Capability,
        now_unix: u64,
        root_crl: Option<&RevocationList>,
    ) -> Result<(), CoreError> {
        let record = self
            .groups
            .get(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_string()))?;
        check_group_scope(cap, group_id)?;
        let manifest = &record.manifest;
        ensure_unexpired(manifest, now_unix)?;
        if manifest
            .revoked_members
            .iter()
            .any(|id| id == sender_device_id)
        {
            return Err(CoreError::GroupMemberRevoked(sender_device_id.to_string()));
        }
        if root_crl.is_some_and(|crl| crl.revoked_devices.iter().any(|d| d == sender_device_id)) {
            return Err(CoreError::GroupMemberRevoked(sender_device_id.to_string()));
        }
        let member = manifest
            .members
            .iter()
            .find(|m| m.device_id == sender_device_id)
            .ok_or_else(|| {
                CoreError::GroupUnauthorized(format!("{sender_device_id} is not a member"))
            })?;
        if cap.namespace == ADMIN_NAMESPACE && cap.verb == ADMIN_VERB {
            if cap.resource.as_deref() != Some(group_id) {
                return Err(CoreError::GroupUnauthorized(
                    "only the exact group.admin capability is answered by admin status".to_string(),
                ));
            }
            return if is_group_admin(record, sender_device_id, now_unix, root_crl) {
                Ok(())
            } else {
                Err(CoreError::GroupUnauthorized(
                    "sender is not a group admin".to_string(),
                ))
            };
        }
        let granted = member
            .caps
            .iter()
            .filter_map(|raw| Capability::parse(raw).ok())
            .any(|held| held.covers(cap));
        if granted {
            Ok(())
        } else {
            Err(CoreError::GroupUnauthorized(format!(
                "{sender_device_id} lacks {cap}"
            )))
        }
    }

    /// Accepts a decoded `0x0B` frame from an authenticated `sender_device_id`.
    ///
    /// Only the founding root device or the stored manifest's `admin_grant` signer may deliver a
    /// key, and only for exactly the stored manifest `seq`. `root_crl` is the output of
    /// [`root_crl`].
    pub fn ingest_group_rendezvous_frame(
        &mut self,
        sender_device_id: &str,
        frame: &GroupRendezvousFrame,
        now_unix: u64,
        root_crl: Option<&RevocationList>,
    ) -> Result<(), CoreError> {
        let record = self
            .groups
            .get_mut(&frame.group_id)
            .ok_or_else(|| CoreError::GroupNotFound(frame.group_id.clone()))?;
        ensure_unexpired(&record.manifest, now_unix)?;
        if !is_group_admin(record, sender_device_id, now_unix, root_crl) {
            return Err(CoreError::GroupUnauthorized(
                "rendezvous sender is not a group admin".to_string(),
            ));
        }
        if frame.seq < record.manifest.seq {
            return Err(CoreError::GroupSeqRollback {
                current: record.manifest.seq,
                got: frame.seq,
            });
        }
        if frame.seq > record.manifest.seq {
            return Err(invalid("rendezvous seq is ahead of the stored manifest"));
        }
        if let Some(existing) = &record.secrets
            && existing.seq() == frame.seq
            && existing != &frame.secrets()
        {
            return Err(invalid("conflicting rendezvous key for the stored seq"));
        }
        if record.rotation_required
            && let Some(existing) = &record.secrets
            && existing.seq() < frame.seq
            && bool::from(
                existing
                    .group_rendezvous_key()
                    .ct_eq(frame.group_rendezvous_key()),
            )
        {
            return Err(invalid(
                "rendezvous key must rotate after a revocation at this seq",
            ));
        }
        record.secrets = Some(frame.secrets());
        record.rotation_required = false;
        Ok(())
    }

    /// Decodes a raw `0x0B` payload and ingests it via [`Self::ingest_group_rendezvous_frame`].
    pub fn ingest_group_rendezvous(
        &mut self,
        sender_device_id: &str,
        payload: &[u8],
        now_unix: u64,
        root_crl: Option<&RevocationList>,
    ) -> Result<(), CoreError> {
        let frame = decode_group_rendezvous_frame(payload)?;
        self.ingest_group_rendezvous_frame(sender_device_id, &frame, now_unix, root_crl)
    }

    /// Derives the first-contact bootstrap secret between two active members from stored secrets.
    pub fn pair_bootstrap(
        &self,
        group_id: &str,
        id_a: &str,
        id_b: &str,
        now_unix: u64,
    ) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        let record = self
            .groups
            .get(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_string()))?;
        ensure_unexpired(&record.manifest, now_unix)?;
        let secrets = record
            .secrets
            .as_ref()
            .filter(|s| s.seq() == record.manifest.seq)
            .ok_or_else(|| {
                CoreError::GroupUnauthorized("no rendezvous key for the stored seq".to_string())
            })?;
        for id in [id_a, id_b] {
            if record.manifest.revoked_members.iter().any(|r| r == id) {
                return Err(CoreError::GroupMemberRevoked(id.to_string()));
            }
            if !record.manifest.members.iter().any(|m| m.device_id == id) {
                return Err(CoreError::GroupUnauthorized(format!(
                    "{id} is not a member"
                )));
            }
        }
        Ok(derive_pair_bootstrap(
            secrets.group_rendezvous_key(),
            secrets.seq(),
            id_a,
            id_b,
        ))
    }
}

/// Returns the device id of the member whose signing key hash matches `root_pub`.
#[must_use]
pub fn root_device_in(
    manifest: &GroupManifest,
    root_pub: &HybridSigningPublicKey,
) -> Option<String> {
    find_root_member(manifest, root_pub).map(|m| m.device_id.clone())
}

impl GroupBook {
    /// Returns the device id of the founding root of the stored group `group_id`, resolved
    /// from the pinned root key and the stored member list.
    #[must_use]
    pub fn root_device_id(&self, group_id: &str) -> Option<String> {
        let record = self.groups.get(group_id)?;
        root_device_in(&record.manifest, &record.root_signing_pub)
    }

    /// Returns whether `local_device_id` is an active member of the stored `group_id` or its
    /// founding root.
    #[must_use]
    pub fn holds_group(&self, local_device_id: &str, group_id: &str) -> bool {
        self.manifest(group_id).is_some_and(|m| {
            is_active_member(m, local_device_id)
                || self.root_device_id(group_id).as_deref() == Some(local_device_id)
        })
    }
}

/// Resolves the roster entry whose pinned static key derives the device id `wanted`.
///
/// Roster keys are host ids chosen by the host application, so the canonical device id is derived
/// from the pinned static key rather than trusting the key or the entry label.
#[must_use]
pub fn find_peer_by_device_id<'a>(
    roster: &'a Roster,
    wanted: &str,
) -> Option<(&'a String, &'a RosterEntry)> {
    roster
        .entries()
        .find(|(_, e)| device_id(&e.static_pub) == wanted)
}

/// Resolves the effective root revocation list of a group whose founding root is
/// `root_device_id` with the pinned founding key `root_pub`.
///
/// Every stored list with `v == 1` whose signature verifies under `root_pub` applies, whatever
/// label it is stored under; labels never grant or remove authority. Candidates are the lists
/// stored under every label a list can be persisted under: each roster entry key, stored
/// `device_id`, and static-derived `device_id`, `root_device_id`, and `local_host_id`, the
/// `host_id` under which the local endpoint mints its own lists (a local root without a roster
/// entry of its own). One authoritative list is returned unchanged. Several are merged into a
/// local view (`issuer = root_device_id`, maximum `seq` and `ts`, empty `sig`) holding the union
/// of their revoked devices and nonces, since `seq` is per label. The view covers the lists
/// stored now: a later root-signed list replaces the earlier one under its label, so an entry
/// the root drops from that label's list stops applying unless another stored list keeps it.
/// The merged view is never sent or re-verified.
///
/// # Errors
///
/// Returns [`CoreError::GroupUnauthorized`] when the root rotated away from the founding key, so
/// the revocation state of the group can no longer be resolved and every decision consuming it
/// fails closed: the entry keyed `root_device_id` is not `Pending`, has rotated keys
/// (`rotation_seq > 0`), and its pinned signing key is no longer `root_pub`, whether or not a
/// re-signed list has arrived; or the list stored under `root_device_id` does not verify under
/// `root_pub` and either this endpoint is the root (`local_host_id` equals `root_device_id`), no
/// entry is keyed `root_device_id`, or that entry is not `Pending` and has rotated keys. A local
/// root holds the authoritative list under its own label, so it fails closed whenever that list
/// does not verify, whatever entry a peer pinned under the label. A roster entry does not record where its key lineage started,
/// so any such rotated entry counts as the root's, whether `Active` or `Revoked`, including a
/// never-confirmed pin later revoked locally. A `Pending` entry, such as an unconfirmed host pin
/// whose `host_id` the remote chose, counts as no entry in both rules, so a local root that holds
/// one under its own `device_id` still fails closed once its re-signed list replaces the founding
/// one.
pub fn root_crl(
    roster: &Roster,
    root_device_id: &str,
    root_pub: &HybridSigningPublicKey,
    local_host_id: Option<&str>,
) -> Result<Option<RevocationList>, CoreError> {
    let authoritative =
        |list: &RevocationList| list.v == 1 && verify_crl_signature(list, root_pub).is_ok();
    let held = roster
        .get(root_device_id)
        .filter(|e| e.state != PeerState::Pending);
    let rotated_root = held.filter(|e| e.rotation_seq > 0);
    let rotated_away = rotated_root.is_some_and(|e| e.signing_pub.as_ref() != Some(root_pub));
    let local_root = local_host_id == Some(root_device_id);
    let foreign_root_list = roster.crl(root_device_id).is_some_and(|list| {
        !authoritative(list) && (local_root || held.is_none() || rotated_root.is_some())
    });
    if rotated_away || foreign_root_list {
        return Err(CoreError::GroupUnauthorized(
            "root revocation list does not verify under the group root key".to_owned(),
        ));
    }
    let labels: BTreeSet<String> = roster
        .entries()
        .flat_map(|(key, e)| [key.clone(), e.device_id.clone(), device_id(&e.static_pub)])
        .chain([root_device_id.to_owned()])
        .chain(local_host_id.map(str::to_owned))
        .collect();
    let mut lists = labels
        .iter()
        .filter_map(|label| roster.crl(label))
        .filter(|list| authoritative(list));
    let Some(first) = lists.next() else {
        return Ok(None);
    };
    let rest: Vec<&RevocationList> = lists.collect();
    if rest.is_empty() {
        return Ok(Some(first.clone()));
    }
    let mut merged = RevocationList {
        v: 1,
        issuer: root_device_id.to_owned(),
        seq: first.seq,
        revoked_devices: Vec::new(),
        revoked_nonces: Vec::new(),
        ts: first.ts.clone(),
        sig: String::new(),
    };
    let mut latest = parse_rfc3339_utc(&first.ts)?;
    for list in std::iter::once(first).chain(rest) {
        merged.seq = merged.seq.max(list.seq);
        let ts = parse_rfc3339_utc(&list.ts)?;
        if ts > latest {
            latest = ts;
            merged.ts.clone_from(&list.ts);
        }
        for id in &list.revoked_devices {
            if !merged.revoked_devices.contains(id) {
                merged.revoked_devices.push(id.clone());
            }
        }
        for nonce in &list.revoked_nonces {
            if !merged.revoked_nonces.contains(nonce) {
                merged.revoked_nonces.push(nonce.clone());
            }
        }
    }
    Ok(Some(merged))
}

/// F11 first-contact pinning rule for a group not yet stored.
///
/// `sender_device_id` is the authenticated session peer. The group is pinnable only when the
/// sender is the manifest's `signer_device_id`, an `Active` ordinarily paired peer that no CRL
/// revokes, whose pinned signing key equals the manifest signer key (`signer_signing_pub`, else
/// `root_signing_pub`), and `local_device_id` is an active member of the manifest. The manifest
/// signature is not checked here; ingest verifies it.
///
/// # Errors
///
/// Returns [`CoreError::GroupUnauthorized`] naming the failed condition.
pub fn check_first_contact(
    roster: &Roster,
    local_device_id: &str,
    sender_device_id: &str,
    manifest: &GroupManifest,
) -> Result<(), CoreError> {
    let refuse = |why: &str| CoreError::GroupUnauthorized(why.to_owned());
    if sender_device_id != manifest.signer_device_id {
        return Err(refuse("first contact must come from the manifest signer"));
    }
    let entry = find_peer_by_device_id(roster, sender_device_id)
        .map(|(_, e)| e)
        .filter(|e| e.state == PeerState::Active && !roster.crl_revokes_entry(e))
        .ok_or_else(|| refuse("manifest signer is not an active paired peer"))?;
    let signer_key = manifest
        .signer_signing_pub
        .as_deref()
        .unwrap_or(&manifest.root_signing_pub);
    let signer_key = HybridSigningPublicKey::from_b64url(signer_key)
        .map_err(|_| refuse("invalid manifest signer key"))?;
    if entry.signing_pub.as_ref() != Some(&signer_key) {
        return Err(refuse(
            "manifest signer key differs from the paired peer's pinned key",
        ));
    }
    if !is_active_member(manifest, local_device_id) {
        return Err(refuse("local device is not an active member"));
    }
    Ok(())
}

/// Refuses to store `group_id` when it is new and `local_device_id` already holds
/// [`MAX_LOCAL_GROUPS`] groups or [`MAX_STORED_GROUPS`] records exist.
///
/// Only groups where the local device is an active member or the root count toward
/// [`MAX_LOCAL_GROUPS`] (H1): groups it was revoked or removed from do not consume those slots,
/// but they do count toward [`MAX_STORED_GROUPS`] (H4). Updating a stored group is always
/// allowed.
///
/// # Errors
///
/// Returns [`CoreError::GroupUnauthorized`] when a cap is reached.
pub fn check_group_capacity(
    book: &GroupBook,
    local_device_id: &str,
    group_id: &str,
) -> Result<(), CoreError> {
    if book.manifest(group_id).is_some() {
        return Ok(());
    }
    if book.groups.len() >= MAX_STORED_GROUPS {
        return Err(CoreError::GroupUnauthorized(format!(
            "more than {MAX_STORED_GROUPS} stored groups"
        )));
    }
    let held = book
        .groups
        .keys()
        .filter(|id| book.holds_group(local_device_id, id))
        .count();
    if held < MAX_LOCAL_GROUPS {
        return Ok(());
    }
    Err(CoreError::GroupUnauthorized(format!(
        "more than {MAX_LOCAL_GROUPS} local groups"
    )))
}

/// H4(a): drops the rendezvous and pairwise secrets of `group_id` once `local_device_id` is
/// neither an active member nor the root, keeping the manifest for seq and fork checks.
/// Returns whether secrets were dropped.
pub fn drop_secrets_if_left(book: &mut GroupBook, local_device_id: &str, group_id: &str) -> bool {
    if book.manifest(group_id).is_none() || book.holds_group(local_device_id, group_id) {
        return false;
    }
    book.drop_secrets(group_id)
}

/// H6: refuses a rendezvous frame for a stored group the local device is neither an active
/// member of nor the root of, so a removed device never regains rendezvous secrets. A group
/// that is not stored passes; ingest rejects it on its own rules.
///
/// # Errors
///
/// Returns [`CoreError::GroupUnauthorized`] when the stored group excludes the local device.
pub fn check_rendezvous_local_membership(
    book: &GroupBook,
    local_device_id: &str,
    group_id: &str,
) -> Result<(), CoreError> {
    if book.manifest(group_id).is_some() && !book.holds_group(local_device_id, group_id) {
        return Err(CoreError::GroupUnauthorized(format!(
            "{local_device_id} is not an active member of {group_id}"
        )));
    }
    Ok(())
}

fn is_expired(manifest: &GroupManifest, now_unix: u64) -> Result<bool, CoreError> {
    Ok(now_unix >= parse_rfc3339_utc(&manifest.expires_at)?)
}

fn ensure_unexpired(manifest: &GroupManifest, now_unix: u64) -> Result<(), CoreError> {
    if is_expired(manifest, now_unix)? {
        return Err(CoreError::GroupUnauthorized(
            "stored manifest has expired".to_string(),
        ));
    }
    Ok(())
}

fn find_root_member<'a>(
    manifest: &'a GroupManifest,
    root_pub: &HybridSigningPublicKey,
) -> Option<&'a GroupMember> {
    let hash = b64url_encode(&root_pub.sha256_hash());
    manifest.members.iter().find(|m| m.signing_pub_hash == hash)
}

fn is_group_admin(
    record: &GroupRecord,
    device_id: &str,
    now_unix: u64,
    root_crl: Option<&RevocationList>,
) -> bool {
    let manifest = &record.manifest;
    if ensure_unexpired(manifest, now_unix).is_err() {
        return false;
    }
    let Some(root) = find_root_member(manifest, &record.root_signing_pub) else {
        return false;
    };
    if root.device_id == device_id {
        return true;
    }
    let (Some(grant), Some(encoded)) = (&manifest.admin_grant, &manifest.signer_signing_pub) else {
        return false;
    };
    if manifest.signer_device_id != device_id
        || !manifest.members.iter().any(|m| m.device_id == device_id)
    {
        return false;
    }
    let Ok(signer_pub) = HybridSigningPublicKey::from_b64url(encoded) else {
        return false;
    };
    verify_admin_grant(
        grant,
        device_id,
        &root.device_id,
        &record.root_signing_pub,
        &signer_pub,
        &manifest.group_id,
        now_unix,
        root_crl,
    )
    .is_ok()
}

/// Timing parameters for the builder helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupBuildParams {
    pub now_unix: u64,
    pub validity_secs: u64,
}

impl GroupBuildParams {
    #[must_use]
    pub const fn new(now_unix: u64) -> Self {
        Self {
            now_unix,
            validity_secs: DEFAULT_MANIFEST_VALIDITY_SECS,
        }
    }

    #[must_use]
    pub const fn with_validity_secs(mut self, validity_secs: u64) -> Self {
        self.validity_secs = validity_secs;
        self
    }
}

/// Admin-side signing identity: the founding root, or a co-admin with its `admin_grant`.
pub struct GroupSigner<'a> {
    signing_key: &'a SigningKeypair,
    co_admin: Option<(String, Grant)>,
    deterministic: bool,
}

impl<'a> GroupSigner<'a> {
    /// Signs as the founding root device.
    #[must_use]
    pub const fn root(signing_key: &'a SigningKeypair) -> Self {
        Self {
            signing_key,
            co_admin: None,
            deterministic: false,
        }
    }

    /// Signs as a co-admin holding a root-issued `admin_grant`.
    #[must_use]
    pub fn co_admin(
        signing_key: &'a SigningKeypair,
        device_id: impl Into<String>,
        admin_grant: Grant,
    ) -> Self {
        Self {
            signing_key,
            co_admin: Some((device_id.into(), admin_grant)),
            deterministic: false,
        }
    }

    /// Switches to deterministic signatures for reproducible vectors.
    #[must_use]
    pub const fn deterministic(mut self) -> Self {
        self.deterministic = true;
        self
    }
}

fn expiry_for(params: GroupBuildParams) -> Result<(String, String), CoreError> {
    if params.validity_secs == 0 || params.validity_secs > MAX_MANIFEST_VALIDITY_SECS {
        return Err(invalid("validity must be in 1..=90 days"));
    }
    Ok((
        format_rfc3339_utc(params.now_unix)?,
        format_rfc3339_utc(params.now_unix.saturating_add(params.validity_secs))?,
    ))
}

fn root_device_of(
    members: &[GroupMember],
    root_pub: &HybridSigningPublicKey,
) -> Result<String, CoreError> {
    let hash = b64url_encode(&root_pub.sha256_hash());
    members
        .iter()
        .find(|m| m.signing_pub_hash == hash)
        .map(|m| m.device_id.clone())
        .ok_or_else(|| invalid("founding root device missing from members"))
}

#[allow(clippy::too_many_arguments)]
fn assemble_and_sign(
    group_id: String,
    name: String,
    seq: u64,
    min_wire_version: u8,
    root_pub: &HybridSigningPublicKey,
    members: Vec<GroupMember>,
    revoked_members: Vec<String>,
    signer: &GroupSigner<'_>,
    params: GroupBuildParams,
) -> Result<GroupManifest, CoreError> {
    let (ts, expires_at) = expiry_for(params)?;
    let root_device_id = root_device_of(&members, root_pub)?;
    let (signer_device_id, signer_signing_pub, admin_grant) = match &signer.co_admin {
        None => {
            if signer.signing_key.public_key() != root_pub {
                return Err(invalid("root signer key does not match the group root"));
            }
            (root_device_id, None, None)
        }
        Some((id, grant)) => (
            id.clone(),
            Some(signer.signing_key.public_key().to_b64url()),
            Some(grant.clone()),
        ),
    };
    let unsigned = GroupManifestUnsigned {
        v: GROUP_MANIFEST_VERSION,
        group_id,
        name,
        seq,
        min_wire_version,
        ts,
        expires_at,
        root_signing_pub: root_pub.to_b64url(),
        signer_device_id,
        signer_signing_pub,
        admin_grant,
        members,
        revoked_members,
    };
    let manifest = if signer.deterministic {
        sign_group_manifest_deterministic(unsigned, signer.signing_key)?
    } else {
        sign_group_manifest(unsigned, signer.signing_key)?
    };
    verify_group_manifest(&manifest, params.now_unix, None)?;
    Ok(manifest)
}

/// Creates a group rooted at `root_signing` with `seq = 1` and a fresh rendezvous key.
///
/// `root_member` must be the root device entry (`signing_pub_hash` and `relay_pub` derived from
/// `root_signing`, for example via [`GroupMember::new`]).
pub fn create_group(
    root_signing: &SigningKeypair,
    name: &str,
    min_wire_version: u8,
    root_member: GroupMember,
    params: GroupBuildParams,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    create_group_with_signer(
        &GroupSigner::root(root_signing),
        name,
        min_wire_version,
        root_member,
        params,
        V2GroupSecrets::generate(1)?,
    )
}

/// Like [`create_group`] with an explicit signer and secrets, for deterministic vectors.
pub fn create_group_with_signer(
    signer: &GroupSigner<'_>,
    name: &str,
    min_wire_version: u8,
    root_member: GroupMember,
    params: GroupBuildParams,
    secrets: V2GroupSecrets,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    if signer.co_admin.is_some() {
        return Err(invalid("only the root can create a group"));
    }
    let root_pub = signer.signing_key.public_key();
    let group_id = group_id_from_root(root_pub);
    let manifest = assemble_and_sign(
        group_id,
        name.to_string(),
        1,
        min_wire_version,
        root_pub,
        vec![root_member],
        Vec::new(),
        signer,
        params,
    )?;
    Ok((manifest, secrets.rebound(1)))
}

fn next_seq(prev: &GroupManifest, secrets: &V2GroupSecrets) -> Result<u64, CoreError> {
    if secrets.seq() != prev.seq {
        return Err(invalid("secrets seq must equal the previous manifest seq"));
    }
    prev.seq
        .checked_add(1)
        .ok_or_else(|| invalid("manifest seq overflow"))
}

fn rebuild(
    prev: &GroupManifest,
    seq: u64,
    min_wire_version: u8,
    members: Vec<GroupMember>,
    revoked: Vec<String>,
    signer: &GroupSigner<'_>,
    params: GroupBuildParams,
) -> Result<GroupManifest, CoreError> {
    let root_pub = HybridSigningPublicKey::from_b64url(&prev.root_signing_pub)?;
    assemble_and_sign(
        prev.group_id.clone(),
        prev.name.clone(),
        seq,
        min_wire_version,
        &root_pub,
        members,
        revoked,
        signer,
        params,
    )
}

/// Adds `member` at `seq + 1`, keeping the rendezvous key and re-binding it to the new `seq`.
pub fn add_member(
    prev: &GroupManifest,
    signer: &GroupSigner<'_>,
    member: GroupMember,
    secrets: &V2GroupSecrets,
    params: GroupBuildParams,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    let seq = next_seq(prev, secrets)?;
    if prev.revoked_members.contains(&member.device_id) {
        return Err(CoreError::GroupMemberRevoked(member.device_id));
    }
    if prev.members.iter().any(|m| m.device_id == member.device_id) {
        return Err(invalid("member already present"));
    }
    let mut members = prev.members.clone();
    members.push(member);
    let manifest = rebuild(
        prev,
        seq,
        prev.min_wire_version,
        members,
        prev.revoked_members.clone(),
        signer,
        params,
    )?;
    Ok((manifest, secrets.rebound(seq)))
}

/// Removes `device_id` at `seq + 1`, revokes it permanently, and rotates the rendezvous key.
pub fn remove_member(
    prev: &GroupManifest,
    signer: &GroupSigner<'_>,
    device_id: &str,
    secrets: &V2GroupSecrets,
    params: GroupBuildParams,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    let rotated_key = Zeroizing::new(random_bytes::<32>()?);
    remove_member_with_key(prev, signer, device_id, secrets, *rotated_key, params)
}

/// Like [`remove_member`] with a caller-supplied rotated key, for deterministic vectors.
pub fn remove_member_with_key(
    prev: &GroupManifest,
    signer: &GroupSigner<'_>,
    device_id: &str,
    secrets: &V2GroupSecrets,
    rotated_key: [u8; 32],
    params: GroupBuildParams,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    let seq = next_seq(prev, secrets)?;
    let root_pub = HybridSigningPublicKey::from_b64url(&prev.root_signing_pub)?;
    if root_device_of(&prev.members, &root_pub)? == device_id {
        return Err(invalid("the founding root device cannot be removed"));
    }
    if !prev.members.iter().any(|m| m.device_id == device_id) {
        return Err(invalid("member not present"));
    }
    let members: Vec<GroupMember> = prev
        .members
        .iter()
        .filter(|m| m.device_id != device_id)
        .cloned()
        .collect();
    let mut revoked = prev.revoked_members.clone();
    revoked.push(device_id.to_string());
    let manifest = rebuild(
        prev,
        seq,
        prev.min_wire_version,
        members,
        revoked,
        signer,
        params,
    )?;
    Ok((manifest, V2GroupSecrets::new(rotated_key, seq)))
}

/// Raises the wire floor at `seq + 1` (never lowers it).
pub fn set_min_wire_version(
    prev: &GroupManifest,
    signer: &GroupSigner<'_>,
    min_wire_version: u8,
    secrets: &V2GroupSecrets,
    params: GroupBuildParams,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    let seq = next_seq(prev, secrets)?;
    if min_wire_version < prev.min_wire_version {
        return Err(CoreError::GroupWireDowngrade {
            current: prev.min_wire_version,
            got: min_wire_version,
        });
    }
    let manifest = rebuild(
        prev,
        seq,
        min_wire_version,
        prev.members.clone(),
        prev.revoked_members.clone(),
        signer,
        params,
    )?;
    Ok((manifest, secrets.rebound(seq)))
}

/// Re-signs the current membership at `seq + 1` with a fresh validity window.
pub fn renew_manifest(
    prev: &GroupManifest,
    signer: &GroupSigner<'_>,
    secrets: &V2GroupSecrets,
    params: GroupBuildParams,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    let seq = next_seq(prev, secrets)?;
    let manifest = rebuild(
        prev,
        seq,
        prev.min_wire_version,
        prev.members.clone(),
        prev.revoked_members.clone(),
        signer,
        params,
    )?;
    Ok((manifest, secrets.rebound(seq)))
}

/// Issues a root-signed grant of `group.admin:<group_id>/<hex(SHA-256(co_admin_signing_pub))>`
/// to `co_admin_device_id`, binding the grant to the co-admin's signing key.
///
/// `live_co_admins` is the number of unexpired, unrevoked admin grants the root has already
/// issued for this group; the root tracks it because verification does not count co-admins.
pub fn issue_admin_grant(
    root_signing: &SigningKeypair,
    root_device_id: &str,
    group_id: &str,
    co_admin_device_id: &str,
    co_admin_signing_pub: &HybridSigningPublicKey,
    live_co_admins: usize,
    params: GroupBuildParams,
) -> Result<Grant, CoreError> {
    let nonce = b64url_encode(&random_bytes::<16>()?);
    issue_admin_grant_impl(
        root_signing,
        root_device_id,
        group_id,
        co_admin_device_id,
        co_admin_signing_pub,
        live_co_admins,
        params,
        nonce,
        false,
    )
}

/// Deterministic variant of [`issue_admin_grant`] with a caller-supplied nonce, for vectors.
#[allow(clippy::too_many_arguments)]
pub fn issue_admin_grant_deterministic(
    root_signing: &SigningKeypair,
    root_device_id: &str,
    group_id: &str,
    co_admin_device_id: &str,
    co_admin_signing_pub: &HybridSigningPublicKey,
    live_co_admins: usize,
    params: GroupBuildParams,
    nonce: [u8; 16],
) -> Result<Grant, CoreError> {
    issue_admin_grant_impl(
        root_signing,
        root_device_id,
        group_id,
        co_admin_device_id,
        co_admin_signing_pub,
        live_co_admins,
        params,
        b64url_encode(&nonce),
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_admin_grant_impl(
    root_signing: &SigningKeypair,
    root_device_id: &str,
    group_id: &str,
    co_admin_device_id: &str,
    co_admin_signing_pub: &HybridSigningPublicKey,
    live_co_admins: usize,
    params: GroupBuildParams,
    nonce: String,
    deterministic: bool,
) -> Result<Grant, CoreError> {
    if live_co_admins >= MAX_GROUP_CO_ADMINS {
        return Err(CoreError::GroupUnauthorized(
            "co-admin limit reached".to_string(),
        ));
    }
    if !is_valid_group_id(group_id) || group_id_from_root(root_signing.public_key()) != group_id {
        return Err(invalid("group_id does not match the root signing key"));
    }
    let (not_before, not_after) = expiry_for(params)?;
    let unsigned = GrantUnsigned {
        v: 1,
        issuer: root_device_id.to_string(),
        subject: co_admin_device_id.to_string(),
        caps: vec![admin_cap_for(group_id, co_admin_signing_pub)],
        not_before,
        not_after,
        nonce,
        delegated_from: Vec::new(),
        uses: None,
        machine: None,
    };
    if deterministic {
        sign_grant_deterministic(unsigned, root_signing)
    } else {
        sign_grant(unsigned, root_signing)
    }
}
