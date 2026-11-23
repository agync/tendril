//! Group administration facade: the one place group create, add, remove, ingest, and forget
//! policy lives, so the CLI and every binding call the same code.
//!
//! Every function takes the [`StateStore`] and runs its book mutation inside one
//! [`StateStore::update_group_book`] transaction. All signing and verification stays in
//! `tendril-core`; this module only checks roster and root authority, then persists the result.

use std::net::SocketAddr;

use tendril_core::crypto::device_id;
use tendril_core::error::CoreError;
use tendril_core::group::{
    GroupBook, GroupBuildParams, GroupIngestOutcome, GroupManifest, GroupMember, GroupSigner,
    V2GroupSecrets, add_member, create_group, group_id_from_root, remove_member,
    resolve_group_peer,
};
use tendril_core::identity::EndpointIdentity;

use super::{
    check_group_capacity, current_unix_secs, ingest_pushed_manifest, require_group_identity,
    root_device_of,
};
use crate::error::RuntimeError;
use crate::store::StateStore;

const ROOT_MEMBER_NAME: &str = "root";

/// Capabilities granted to a member when none are requested: send and receive in `group_id`.
#[must_use]
pub fn default_group_caps(group_id: &str) -> Vec<String> {
    vec![
        format!("group.send:{group_id}"),
        format!("group.recv:{group_id}"),
    ]
}

/// Prefixes a bare `ip:port` socket address with `direct:`; other hints pass through unchanged.
#[must_use]
pub fn normalize_endpoint_hint(hint: String) -> String {
    if hint.parse::<SocketAddr>().is_ok() {
        format!("direct:{hint}")
    } else {
        hint
    }
}

fn normalize_hints(hints: Vec<String>) -> Vec<String> {
    hints.into_iter().map(normalize_endpoint_hint).collect()
}

fn is_local_root(book: &GroupBook, group_id: &str, identity: &EndpointIdentity) -> bool {
    book.root_signing_pub(group_id) == Some(identity.signing_key().public_key())
}

fn root_admin_view(
    book: &GroupBook,
    group_id: &str,
    identity: &EndpointIdentity,
) -> Result<(GroupManifest, V2GroupSecrets), CoreError> {
    let manifest = book
        .manifest(group_id)
        .cloned()
        .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()))?;
    if !is_local_root(book, group_id, identity) {
        return Err(CoreError::GroupUnauthorized(format!(
            "only the group root can change {group_id}"
        )));
    }
    let secrets = book.secrets(group_id).cloned().ok_or_else(|| {
        CoreError::GroupUnauthorized(format!("no rendezvous secrets stored for {group_id}"))
    })?;
    Ok((manifest, secrets))
}

/// Creates a group rooted at `identity` and persists its manifest and rendezvous secrets.
///
/// `min_wire_version` is the wire floor recorded in the manifest. Bare socket addresses in
/// `endpoints` become `direct:` hints. Refuses when this identity already roots the group or
/// when [`check_group_capacity`] fails.
pub fn group_create(
    store: &StateStore,
    identity: &EndpointIdentity,
    name: &str,
    min_wire_version: u8,
    endpoints: Vec<String>,
) -> Result<GroupManifest, RuntimeError> {
    require_group_identity(identity)?;
    let group_id = group_id_from_root(identity.signing_key().public_key());
    let root_member = GroupMember::new(
        identity.static_key().public_bytes(),
        ROOT_MEMBER_NAME,
        identity.signing_key().public_key(),
        normalize_hints(endpoints),
        default_group_caps(&group_id),
    );
    let now = current_unix_secs();
    let (manifest, secrets) = create_group(
        identity.signing_key(),
        name,
        min_wire_version,
        root_member,
        GroupBuildParams::new(now),
    )?;
    let local_id = identity.device_id();
    store.update_group_book(|book| {
        if book.manifest(&group_id).is_some() {
            return Err(CoreError::GroupUnauthorized(format!(
                "this identity already roots {group_id}"
            ))
            .into());
        }
        check_group_capacity(book, &local_id, &group_id)?;
        book.ingest_group_manifest(&manifest, now, None)?;
        book.install_secrets(&group_id, secrets.clone())?;
        Ok(())
    })?;
    Ok(manifest)
}

/// Adds the paired peer `peer_device_id` to a group `identity` roots and returns the new
/// manifest.
///
/// The peer is every roster entry whose stored or static-derived device id is `peer_device_id`
/// (a reverse pairing can leave a host label and a `dev_` entry for one peer): none may be
/// revoked or CRL-revoked, and one must be `Active` with a known signing key. Empty `caps` grant
/// [`default_group_caps`]. Only the group root may add members.
pub fn group_add_member(
    store: &StateStore,
    identity: &EndpointIdentity,
    group_id: &str,
    peer_device_id: &str,
    caps: Vec<String>,
    endpoints: Vec<String>,
) -> Result<GroupManifest, RuntimeError> {
    require_group_identity(identity)?;
    let roster = store.load_roster()?;
    let (_, entry) = resolve_group_peer(
        &roster,
        |e| e.device_id == peer_device_id || device_id(&e.static_pub) == peer_device_id,
        None,
    )
    .map_err(|err| match err {
        CoreError::PeerNotFound(_) => CoreError::PeerNotFound(peer_device_id.to_owned()),
        CoreError::PeerPending(_) => CoreError::PeerPending(peer_device_id.to_owned()),
        CoreError::PeerRevoked(_) => CoreError::PeerRevoked(peer_device_id.to_owned()),
        CoreError::IncompletePin(_) => CoreError::IncompletePin(peer_device_id.to_owned()),
        other => other,
    })?;
    let signing_pub = entry
        .signing_pub
        .as_ref()
        .ok_or_else(|| CoreError::IncompletePin(peer_device_id.to_owned()))?;
    let caps = if caps.is_empty() {
        default_group_caps(group_id)
    } else {
        caps
    };
    let member = GroupMember::new(
        &entry.static_pub,
        entry.name.clone(),
        signing_pub,
        normalize_hints(endpoints),
        caps,
    );
    let now = current_unix_secs();
    store.update_group_book(|book| {
        let (prev, secrets) = root_admin_view(book, group_id, identity)?;
        let (manifest, next_secrets) = add_member(
            &prev,
            &GroupSigner::root(identity.signing_key()),
            member.clone(),
            &secrets,
            GroupBuildParams::new(now),
        )?;
        book.ingest_group_manifest(&manifest, now, None)?;
        book.install_secrets(group_id, next_secrets)?;
        Ok(manifest)
    })
}

/// Revokes `peer_device_id` from a group `identity` roots, rotates the rendezvous key, and
/// returns the new manifest. Only the group root may remove members.
pub fn group_remove_member(
    store: &StateStore,
    identity: &EndpointIdentity,
    group_id: &str,
    peer_device_id: &str,
) -> Result<GroupManifest, RuntimeError> {
    require_group_identity(identity)?;
    let now = current_unix_secs();
    store.update_group_book(|book| {
        let (prev, secrets) = root_admin_view(book, group_id, identity)?;
        let (manifest, next_secrets) = remove_member(
            &prev,
            &GroupSigner::root(identity.signing_key()),
            peer_device_id,
            &secrets,
            GroupBuildParams::new(now),
        )?;
        book.ingest_group_manifest(&manifest, now, None)?;
        book.install_secrets(group_id, next_secrets)?;
        Ok(manifest)
    })
}

/// Parses a manifest from its strict JSON wire form and ingests it as pushed by the
/// authenticated peer `sender_device_id`.
///
/// Unknown fields and oversized input are refused by `tendril-core`; first-contact and
/// capacity rules are those of [`ingest_pushed_manifest`].
pub fn group_ingest_manifest(
    store: &StateStore,
    local_device_id: &str,
    sender_device_id: &str,
    manifest_json: &str,
) -> Result<GroupIngestOutcome, RuntimeError> {
    let manifest = GroupManifest::from_wire_bytes(manifest_json.as_bytes())?;
    ingest_pushed_manifest(store, local_device_id, sender_device_id, &manifest)
}

/// Deletes every record of `group_id`: manifest, rendezvous secrets, group-scoped pairwise
/// secrets, and pins. Refuses for the group root, which must keep its signing authority.
pub fn group_forget(
    store: &StateStore,
    local_device_id: &str,
    group_id: &str,
) -> Result<(), RuntimeError> {
    store.update_group_book(|book| {
        let manifest = book
            .manifest(group_id)
            .ok_or_else(|| CoreError::GroupNotFound(group_id.to_owned()))?;
        if root_device_of(book, manifest).as_deref() == Some(local_device_id) {
            return Err(
                CoreError::GroupUnauthorized(format!("the root cannot forget {group_id}")).into(),
            );
        }
        book.forget_group(group_id);
        Ok(())
    })
}
