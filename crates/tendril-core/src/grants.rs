//! Capability grammar, RFC 8785 JCS grant signing, subset delegation, and CRL checks.

use std::collections::HashSet;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};

use crate::crypto::{b64url_decode_array, b64url_encode};
use crate::error::CoreError;
use crate::identity::parse_rfc3339_utc;

/// 17-byte domain prefix prepended to JCS canonical grant bytes before signing.
pub const GRANT_DOMAIN: &[u8] = b"tendril-grant-v1\0";

/// 15-byte domain prefix prepended to JCS canonical CRL bytes before signing.
pub const CRL_DOMAIN: &[u8] = b"tendril-crl-v1\0";

/// Default maximum delegation chain depth.
pub const MAX_DELEGATION_DEPTH: usize = 4;

/// Maximum tolerated clock skew before `not_before` in seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Parsed capability string `namespace.verb[:resource]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub namespace: String,
    pub verb: String,
    pub resource: Option<String>,
}

impl Capability {
    /// Strictly parses `namespace.verb` or `namespace.verb:resource`.
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        let (action, resource) = match raw.split_once(':') {
            Some((a, r)) => (a, Some(r)),
            None => (raw, None),
        };
        let (namespace, verb) = action
            .split_once('.')
            .ok_or_else(|| CoreError::InvalidCapability(raw.to_string()))?;

        if !is_valid_ident(namespace) || !is_valid_ident(verb) {
            return Err(CoreError::InvalidCapability(raw.to_string()));
        }

        if let Some(res) = resource {
            if res.is_empty() || !res.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
                return Err(CoreError::InvalidCapability(raw.to_string()));
            }
            if let Some(star_pos) = res.find('*')
                && star_pos != res.len() - 1
            {
                return Err(CoreError::InvalidCapability(raw.to_string()));
            }
        }

        Ok(Self {
            namespace: namespace.to_string(),
            verb: verb.to_string(),
            resource: resource.map(ToString::to_string),
        })
    }

    /// Reports whether `self` (as a granted capability) covers `requested`.
    #[must_use]
    pub fn covers(&self, requested: &Self) -> bool {
        if self.namespace != requested.namespace || self.verb != requested.verb {
            return false;
        }
        match (&self.resource, &requested.resource) {
            (None, None) => true,
            (Some(granted_res), Some(req_res)) => match granted_res.strip_suffix('*') {
                None => !req_res.ends_with('*') && granted_res == req_res,
                Some(granted_prefix) => {
                    let req_target = req_res.strip_suffix('*').unwrap_or(req_res);
                    req_target.starts_with(granted_prefix)
                }
            },
            _ => false,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.resource {
            Some(r) => write!(f, "{}.{}:{}", self.namespace, self.verb, r),
            None => write!(f, "{}.{}", self.namespace, self.verb),
        }
    }
}

fn is_valid_ident(s: &str) -> bool {
    if s.is_empty() || s.len() > 32 {
        return false;
    }
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn deserialize_non_empty_delegated_from<'de, D>(deserializer: D) -> Result<Vec<Grant>, D::Error>
where
    D: Deserializer<'de>,
{
    let items = Vec::<Grant>::deserialize(deserializer)?;
    if items.is_empty() {
        return Err(serde::de::Error::custom(
            "empty delegated_from array must be omitted from canonical grant JSON",
        ));
    }
    Ok(items)
}

fn deserialize_some_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<u64>::deserialize(deserializer)?
        .ok_or_else(|| {
            serde::de::Error::custom("null uses field must be omitted from canonical grant JSON")
        })
        .map(Some)
}

fn deserialize_some_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<bool>::deserialize(deserializer)?
        .ok_or_else(|| {
            serde::de::Error::custom("null machine field must be omitted from canonical grant JSON")
        })
        .map(Some)
}

/// Unsigned capability grant body used for canonical JSON serialization and signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantUnsigned {
    pub v: u8,
    pub issuer: String,
    pub subject: String,
    pub caps: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub nonce: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_non_empty_delegated_from"
    )]
    pub delegated_from: Vec<Grant>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some_u64"
    )]
    pub uses: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some_bool"
    )]
    pub machine: Option<bool>,
}

/// Signed capability grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub v: u8,
    pub issuer: String,
    pub subject: String,
    pub caps: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub nonce: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_non_empty_delegated_from"
    )]
    pub delegated_from: Vec<Grant>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some_u64"
    )]
    pub uses: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_some_bool"
    )]
    pub machine: Option<bool>,
    pub sig: String,
}

impl Grant {
    /// Extracts the unsigned portion of this grant.
    #[must_use]
    pub fn unsigned(&self) -> GrantUnsigned {
        GrantUnsigned {
            v: self.v,
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            caps: self.caps.clone(),
            not_before: self.not_before.clone(),
            not_after: self.not_after.clone(),
            nonce: self.nonce.clone(),
            delegated_from: self.delegated_from.clone(),
            uses: self.uses,
            machine: self.machine,
        }
    }
}

/// Unsigned revocation list body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationListUnsigned {
    pub v: u8,
    pub issuer: String,
    pub seq: u64,
    pub revoked_devices: Vec<String>,
    pub revoked_nonces: Vec<String>,
    pub ts: String,
}

/// Signed revocation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    pub v: u8,
    pub issuer: String,
    pub seq: u64,
    pub revoked_devices: Vec<String>,
    pub revoked_nonces: Vec<String>,
    pub ts: String,
    pub sig: String,
}

impl RevocationList {
    /// Extracts the unsigned portion of this revocation list.
    #[must_use]
    pub fn unsigned(&self) -> RevocationListUnsigned {
        RevocationListUnsigned {
            v: self.v,
            issuer: self.issuer.clone(),
            seq: self.seq,
            revoked_devices: self.revoked_devices.clone(),
            revoked_nonces: self.revoked_nonces.clone(),
            ts: self.ts.clone(),
        }
    }
}

/// Serializes any `Serialize` value to RFC 8785 JCS canonical JSON.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, CoreError> {
    serde_json_canonicalizer::to_string(value)
        .map_err(|err| CoreError::CanonicalJson(err.to_string()))
}

/// Builds `"tendril-grant-v1\0" || RFC8785_JCS(unsigned)`.
pub fn grant_signed_bytes(unsigned: &GrantUnsigned) -> Result<Vec<u8>, CoreError> {
    let jcs = canonical_json(unsigned)?;
    let mut out = Vec::with_capacity(GRANT_DOMAIN.len() + jcs.len());
    out.extend_from_slice(GRANT_DOMAIN);
    out.extend_from_slice(jcs.as_bytes());
    Ok(out)
}

/// Signs a capability grant using `signing_key`.
pub fn sign_grant(unsigned: GrantUnsigned, signing_key: &SigningKey) -> Result<Grant, CoreError> {
    let msg = grant_signed_bytes(&unsigned)?;
    let sig: Signature = signing_key.sign(&msg);
    Ok(Grant {
        v: unsigned.v,
        issuer: unsigned.issuer,
        subject: unsigned.subject,
        caps: unsigned.caps,
        not_before: unsigned.not_before,
        not_after: unsigned.not_after,
        nonce: unsigned.nonce,
        delegated_from: unsigned.delegated_from,
        uses: unsigned.uses,
        machine: unsigned.machine,
        sig: b64url_encode(&sig.to_bytes()),
    })
}

/// Strictly verifies a grant signature against `issuer_signing_pub`.
pub fn verify_grant_signature(
    grant: &Grant,
    issuer_signing_pub: &[u8; 32],
) -> Result<(), CoreError> {
    let sig_bytes: [u8; 64] = b64url_decode_array(&grant.sig)?;
    let vk =
        VerifyingKey::from_bytes(issuer_signing_pub).map_err(|_| CoreError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = grant_signed_bytes(&grant.unsigned())?;
    vk.verify_strict(&msg, &sig)
        .map_err(|_| CoreError::InvalidSignature)
}

/// Checks that `child` is a valid subset delegation of `parent` (syntax, `pair.mint`, time, caps).
pub fn verify_delegation_subset(child: &Grant, parent: &Grant) -> Result<(), CoreError> {
    if child.v != 1 || parent.v != 1 {
        return Err(CoreError::DelegationDenied(
            "unsupported grant version".to_string(),
        ));
    }
    if child.issuer != parent.subject {
        return Err(CoreError::DelegationDenied(
            "child issuer must equal parent subject".to_string(),
        ));
    }

    let parent_caps = parse_caps(&parent.caps)?;
    let child_caps = parse_caps(&child.caps)?;
    let mint_cap = Capability::parse("pair.mint")?;

    if !parent_caps.iter().any(|c| c.covers(&mint_cap)) {
        return Err(CoreError::DelegationDenied(
            "parent grant lacks pair.mint".to_string(),
        ));
    }

    let child_nb = parse_rfc3339_utc(&child.not_before)?;
    let child_na = parse_rfc3339_utc(&child.not_after)?;
    let parent_nb = parse_rfc3339_utc(&parent.not_before)?;
    let parent_na = parse_rfc3339_utc(&parent.not_after)?;

    if child_nb < parent_nb || child_na > parent_na || child_nb >= child_na {
        return Err(CoreError::DelegationDenied(
            "child validity window exceeds parent window".to_string(),
        ));
    }

    for req in &child_caps {
        if !parent_caps.iter().any(|p| p.covers(req)) {
            return Err(CoreError::DelegationDenied(format!(
                "capability {req} is not covered by parent"
            )));
        }
    }

    Ok(())
}

/// Validates a full delegation chain recursively (structural bounds, subject, time, CRL,
/// root authority, signatures, subset rules).
///
/// When `crl` is `Some(list)`, this verifies `list.v == 1`, `list.issuer == expected_root_issuer`,
/// valid whole-second UTC `list.ts`, and `verify_crl_signature(list, root_pub)` using the key
/// returned by `lookup_issuer_key(expected_root_issuer)`. Stateful callers persisting CRL history
/// MUST also enforce monotonic `list.seq` via `Roster::ingest_crl`.
pub fn verify_grant_with_chain<F>(
    grant: &Grant,
    expected_subject: &str,
    expected_root_issuer: &str,
    now_unix: u64,
    crl: Option<&RevocationList>,
    mut lookup_issuer_key: F,
) -> Result<(), CoreError>
where
    F: FnMut(&str) -> Option<[u8; 32]>,
{
    if let Some(list) = crl {
        if list.v != 1 {
            return Err(CoreError::CrlUnsupportedVersion(list.v));
        }
        if list.issuer != expected_root_issuer {
            return Err(CoreError::CrlIssuerMismatch {
                expected: expected_root_issuer.to_string(),
                got: list.issuer.clone(),
            });
        }
        let root_pub = lookup_issuer_key(expected_root_issuer).ok_or_else(|| {
            CoreError::GrantDenied("unknown or inactive root issuer for CRL".to_string())
        })?;
        verify_crl_signature(list, &root_pub)?;
    }

    let mut seen_nonces = HashSet::new();
    let mut seen_subjects = HashSet::new();
    verify_grant_node(
        grant,
        Some(expected_subject),
        expected_root_issuer,
        now_unix,
        crl,
        0,
        &mut seen_nonces,
        &mut seen_subjects,
        &mut lookup_issuer_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_grant_node<F>(
    grant: &Grant,
    expected_subject: Option<&str>,
    expected_root_issuer: &str,
    now_unix: u64,
    crl: Option<&RevocationList>,
    depth: usize,
    seen_nonces: &mut HashSet<String>,
    seen_subjects: &mut HashSet<String>,
    lookup_issuer_key: &mut F,
) -> Result<(), CoreError>
where
    F: FnMut(&str) -> Option<[u8; 32]>,
{
    if depth > MAX_DELEGATION_DEPTH {
        return Err(CoreError::DelegationDenied(
            "delegation depth exceeded".to_string(),
        ));
    }
    if grant.v != 1 || grant.nonce.is_empty() {
        return Err(CoreError::GrantDenied(
            "invalid grant version or nonce".to_string(),
        ));
    }
    if !seen_nonces.insert(grant.nonce.clone()) {
        return Err(CoreError::DelegationDenied(
            "delegation nonce cycle".to_string(),
        ));
    }
    if !seen_subjects.insert(grant.subject.clone()) {
        return Err(CoreError::DelegationDenied(
            "delegation subject cycle".to_string(),
        ));
    }
    parse_caps(&grant.caps)?;

    if let Some(subj) = expected_subject
        && grant.subject != subj
    {
        return Err(CoreError::GrantDenied("grant subject mismatch".to_string()));
    }

    let nb = parse_rfc3339_utc(&grant.not_before)?;
    let na = parse_rfc3339_utc(&grant.not_after)?;
    if now_unix < nb.saturating_sub(MAX_CLOCK_SKEW_SECS) || now_unix >= na || nb >= na {
        return Err(CoreError::GrantDenied(
            "grant outside validity window".to_string(),
        ));
    }

    if let Some(list) = crl {
        if list
            .revoked_devices
            .iter()
            .any(|d| d == &grant.subject || d == &grant.issuer)
        {
            return Err(CoreError::GrantDenied("device is revoked".to_string()));
        }
        if list.revoked_nonces.iter().any(|n| n == &grant.nonce) {
            return Err(CoreError::GrantDenied("grant nonce is revoked".to_string()));
        }
    }

    if grant.delegated_from.is_empty() {
        if grant.issuer != expected_root_issuer {
            return Err(CoreError::GrantDenied(
                "root grant issuer is not authoritative".to_string(),
            ));
        }
    } else if grant.delegated_from.len() != 1 {
        return Err(CoreError::DelegationDenied(
            "delegated_from chain must contain immediate parent at each link".to_string(),
        ));
    }

    let issuer_key = lookup_issuer_key(&grant.issuer)
        .ok_or_else(|| CoreError::GrantDenied("unknown or inactive issuer".to_string()))?;
    verify_grant_signature(grant, &issuer_key)?;

    if let Some(parent) = grant.delegated_from.first() {
        verify_delegation_subset(grant, parent)?;
        verify_grant_node(
            parent,
            Some(&grant.issuer),
            expected_root_issuer,
            now_unix,
            crl,
            depth + 1,
            seen_nonces,
            seen_subjects,
            lookup_issuer_key,
        )?;
    }

    Ok(())
}

/// Structured authorization audit record emitted on every grant evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: u64,
    pub subject: String,
    pub cap: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_nonce: Option<String>,
    pub allow: bool,
    pub reason: String,
}

/// Evaluates `grant` for `requested_cap` (fail-closed) and always emits a structured [`AuditEvent`].
pub fn authorize_grant<F>(
    grant: Option<&Grant>,
    expected_subject: &str,
    expected_root_issuer: &str,
    requested_cap: &str,
    now_unix: u64,
    crl: Option<&RevocationList>,
    lookup_issuer_key: F,
) -> (Result<(), CoreError>, AuditEvent)
where
    F: FnMut(&str) -> Option<[u8; 32]>,
{
    let deny = |err: CoreError, nonce: Option<String>| -> (Result<(), CoreError>, AuditEvent) {
        let audit = AuditEvent {
            ts: now_unix,
            subject: expected_subject.to_string(),
            cap: requested_cap.to_string(),
            grant_nonce: nonce,
            allow: false,
            reason: err.to_string(),
        };
        (Err(err), audit)
    };

    let Some(g) = grant else {
        return deny(
            CoreError::GrantDenied("missing capability grant".to_string()),
            None,
        );
    };
    let nonce = Some(g.nonce.clone());

    if let Err(err) = verify_grant_with_chain(
        g,
        expected_subject,
        expected_root_issuer,
        now_unix,
        crl,
        lookup_issuer_key,
    ) {
        return deny(err, nonce);
    }

    let req = match Capability::parse(requested_cap) {
        Ok(cap) => cap,
        Err(err) => return deny(err, nonce),
    };

    match grant_allows(g, &req) {
        Ok(true) => (
            Ok(()),
            AuditEvent {
                ts: now_unix,
                subject: expected_subject.to_string(),
                cap: requested_cap.to_string(),
                grant_nonce: nonce,
                allow: true,
                reason: "allowed".to_string(),
            },
        ),
        Ok(false) => deny(
            CoreError::GrantDenied(format!("capability {requested_cap} not granted")),
            nonce,
        ),
        Err(err) => deny(err, nonce),
    }
}

/// Checks if a grant covers `requested` (without re-verifying signatures; run after [`verify_grant_with_chain`]).
pub fn grant_allows(grant: &Grant, requested: &Capability) -> Result<bool, CoreError> {
    let caps = parse_caps(&grant.caps)?;
    Ok(caps.iter().any(|c| c.covers(requested)))
}

fn parse_caps(raw: &[String]) -> Result<Vec<Capability>, CoreError> {
    raw.iter().map(|s| Capability::parse(s)).collect()
}

/// Builds `"tendril-crl-v1\0" || RFC8785_JCS(unsigned)`.
pub fn crl_signed_bytes(unsigned: &RevocationListUnsigned) -> Result<Vec<u8>, CoreError> {
    let jcs = canonical_json(unsigned)?;
    let mut out = Vec::with_capacity(CRL_DOMAIN.len() + jcs.len());
    out.extend_from_slice(CRL_DOMAIN);
    out.extend_from_slice(jcs.as_bytes());
    Ok(out)
}

/// Signs a [`RevocationListUnsigned`] using `signing_key`.
pub fn sign_crl(
    unsigned: RevocationListUnsigned,
    signing_key: &SigningKey,
) -> Result<RevocationList, CoreError> {
    let msg = crl_signed_bytes(&unsigned)?;
    let sig: Signature = signing_key.sign(&msg);
    Ok(RevocationList {
        v: unsigned.v,
        issuer: unsigned.issuer,
        seq: unsigned.seq,
        revoked_devices: unsigned.revoked_devices,
        revoked_nonces: unsigned.revoked_nonces,
        ts: unsigned.ts,
        sig: b64url_encode(&sig.to_bytes()),
    })
}

/// Strictly verifies a [`RevocationList`] signature and whole-second UTC timestamp against
/// `issuer_signing_pub`.
pub fn verify_crl_signature(
    crl: &RevocationList,
    issuer_signing_pub: &[u8; 32],
) -> Result<(), CoreError> {
    parse_rfc3339_utc(&crl.ts)?;
    let sig_bytes: [u8; 64] = b64url_decode_array(&crl.sig)?;
    let vk =
        VerifyingKey::from_bytes(issuer_signing_pub).map_err(|_| CoreError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = crl_signed_bytes(&crl.unsigned())?;
    vk.verify_strict(&msg, &sig)
        .map_err(|_| CoreError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_signer(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn mk_grant(
        sk: &SigningKey,
        issuer: &str,
        subject: &str,
        caps: Vec<&str>,
        nonce: &str,
        delegated_from: Vec<Grant>,
    ) -> Grant {
        sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: issuer.to_string(),
                subject: subject.to_string(),
                caps: caps.into_iter().map(str::to_string).collect(),
                not_before: "2026-11-20T00:00:00Z".to_string(),
                not_after: "2026-12-20T00:00:00Z".to_string(),
                nonce: nonce.to_string(),
                delegated_from,
                uses: None,
                machine: None,
            },
            sk,
        )
        .unwrap()
    }

    #[test]
    fn rejects_delegation_subject_cycle_with_distinct_nonces() {
        let (sk_root, pk_root) = mk_signer(0x01);
        let (sk_a, pk_a) = mk_signer(0x02);
        let (sk_b, pk_b) = mk_signer(0x03);

        let g_root = mk_grant(
            &sk_root,
            "dev_root",
            "dev_a",
            vec!["pair.mint", "fs.read:*"],
            "nc_1",
            vec![],
        );
        let g_ab = mk_grant(
            &sk_a,
            "dev_a",
            "dev_b",
            vec!["pair.mint", "fs.read:*"],
            "nc_2",
            vec![g_root],
        );
        let g_ba = mk_grant(
            &sk_b,
            "dev_b",
            "dev_a",
            vec!["fs.read:/a"],
            "nc_3",
            vec![g_ab],
        );

        let lookup = |issuer: &str| match issuer {
            "dev_root" => Some(pk_root),
            "dev_a" => Some(pk_a),
            "dev_b" => Some(pk_b),
            _ => None,
        };

        let now = parse_rfc3339_utc("2026-11-25T00:00:00Z").unwrap();
        let res = verify_grant_with_chain(&g_ba, "dev_a", "dev_root", now, None, lookup);
        assert!(matches!(res, Err(CoreError::DelegationDenied(_))));
    }

    #[test]
    fn validates_clock_skew_and_validity_window_boundaries() {
        let (sk_root, pk_root) = mk_signer(0x10);
        let root_g = mk_grant(
            &sk_root,
            "dev_root",
            "dev_leaf",
            vec!["session.open"],
            "skew_n1",
            vec![],
        );
        let nb = parse_rfc3339_utc(&root_g.not_before).unwrap();
        let na = parse_rfc3339_utc(&root_g.not_after).unwrap();
        let lookup = |issuer: &str| (issuer == "dev_root").then_some(pk_root);

        assert!(
            verify_grant_with_chain(
                &root_g,
                "dev_leaf",
                "dev_root",
                nb - MAX_CLOCK_SKEW_SECS,
                None,
                lookup
            )
            .is_ok()
        );
        assert!(matches!(
            verify_grant_with_chain(
                &root_g,
                "dev_leaf",
                "dev_root",
                nb - MAX_CLOCK_SKEW_SECS - 1,
                None,
                lookup
            ),
            Err(CoreError::GrantDenied(_))
        ));
        assert!(
            verify_grant_with_chain(&root_g, "dev_leaf", "dev_root", na - 1, None, lookup).is_ok()
        );
        assert!(matches!(
            verify_grant_with_chain(&root_g, "dev_leaf", "dev_root", na, None, lookup),
            Err(CoreError::GrantDenied(_))
        ));
    }

    #[test]
    fn enforces_crl_revocations_across_subject_issuer_and_ancestor_nonces() {
        let (sk_root, pk_root) = mk_signer(0x20);
        let (sk_del, pk_del) = mk_signer(0x21);
        let g_root = mk_grant(
            &sk_root,
            "dev_root",
            "dev_del",
            vec!["pair.mint", "fs.read:*"],
            "anc_n1",
            vec![],
        );
        let g_leaf = mk_grant(
            &sk_del,
            "dev_del",
            "dev_leaf",
            vec!["fs.read:/a"],
            "leaf_n1",
            vec![g_root],
        );
        let lookup = |issuer: &str| match issuer {
            "dev_root" => Some(pk_root),
            "dev_del" => Some(pk_del),
            _ => None,
        };
        let now = parse_rfc3339_utc("2026-11-25T00:00:00Z").unwrap();

        let mk_crl = |devs: Vec<&str>, nonces: Vec<&str>| {
            sign_crl(
                RevocationListUnsigned {
                    v: 1,
                    issuer: "dev_root".to_string(),
                    seq: 1,
                    revoked_devices: devs.into_iter().map(str::to_string).collect(),
                    revoked_nonces: nonces.into_iter().map(str::to_string).collect(),
                    ts: "2026-11-22T00:00:00Z".to_string(),
                },
                &sk_root,
            )
            .unwrap()
        };

        let crl_subj = mk_crl(vec!["dev_leaf"], vec![]);
        assert!(matches!(
            verify_grant_with_chain(
                &g_leaf,
                "dev_leaf",
                "dev_root",
                now,
                Some(&crl_subj),
                lookup
            ),
            Err(CoreError::GrantDenied(_))
        ));
        let crl_issuer = mk_crl(vec!["dev_del"], vec![]);
        assert!(matches!(
            verify_grant_with_chain(
                &g_leaf,
                "dev_leaf",
                "dev_root",
                now,
                Some(&crl_issuer),
                lookup
            ),
            Err(CoreError::GrantDenied(_))
        ));
        let crl_nonce = mk_crl(vec![], vec!["anc_n1"]);
        assert!(matches!(
            verify_grant_with_chain(
                &g_leaf,
                "dev_leaf",
                "dev_root",
                now,
                Some(&crl_nonce),
                lookup
            ),
            Err(CoreError::GrantDenied(_))
        ));
    }

    #[test]
    fn rejects_delegation_depth_cycles_arity_mint_window_and_syntax() {
        let signers: Vec<(SigningKey, [u8; 32], String)> = (0u8..=6)
            .map(|i| {
                let (sk, pk) = mk_signer(0x30 + i);
                (sk, pk, format!("dev_{i}"))
            })
            .collect();
        let lookup = |issuer: &str| -> Option<[u8; 32]> {
            signers
                .iter()
                .find(|(_, _, id)| id == issuer)
                .map(|(_, pk, _)| *pk)
        };
        let now = parse_rfc3339_utc("2026-11-25T00:00:00Z").unwrap();

        // Build chain of 5 delegations (depth 0..=5 -> exceeds MAX_DELEGATION_DEPTH = 4).
        let g0 = mk_grant(
            &signers[0].0,
            "dev_0",
            "dev_1",
            vec!["pair.mint", "fs.read:*"],
            "dn0",
            vec![],
        );
        let g1 = mk_grant(
            &signers[1].0,
            "dev_1",
            "dev_2",
            vec!["pair.mint", "fs.read:*"],
            "dn1",
            vec![g0.clone()],
        );
        let g2 = mk_grant(
            &signers[2].0,
            "dev_2",
            "dev_3",
            vec!["pair.mint", "fs.read:*"],
            "dn2",
            vec![g1],
        );
        let g3 = mk_grant(
            &signers[3].0,
            "dev_3",
            "dev_4",
            vec!["pair.mint", "fs.read:*"],
            "dn3",
            vec![g2],
        );
        let g4 = mk_grant(
            &signers[4].0,
            "dev_4",
            "dev_5",
            vec!["pair.mint", "fs.read:/a"],
            "dn4",
            vec![g3],
        );
        // Depth 4 is allowed.
        assert!(verify_grant_with_chain(&g4, "dev_5", "dev_0", now, None, lookup).is_ok());
        // Depth 5 exceeds MAX_DELEGATION_DEPTH = 4.
        let g5 = mk_grant(
            &signers[5].0,
            "dev_5",
            "dev_6",
            vec!["fs.read:/a"],
            "dn5",
            vec![g4],
        );
        assert!(matches!(
            verify_grant_with_chain(&g5, "dev_6", "dev_0", now, None, lookup),
            Err(CoreError::DelegationDenied(_))
        ));

        // Nonce cycle between parent and child.
        let dup_nonce = mk_grant(
            &signers[1].0,
            "dev_1",
            "dev_2",
            vec!["fs.read:/a"],
            "dn0",
            vec![g0.clone()],
        );
        assert!(matches!(
            verify_grant_with_chain(&dup_nonce, "dev_2", "dev_0", now, None, lookup),
            Err(CoreError::DelegationDenied(_))
        ));

        // Multiple entries in delegated_from must be rejected.
        let multi = mk_grant(
            &signers[1].0,
            "dev_1",
            "dev_2",
            vec!["fs.read:/a"],
            "dn_m",
            vec![g0.clone(), g0],
        );
        assert!(matches!(
            verify_grant_with_chain(&multi, "dev_2", "dev_0", now, None, lookup),
            Err(CoreError::DelegationDenied(_))
        ));

        // Parent lacking pair.mint and child widening time window must both be rejected.
        let no_mint = mk_grant(
            &signers[0].0,
            "dev_0",
            "dev_1",
            vec!["fs.read:*"],
            "nm_0",
            vec![],
        );
        let child_of_nomint = mk_grant(
            &signers[1].0,
            "dev_1",
            "dev_2",
            vec!["fs.read:/a"],
            "nm_1",
            vec![no_mint],
        );
        assert!(matches!(
            verify_grant_with_chain(&child_of_nomint, "dev_2", "dev_0", now, None, lookup),
            Err(CoreError::DelegationDenied(_))
        ));

        let with_mint = mk_grant(
            &signers[0].0,
            "dev_0",
            "dev_1",
            vec!["pair.mint", "fs.read:*"],
            "wm_0",
            vec![],
        );
        let wider_time = sign_grant(
            GrantUnsigned {
                v: 1,
                issuer: "dev_1".to_string(),
                subject: "dev_2".to_string(),
                caps: vec!["fs.read:/a".to_string()],
                not_before: "2026-11-19T00:00:00Z".to_string(),
                not_after: "2026-12-20T00:00:00Z".to_string(),
                nonce: "wt_1".to_string(),
                delegated_from: vec![with_mint],
                uses: None,
                machine: None,
            },
            &signers[1].0,
        )
        .unwrap();
        assert!(matches!(
            verify_grant_with_chain(&wider_time, "dev_2", "dev_0", now, None, lookup),
            Err(CoreError::DelegationDenied(_))
        ));

        // Capability syntax edge cases.
        for bad_cap in ["fs", "Fs.read", "fs.read:", "fs.read:a b", "fs.read:/*.txt"] {
            assert!(
                matches!(
                    Capability::parse(bad_cap),
                    Err(CoreError::InvalidCapability(_))
                ),
                "expected InvalidCapability for {bad_cap}"
            );
        }

        // CRL signature verification rejects non-whole-second timestamps.
        let (sk_crl, pk_crl) = mk_signer(0x55);
        let bad_crl = sign_crl(
            RevocationListUnsigned {
                v: 1,
                issuer: "dev_root".to_string(),
                seq: 1,
                revoked_devices: vec![],
                revoked_nonces: vec![],
                ts: "2026-11-22T00:00:00.500Z".to_string(),
            },
            &sk_crl,
        )
        .unwrap();
        assert!(matches!(
            verify_crl_signature(&bad_crl, &pk_crl),
            Err(CoreError::InvalidTimestamp(_))
        ));

        let (sk_auth, pk_auth) = mk_signer(0x66);
        let auth_g = mk_grant(
            &sk_auth,
            "dev_root",
            "dev_leaf",
            vec!["fs.read:/docs/*"],
            "au_1",
            vec![],
        );
        let lookup_auth = |id: &str| (id == "dev_root").then_some(pk_auth);
        let (none_res, none_audit) = authorize_grant(
            None,
            "dev_leaf",
            "dev_root",
            "fs.read:/docs/a.md",
            now,
            None,
            lookup_auth,
        );
        assert!(matches!(none_res, Err(CoreError::GrantDenied(_))));
        assert!(!none_audit.allow);
        assert!(none_audit.grant_nonce.is_none());

        let (ok_res, ok_audit) = authorize_grant(
            Some(&auth_g),
            "dev_leaf",
            "dev_root",
            "fs.read:/docs/a.md",
            now,
            None,
            lookup_auth,
        );
        assert!(ok_res.is_ok());
        assert!(ok_audit.allow);
        assert_eq!(ok_audit.grant_nonce.as_deref(), Some("au_1"));

        let (deny_res, deny_audit) = authorize_grant(
            Some(&auth_g),
            "dev_leaf",
            "dev_root",
            "fs.write:/docs/a.md",
            now,
            None,
            lookup_auth,
        );
        assert!(matches!(deny_res, Err(CoreError::GrantDenied(_))));
        assert!(!deny_audit.allow);
        assert_eq!(deny_audit.grant_nonce.as_deref(), Some("au_1"));
    }
}
