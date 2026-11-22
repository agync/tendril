//! Stateless relay admission primitives (HMAC-SHA256 and Ed25519 JCS tickets).

use std::fmt;

use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{b64url_decode_array, b64url_encode, is_valid_ed25519_public_key};
use crate::error::CoreError;
use crate::grants::canonical_json;
use crate::v2::{RELAY_V2_EPOCH_SECS, canonical_relay_host, epoch_for_unix};

type HmacSha256 = Hmac<Sha256>;

/// 22-byte domain prefix prepended to relay shared-secret HMAC admission inputs.
pub const RELAY_AUTH_HMAC_DOMAIN: &[u8] = b"tendril-relay-auth-v1\0";

/// 24-byte domain prefix prepended to RFC 8785 JCS relay ticket bytes before signing.
pub const RELAY_TICKET_DOMAIN: &[u8] = b"tendril-relay-ticket-v1\0";

/// Maximum lifetime (`24` hours) accepted for a signed [`RelayTicket`].
pub const MAX_RELAY_TICKET_TTL_SECS: u64 = 86_400;

/// Clock skew tolerance (`+-30` seconds) around [`RelayTicket`] validity bounds.
pub const RELAY_TICKET_CLOCK_SKEW_SECS: u64 = 30;

/// Maximum accepted length in bytes for a shared relay HMAC secret (`4096` B).
pub const MAX_RELAY_AUTH_SECRET_BYTES: usize = 4_096;

/// Operation role authorized by a [`RelayTicket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAuthRole {
    Register,
    Dial,
    Any,
}

/// Option 1A relay admission enforcement scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayAuthScope {
    All,
    RegisterOnly,
}

impl RelayAuthScope {
    /// Reports whether `dial` requests require an admission proof under this scope.
    #[must_use]
    pub const fn includes_dial(self) -> bool {
        matches!(self, Self::All)
    }
}

/// Stateless Ed25519 capability ticket authorizing relay registration and/or dialing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayTicket {
    pub v: u8,
    pub issuer_pub: String,
    pub relay_host: String,
    pub role: RelayAuthRole,
    pub target_pub: String,
    pub not_before: u64,
    pub not_after: u64,
    pub sig: String,
}

impl RelayTicket {
    /// Returns the ticket lifetime in seconds (`not_after - not_before`).
    #[must_use]
    pub const fn ttl_secs(&self) -> u64 {
        self.not_after.saturating_sub(self.not_before)
    }

    /// Returns `true` when the validity window reaches into a later `/v2/relay` hourly epoch than
    /// it starts in.
    ///
    /// A wildcard (`target_pub = "*"`) ticket is replayable against every mailbox for its whole
    /// TTL, so a relay can link all epochs it spans; a ticket for which this returns `false` and
    /// whose `target_pub` is a concrete epoch `mailbox_id` is confined to a single epoch.
    #[must_use]
    pub const fn spans_multiple_v2_epochs(&self) -> bool {
        self.not_after / RELAY_V2_EPOCH_SECS > self.not_before / RELAY_V2_EPOCH_SECS
    }
}

#[derive(Serialize)]
struct RelayTicketUnsigned<'a> {
    v: u8,
    issuer_pub: &'a str,
    relay_host: &'a str,
    role: RelayAuthRole,
    target_pub: &'a str,
    not_before: u64,
    not_after: u64,
}

/// Wire admission proof carried in the optional `auth` field of relay control requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayAuthProof {
    Hmac { mac: String },
    Ticket { ticket: RelayTicket },
}

/// Zeroizing, debug-redacted wrapper around a shared relay HMAC admission secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RelayAuthSecret(Zeroizing<Vec<u8>>);

impl RelayAuthSecret {
    /// Validates and wraps a shared HMAC secret (`1..=4096` bytes).
    pub fn new(secret: Vec<u8>) -> Result<Self, CoreError> {
        validate_relay_auth_secret(&secret)?;
        Ok(Self(Zeroizing::new(secret)))
    }

    /// Validates and wraps a shared HMAC secret slice (`1..=4096` bytes).
    pub fn from_bytes(secret: &[u8]) -> Result<Self, CoreError> {
        validate_relay_auth_secret(secret)?;
        Ok(Self(Zeroizing::new(secret.to_vec())))
    }

    /// Returns the raw shared secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for RelayAuthSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

impl Eq for RelayAuthSecret {}

impl fmt::Debug for RelayAuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayAuthSecret")
            .field("len", &self.0.len())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Validates that a relay HMAC shared secret is non-empty and within `MAX_RELAY_AUTH_SECRET_BYTES`.
pub fn validate_relay_auth_secret(secret: &[u8]) -> Result<(), CoreError> {
    if secret.is_empty() || secret.len() > MAX_RELAY_AUTH_SECRET_BYTES {
        return Err(CoreError::ProtocolViolation(
            "invalid relay auth secret length",
        ));
    }
    Ok(())
}

/// Validates that `op` is one of `"register"`, `"dial"`, or `"accept"`.
pub fn validate_relay_auth_op(op: &str) -> Result<(), CoreError> {
    match op {
        "register" | "dial" | "accept" => Ok(()),
        _ => Err(CoreError::ProtocolViolation("invalid relay auth op")),
    }
}

/// Builds the domain-separated HMAC input bound to `op`, canonical `relay_host`, `nonce`, and key.
pub fn relay_auth_hmac_input(
    op: &str,
    canonical_host: &str,
    nonce: &[u8; 32],
    pub_or_target: &[u8; 32],
) -> Result<Vec<u8>, CoreError> {
    validate_relay_auth_op(op)?;
    let host = canonical_relay_host(canonical_host)?;
    let mut out = Vec::with_capacity(
        RELAY_AUTH_HMAC_DOMAIN.len()
            + op.len()
            + 1
            + host.len()
            + nonce.len()
            + pub_or_target.len(),
    );
    out.extend_from_slice(RELAY_AUTH_HMAC_DOMAIN);
    out.extend_from_slice(op.as_bytes());
    out.push(0);
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(pub_or_target);
    Ok(out)
}

/// Computes the 32-byte `HMAC-SHA256` relay admission tag.
pub fn compute_relay_auth_hmac(
    secret: &[u8],
    op: &str,
    relay_host: &str,
    nonce: &[u8; 32],
    pub_or_target: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    validate_relay_auth_secret(secret)?;
    let input = relay_auth_hmac_input(op, relay_host, nonce, pub_or_target)?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| CoreError::ProtocolViolation("invalid relay auth secret"))?;
    mac.update(&input);
    Ok(mac.finalize().into_bytes().into())
}

/// Computes the `b64url`-encoded `HMAC-SHA256` relay admission tag.
pub fn compute_relay_auth_hmac_b64(
    secret: &[u8],
    op: &str,
    relay_host: &str,
    nonce: &[u8; 32],
    pub_or_target: &[u8; 32],
) -> Result<String, CoreError> {
    let mac = compute_relay_auth_hmac(secret, op, relay_host, nonce, pub_or_target)?;
    Ok(b64url_encode(&mac))
}

/// Verifies a `b64url`-encoded relay admission `HMAC-SHA256` tag in constant time.
pub fn verify_relay_auth_hmac(
    secret: &[u8],
    op: &str,
    relay_host: &str,
    nonce: &[u8; 32],
    pub_or_target: &[u8; 32],
    candidate_mac_b64: &str,
) -> Result<(), CoreError> {
    let expected = compute_relay_auth_hmac(secret, op, relay_host, nonce, pub_or_target)?;
    let candidate = b64url_decode_array::<32>(candidate_mac_b64)?;
    if !bool::from(expected.ct_eq(&candidate)) {
        return Err(CoreError::InvalidSignature);
    }
    Ok(())
}

fn relay_ticket_unsigned_jcs(unsigned: &RelayTicketUnsigned<'_>) -> Result<String, CoreError> {
    canonical_json(unsigned)
}

fn relay_ticket_unsigned_bytes(unsigned: &RelayTicketUnsigned<'_>) -> Result<Vec<u8>, CoreError> {
    let jcs = relay_ticket_unsigned_jcs(unsigned)?;
    let mut out = Vec::with_capacity(RELAY_TICKET_DOMAIN.len() + jcs.len());
    out.extend_from_slice(RELAY_TICKET_DOMAIN);
    out.extend_from_slice(jcs.as_bytes());
    Ok(out)
}

/// Serializes the unsigned portion of `ticket` to RFC 8785 JCS canonical JSON.
pub fn relay_ticket_jcs(ticket: &RelayTicket) -> Result<String, CoreError> {
    let unsigned = RelayTicketUnsigned {
        v: ticket.v,
        issuer_pub: &ticket.issuer_pub,
        relay_host: &ticket.relay_host,
        role: ticket.role,
        target_pub: &ticket.target_pub,
        not_before: ticket.not_before,
        not_after: ticket.not_after,
    };
    relay_ticket_unsigned_jcs(&unsigned)
}

/// Builds `"tendril-relay-ticket-v1\0" || RFC8785_JCS(unsigned)` for `ticket`.
pub fn relay_ticket_signed_bytes(ticket: &RelayTicket) -> Result<Vec<u8>, CoreError> {
    let unsigned = RelayTicketUnsigned {
        v: ticket.v,
        issuer_pub: &ticket.issuer_pub,
        relay_host: &ticket.relay_host,
        role: ticket.role,
        target_pub: &ticket.target_pub,
        not_before: ticket.not_before,
        not_after: ticket.not_after,
    };
    relay_ticket_unsigned_bytes(&unsigned)
}

/// Mints a signed [`RelayTicket`] using an Ed25519 `signing_key`.
pub fn mint_relay_ticket(
    signing_key: &SigningKey,
    relay_host: &str,
    role: RelayAuthRole,
    target_pub: &str,
    now_unix: u64,
    ttl_secs: u64,
) -> Result<RelayTicket, CoreError> {
    let canon_host = canonical_relay_host(relay_host)?;
    if ttl_secs == 0 || ttl_secs > MAX_RELAY_TICKET_TTL_SECS {
        return Err(CoreError::GrantDenied(
            "relay ticket ttl must be within 1..=86400 seconds".to_string(),
        ));
    }
    let not_after = now_unix.checked_add(ttl_secs).ok_or_else(|| {
        CoreError::GrantDenied("relay ticket not_after timestamp overflow".to_string())
    })?;
    if target_pub != "*" {
        let target_bytes = b64url_decode_array::<32>(target_pub)?;
        if !is_valid_ed25519_public_key(&target_bytes) {
            return Err(CoreError::ProtocolViolation(
                "invalid Ed25519 target_pub in relay ticket",
            ));
        }
    }

    let issuer_bytes = signing_key.verifying_key().to_bytes();
    if !is_valid_ed25519_public_key(&issuer_bytes) {
        return Err(CoreError::InvalidSignature);
    }
    let issuer_pub = b64url_encode(&issuer_bytes);
    let unsigned = RelayTicketUnsigned {
        v: 1,
        issuer_pub: &issuer_pub,
        relay_host: &canon_host,
        role,
        target_pub,
        not_before: now_unix,
        not_after,
    };
    let signed_bytes = relay_ticket_unsigned_bytes(&unsigned)?;
    let sig = signing_key.sign(&signed_bytes).to_bytes();

    Ok(RelayTicket {
        v: 1,
        issuer_pub,
        relay_host: canon_host,
        role,
        target_pub: target_pub.to_string(),
        not_before: now_unix,
        not_after,
        sig: b64url_encode(&sig),
    })
}

/// Mints a [`RelayTicket`] bound to one concrete epoch `mailbox_id` that never leaves the epoch of
/// `now_unix`.
///
/// `ttl_secs` is clamped to the time left before the epoch boundary so the result never satisfies
/// [`RelayTicket::spans_multiple_v2_epochs`]. Returns an error when fewer than two seconds remain
/// in the epoch, in which case the caller should mint against the next epoch's `mailbox_id`.
pub fn mint_v2_epoch_relay_ticket(
    signing_key: &SigningKey,
    relay_host: &str,
    role: RelayAuthRole,
    mailbox_id: &[u8; 32],
    now_unix: u64,
    ttl_secs: u64,
) -> Result<RelayTicket, CoreError> {
    let epoch_end = epoch_for_unix(now_unix)
        .saturating_add(1)
        .saturating_mul(RELAY_V2_EPOCH_SECS);
    let remaining = epoch_end.saturating_sub(1).saturating_sub(now_unix);
    if remaining == 0 {
        return Err(CoreError::GrantDenied(
            "relay ticket epoch exhausted; mint for the next epoch".to_string(),
        ));
    }
    mint_relay_ticket(
        signing_key,
        relay_host,
        role,
        &b64url_encode(mailbox_id),
        now_unix,
        ttl_secs.min(remaining),
    )
}

/// Verifies a [`RelayTicket`] strictly against `trusted_issuers`, host, role, target, and clock.
///
/// Returns the verified 32-byte Ed25519 issuer public key on success.
pub fn verify_relay_ticket(
    ticket: &RelayTicket,
    trusted_issuers: &[[u8; 32]],
    expected_relay_host: &str,
    required_op: RelayAuthRole,
    target_pub: &[u8; 32],
    now_unix: u64,
) -> Result<[u8; 32], CoreError> {
    if trusted_issuers.is_empty() {
        return Err(CoreError::GrantDenied(
            "no trusted relay ticket issuers configured".to_string(),
        ));
    }
    if ticket.v != 1 {
        return Err(CoreError::GrantDenied(format!(
            "unsupported relay ticket version {}",
            ticket.v
        )));
    }
    if ticket.not_before >= ticket.not_after {
        return Err(CoreError::GrantDenied(
            "relay ticket not_before must be strictly before not_after".to_string(),
        ));
    }
    if ticket.not_after - ticket.not_before > MAX_RELAY_TICKET_TTL_SECS {
        return Err(CoreError::GrantDenied(
            "relay ticket lifetime exceeds maximum".to_string(),
        ));
    }
    if now_unix.saturating_add(RELAY_TICKET_CLOCK_SKEW_SECS) < ticket.not_before
        || now_unix
            > ticket
                .not_after
                .saturating_add(RELAY_TICKET_CLOCK_SKEW_SECS)
    {
        return Err(CoreError::GrantDenied(
            "relay ticket expired or not yet valid".to_string(),
        ));
    }

    let ticket_host = canonical_relay_host(&ticket.relay_host)?;
    let expected_host = canonical_relay_host(expected_relay_host)?;
    if ticket_host != expected_host {
        return Err(CoreError::GrantDenied(
            "relay ticket host mismatch".to_string(),
        ));
    }

    if required_op == RelayAuthRole::Any {
        return Err(CoreError::ProtocolViolation(
            "verify_relay_ticket required_op cannot be Any",
        ));
    }
    if ticket.role != RelayAuthRole::Any && ticket.role != required_op {
        return Err(CoreError::GrantDenied(
            "relay ticket role does not authorize operation".to_string(),
        ));
    }

    if ticket.target_pub != "*" {
        let decoded_target = b64url_decode_array::<32>(&ticket.target_pub)?;
        if !is_valid_ed25519_public_key(&decoded_target)
            || !bool::from(decoded_target.ct_eq(target_pub))
        {
            return Err(CoreError::GrantDenied(
                "relay ticket target_pub mismatch".to_string(),
            ));
        }
    }

    let issuer_bytes = b64url_decode_array::<32>(&ticket.issuer_pub)?;
    if !is_valid_ed25519_public_key(&issuer_bytes) {
        return Err(CoreError::InvalidSignature);
    }
    if !trusted_issuers
        .iter()
        .any(|trusted| bool::from(trusted.ct_eq(&issuer_bytes)))
    {
        return Err(CoreError::GrantDenied(
            "relay ticket issuer is not trusted".to_string(),
        ));
    }

    let vk = VerifyingKey::from_bytes(&issuer_bytes).map_err(|_| CoreError::InvalidSignature)?;
    let sig_bytes = b64url_decode_array::<64>(&ticket.sig)?;
    let ed_sig = Ed25519Signature::from_bytes(&sig_bytes);
    let signed_bytes = relay_ticket_signed_bytes(ticket)?;
    vk.verify_strict(&signed_bytes, &ed_sig)
        .map_err(|_| CoreError::InvalidSignature)?;
    Ok(issuer_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKeypair;
    use crate::identity::EndpointIdentity;

    fn test_issuer() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn test_target_key() -> [u8; 32] {
        SigningKey::from_bytes(&[0x22; 32])
            .verifying_key()
            .to_bytes()
    }

    fn other_target_key() -> [u8; 32] {
        SigningKey::from_bytes(&[0x33; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn relay_auth_secret_redacts_debug_and_enforces_bounds() {
        assert!(validate_relay_auth_secret(&[]).is_err());
        assert!(RelayAuthSecret::new(Vec::new()).is_err());

        let max_secret = vec![0xAB; MAX_RELAY_AUTH_SECRET_BYTES];
        assert!(validate_relay_auth_secret(&max_secret).is_ok());
        let wrapped = RelayAuthSecret::from_bytes(&max_secret).unwrap();
        let dbg = format!("{wrapped:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("171"));

        let overlong = vec![0xAB; MAX_RELAY_AUTH_SECRET_BYTES + 1];
        assert!(validate_relay_auth_secret(&overlong).is_err());
        assert!(RelayAuthSecret::new(overlong).is_err());
    }

    #[test]
    fn relay_auth_hmac_binds_op_host_nonce_and_key() {
        let secret = b"super-secret-relay-key";
        let nonce = [0x44; 32];
        let target = test_target_key();
        let mac_b64 =
            compute_relay_auth_hmac_b64(secret, "register", "RELAY.Example.COM.", &nonce, &target)
                .unwrap();

        verify_relay_auth_hmac(
            secret,
            "register",
            "relay.example.com",
            &nonce,
            &target,
            &mac_b64,
        )
        .unwrap();

        // Cross-op rejected
        assert!(
            verify_relay_auth_hmac(
                secret,
                "dial",
                "relay.example.com",
                &nonce,
                &target,
                &mac_b64
            )
            .is_err()
        );
        assert!(
            verify_relay_auth_hmac(
                secret,
                "accept",
                "relay.example.com",
                &nonce,
                &target,
                &mac_b64
            )
            .is_err()
        );
        // Invalid op rejected
        assert!(
            compute_relay_auth_hmac(secret, "unknown", "relay.example.com", &nonce, &target)
                .is_err()
        );
        // Cross-host rejected
        assert!(
            verify_relay_auth_hmac(
                secret,
                "register",
                "other.example.com",
                &nonce,
                &target,
                &mac_b64
            )
            .is_err()
        );
        // Cross-nonce rejected
        let mut other_nonce = nonce;
        other_nonce[0] ^= 0x01;
        assert!(
            verify_relay_auth_hmac(
                secret,
                "register",
                "relay.example.com",
                &other_nonce,
                &target,
                &mac_b64
            )
            .is_err()
        );
        // Cross-key rejected
        assert!(
            verify_relay_auth_hmac(
                secret,
                "register",
                "relay.example.com",
                &nonce,
                &other_target_key(),
                &mac_b64
            )
            .is_err()
        );
        // Tampered MAC bit-flip rejected
        let mut raw_mac = b64url_decode_array::<32>(&mac_b64).unwrap();
        raw_mac[0] ^= 0x01;
        let bad_mac = b64url_encode(&raw_mac);
        assert_eq!(
            verify_relay_auth_hmac(
                secret,
                "register",
                "relay.example.com",
                &nonce,
                &target,
                &bad_mac
            ),
            Err(CoreError::InvalidSignature)
        );
        // Overlong secret rejected
        let overlong = vec![0x55; MAX_RELAY_AUTH_SECRET_BYTES + 1];
        assert!(
            compute_relay_auth_hmac(&overlong, "register", "relay.example.com", &nonce, &target)
                .is_err()
        );
    }

    #[test]
    fn relay_ticket_verification_checks_role_target_host_ttl_skew_and_issuer() {
        let issuer = test_issuer();
        let issuer_pub = issuer.verifying_key().to_bytes();
        let target = test_target_key();
        let target_b64 = b64url_encode(&target);
        let now = 1_795_132_800;

        // Concrete Dial ticket
        let dial_ticket = mint_relay_ticket(
            &issuer,
            "RELAY.Example.COM.",
            RelayAuthRole::Dial,
            &target_b64,
            now,
            3600,
        )
        .unwrap();
        assert_eq!(dial_ticket.relay_host, "relay.example.com");

        assert_eq!(
            verify_relay_ticket(
                &dial_ticket,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Dial,
                &target,
                now + 10,
            ),
            Ok(issuer_pub)
        );

        // Dial ticket rejected for Register
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Register,
                &target,
                now + 10,
            )
            .is_err()
        );

        // required_op = Any rejected
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Any,
                &target,
                now + 10,
            )
            .is_err()
        );

        // Wrong target_pub rejected
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Dial,
                &other_target_key(),
                now + 10,
            )
            .is_err()
        );

        // Wildcard "*" allowed for both targets
        let any_ticket = mint_relay_ticket(
            &issuer,
            "relay.example.com",
            RelayAuthRole::Any,
            "*",
            now,
            MAX_RELAY_TICKET_TTL_SECS,
        )
        .unwrap();
        verify_relay_ticket(
            &any_ticket,
            &[issuer_pub],
            "relay.example.com",
            RelayAuthRole::Register,
            &target,
            now,
        )
        .unwrap();
        verify_relay_ticket(
            &any_ticket,
            &[issuer_pub],
            "relay.example.com",
            RelayAuthRole::Dial,
            &other_target_key(),
            now,
        )
        .unwrap();

        // Clock skew +-30s boundaries
        verify_relay_ticket(
            &dial_ticket,
            &[issuer_pub],
            "relay.example.com",
            RelayAuthRole::Dial,
            &target,
            now - RELAY_TICKET_CLOCK_SKEW_SECS,
        )
        .unwrap();
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Dial,
                &target,
                now - RELAY_TICKET_CLOCK_SKEW_SECS - 1,
            )
            .is_err()
        );
        verify_relay_ticket(
            &dial_ticket,
            &[issuer_pub],
            "relay.example.com",
            RelayAuthRole::Dial,
            &target,
            now + 3600 + RELAY_TICKET_CLOCK_SKEW_SECS,
        )
        .unwrap();
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Dial,
                &target,
                now + 3600 + RELAY_TICKET_CLOCK_SKEW_SECS + 1,
            )
            .is_err()
        );

        // TTL bounds: 0 and 86_401 rejected at mint and verify
        assert!(
            mint_relay_ticket(
                &issuer,
                "relay.example.com",
                RelayAuthRole::Dial,
                "*",
                now,
                0,
            )
            .is_err()
        );
        assert!(
            mint_relay_ticket(
                &issuer,
                "relay.example.com",
                RelayAuthRole::Dial,
                "*",
                now,
                MAX_RELAY_TICKET_TTL_SECS + 1,
            )
            .is_err()
        );

        let mut forged_ttl = dial_ticket.clone();
        forged_ttl.not_after = forged_ttl.not_before + MAX_RELAY_TICKET_TTL_SECS + 1;
        assert!(
            verify_relay_ticket(
                &forged_ttl,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Dial,
                &target,
                now,
            )
            .is_err()
        );

        // Wrong relay host rejected
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[issuer_pub],
                "evil.example.com",
                RelayAuthRole::Dial,
                &target,
                now,
            )
            .is_err()
        );

        // Empty trusted_issuers or unknown issuer rejected
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[],
                "relay.example.com",
                RelayAuthRole::Dial,
                &target,
                now,
            )
            .is_err()
        );
        assert!(
            verify_relay_ticket(
                &dial_ticket,
                &[[0x99; 32]],
                "relay.example.com",
                RelayAuthRole::Dial,
                &target,
                now,
            )
            .is_err()
        );

        // Wrong version rejected
        let mut wrong_v = dial_ticket.clone();
        wrong_v.v = 2;
        assert!(
            verify_relay_ticket(
                &wrong_v,
                &[issuer_pub],
                "relay.example.com",
                RelayAuthRole::Dial,
                &target,
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn relay_auth_proof_rejects_unknown_fields_and_endpoint_identity_mints_ticket() {
        let id = EndpointIdentity::from_keys(
            crate::crypto::StaticKeypair::from_scalar([0x41; 32]),
            SigningKeypair::from_seed([0x42; 32]),
        );
        let now = 1_795_132_800;
        let ticket = id
            .mint_relay_ticket("relay.example.com", RelayAuthRole::Register, "*", now, 600)
            .unwrap();
        let issuer_pub = *id.signing_key().ed25519_public_bytes();
        verify_relay_ticket(
            &ticket,
            &[issuer_pub],
            "relay.example.com",
            RelayAuthRole::Register,
            &test_target_key(),
            now,
        )
        .unwrap();

        let proof = RelayAuthProof::Ticket {
            ticket: ticket.clone(),
        };
        let json = serde_json::to_string(&proof).unwrap();
        let roundtrip: RelayAuthProof = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, proof);

        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["extra"] = serde_json::json!("bad");
        assert!(serde_json::from_value::<RelayAuthProof>(val).is_err());

        let mut t_val = serde_json::to_value(&ticket).unwrap();
        t_val["extra"] = serde_json::json!(123);
        assert!(serde_json::from_value::<RelayTicket>(t_val).is_err());

        let hmac_proof = RelayAuthProof::Hmac {
            mac: "AAAA".to_string(),
        };
        let mut h_val = serde_json::to_value(&hmac_proof).unwrap();
        h_val["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RelayAuthProof>(h_val).is_err());
    }

    #[test]
    fn priv02_epoch_ticket_stays_in_one_epoch_while_wildcard_spans() {
        let issuer = test_issuer();
        let mailbox = test_target_key();
        let epoch_start = 1000 * RELAY_V2_EPOCH_SECS;
        let now = epoch_start + 100;

        let bound = mint_v2_epoch_relay_ticket(
            &issuer,
            "relay.example.com",
            RelayAuthRole::Register,
            &mailbox,
            now,
            MAX_RELAY_TICKET_TTL_SECS,
        )
        .unwrap();
        assert!(!bound.spans_multiple_v2_epochs());
        assert_eq!(bound.ttl_secs(), RELAY_V2_EPOCH_SECS - 101);
        assert_eq!(bound.target_pub, b64url_encode(&mailbox));

        let short = mint_v2_epoch_relay_ticket(
            &issuer,
            "relay.example.com",
            RelayAuthRole::Dial,
            &mailbox,
            now,
            60,
        )
        .unwrap();
        assert_eq!(short.ttl_secs(), 60);

        let wildcard = mint_relay_ticket(
            &issuer,
            "relay.example.com",
            RelayAuthRole::Register,
            "*",
            now,
            2 * RELAY_V2_EPOCH_SECS,
        )
        .unwrap();
        assert!(wildcard.spans_multiple_v2_epochs());
        assert_eq!(wildcard.ttl_secs(), 2 * RELAY_V2_EPOCH_SECS);

        let last_second = epoch_start + RELAY_V2_EPOCH_SECS - 1;
        assert!(
            mint_v2_epoch_relay_ticket(
                &issuer,
                "relay.example.com",
                RelayAuthRole::Register,
                &mailbox,
                last_second,
                60,
            )
            .is_err()
        );
    }
}
