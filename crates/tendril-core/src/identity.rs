//! Identity timestamp formatting/parsing and signed key-rotation verification.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{SigningKeypair, StaticKeypair, b64url_decode_array, b64url_encode};
use crate::error::CoreError;

/// 15-byte domain separator prefix for binary `RotationRecord` signatures.
pub const ROTATION_DOMAIN: &[u8] = b"tendril-rot-v1\0";

/// Total byte length of the binary payload signed inside [`RotationRecord`].
pub const ROTATION_SIGNED_LEN: usize = 15 + 8 + 32 + 32 + 32 + 8;

/// Maximum formatted UTC timestamp supported (`9999-12-31T23:59:59Z`).
const MAX_UNIX_SECS: u64 = 253_402_300_799;

/// Local endpoint identity combining X25519 static keys, Ed25519 signing keys, and
/// signed rotation history.
#[derive(Debug, Clone)]
pub struct EndpointIdentity {
    host_id: String,
    static_key: StaticKeypair,
    signing_key: SigningKeypair,
    rotation_chain: Vec<RotationRecord>,
    rotation_seq: u64,
}

impl EndpointIdentity {
    /// Generates a fresh endpoint identity with random static and signing keys.
    pub fn generate() -> Result<Self, CoreError> {
        let static_key = StaticKeypair::generate()?;
        let signing_key = SigningKeypair::generate()?;
        Ok(Self::from_keys(static_key, signing_key))
    }

    /// Builds an endpoint identity from existing keypairs, deriving `host_id` from `static_key`.
    #[must_use]
    pub fn from_keys(static_key: StaticKeypair, signing_key: SigningKeypair) -> Self {
        let host_id = static_key.device_id();
        Self {
            host_id,
            static_key,
            signing_key,
            rotation_chain: Vec::new(),
            rotation_seq: 0,
        }
    }

    /// Overrides the stable `host_id` carried in `HostHello`.
    #[must_use]
    pub fn with_host_id(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = host_id.into();
        self
    }

    /// Returns the stable `host_id`.
    #[must_use]
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// Returns the `device_id` corresponding to the current active static key.
    #[must_use]
    pub fn device_id(&self) -> String {
        self.static_key.device_id()
    }

    /// Returns the active X25519 static keypair.
    #[must_use]
    pub const fn static_key(&self) -> &StaticKeypair {
        &self.static_key
    }

    /// Returns the active Ed25519 signing keypair.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKeypair {
        &self.signing_key
    }

    /// Returns all signed rotation records issued by this identity.
    #[must_use]
    pub fn rotation_chain(&self) -> &[RotationRecord] {
        &self.rotation_chain
    }

    /// Returns the current rotation sequence counter (`0` before any rotation).
    #[must_use]
    pub const fn rotation_seq(&self) -> u64 {
        self.rotation_seq
    }

    /// Signs a new [`RotationRecord`] using the outgoing signing key and rotates keys atomically.
    pub fn rotate(
        &mut self,
        new_static: StaticKeypair,
        new_signing: SigningKeypair,
        now_unix: u64,
    ) -> Result<RotationRecord, CoreError> {
        let next_seq = self
            .rotation_seq
            .checked_add(1)
            .ok_or(CoreError::RotationNonContiguous)?;
        let outgoing = self.signing_key.signing_key();
        let rec = sign_rotation(
            next_seq,
            &outgoing,
            new_signing.public_bytes(),
            new_static.public_bytes(),
            now_unix,
        )?;
        self.rotation_chain.push(rec.clone());
        self.static_key = new_static;
        self.signing_key = new_signing;
        self.rotation_seq = next_seq;
        Ok(rec)
    }
}

/// One signed link in a peer's key-rotation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    pub seq: u64,
    pub prev_signing_pub: String,
    pub new_signing_pub: String,
    pub new_static_pub: String,
    pub ts: String,
    pub sig: String,
}

/// Decoded and validated fields from one [`RotationRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRotation {
    pub seq: u64,
    pub prev_signing_pub: [u8; 32],
    pub new_signing_pub: [u8; 32],
    pub new_static_pub: [u8; 32],
    pub ts_unix: u64,
}

#[derive(PartialEq, Eq)]
struct ForkOutcome {
    new_signing_pub: [u8; 32],
    new_static_pub: [u8; 32],
    ts_unix: u64,
}

/// Builds the exact 127-byte binary payload signed by the outgoing signing key.
#[must_use]
pub fn rotation_signed_bytes(
    seq: u64,
    prev_signing_pub: &[u8; 32],
    new_signing_pub: &[u8; 32],
    new_static_pub: &[u8; 32],
    ts_unix: u64,
) -> [u8; ROTATION_SIGNED_LEN] {
    let mut out = [0u8; ROTATION_SIGNED_LEN];
    out[0..15].copy_from_slice(ROTATION_DOMAIN);
    out[15..23].copy_from_slice(&seq.to_be_bytes());
    out[23..55].copy_from_slice(prev_signing_pub);
    out[55..87].copy_from_slice(new_signing_pub);
    out[87..119].copy_from_slice(new_static_pub);
    out[119..127].copy_from_slice(&ts_unix.to_be_bytes());
    out
}

/// Signs a new [`RotationRecord`] using `prev_signing` over the 127-byte binary payload.
pub fn sign_rotation(
    seq: u64,
    prev_signing: &SigningKey,
    new_signing_pub: &[u8; 32],
    new_static_pub: &[u8; 32],
    ts_unix: u64,
) -> Result<RotationRecord, CoreError> {
    if seq == 0 {
        return Err(CoreError::RotationNonMonotonicSeq {
            expected_min: 1,
            got: 0,
        });
    }
    let ts = format_rfc3339_utc(ts_unix)?;
    let prev_pub = prev_signing.verifying_key().to_bytes();
    let payload = rotation_signed_bytes(seq, &prev_pub, new_signing_pub, new_static_pub, ts_unix);
    let sig: Signature = prev_signing.sign(&payload);
    Ok(RotationRecord {
        seq,
        prev_signing_pub: b64url_encode(&prev_pub),
        new_signing_pub: b64url_encode(new_signing_pub),
        new_static_pub: b64url_encode(new_static_pub),
        ts,
        sig: b64url_encode(&sig.to_bytes()),
    })
}

/// Decodes and strictly verifies a single [`RotationRecord`].
pub fn verify_rotation_record(record: &RotationRecord) -> Result<VerifiedRotation, CoreError> {
    if record.seq == 0 {
        return Err(CoreError::RotationNonMonotonicSeq {
            expected_min: 1,
            got: 0,
        });
    }
    let prev_signing_pub: [u8; 32] = b64url_decode_array(&record.prev_signing_pub)?;
    let new_signing_pub: [u8; 32] = b64url_decode_array(&record.new_signing_pub)?;
    let new_static_pub: [u8; 32] = b64url_decode_array(&record.new_static_pub)?;
    let sig_bytes: [u8; 64] = b64url_decode_array(&record.sig)?;
    let ts_unix = parse_rfc3339_utc(&record.ts)?;

    let vk =
        VerifyingKey::from_bytes(&prev_signing_pub).map_err(|_| CoreError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = rotation_signed_bytes(
        record.seq,
        &prev_signing_pub,
        &new_signing_pub,
        &new_static_pub,
        ts_unix,
    );
    vk.verify_strict(&payload, &sig)
        .map_err(|_| CoreError::InvalidSignature)?;

    Ok(VerifiedRotation {
        seq: record.seq,
        prev_signing_pub,
        new_signing_pub,
        new_static_pub,
        ts_unix,
    })
}

fn detect_fork_in_verified(records: &[VerifiedRotation]) -> Result<(), CoreError> {
    let mut by_key: HashMap<(u64, [u8; 32]), ForkOutcome> = HashMap::new();
    for r in records {
        let outcome = ForkOutcome {
            new_signing_pub: r.new_signing_pub,
            new_static_pub: r.new_static_pub,
            ts_unix: r.ts_unix,
        };
        if let Some(prev) = by_key.insert((r.seq, r.prev_signing_pub), outcome) {
            let cur = ForkOutcome {
                new_signing_pub: r.new_signing_pub,
                new_static_pub: r.new_static_pub,
                ts_unix: r.ts_unix,
            };
            if prev != cur {
                return Err(CoreError::RotationForkDetected { seq: r.seq });
            }
        }
    }
    Ok(())
}

/// Detects whether two distinct valid rotation records share `(seq, prev_signing_pub)`.
///
/// Keying by `(seq, prev_signing_pub)` prevents unanchored keys from colliding with unrelated chains.
/// Callers verifying an untrusted peer handshake MUST still use [`verify_rotation_chain`], which
/// restricts fork detection to keys reachable from `pinned_signing`.
pub fn detect_rotation_fork(records: &[RotationRecord]) -> Result<(), CoreError> {
    let mut decoded = Vec::with_capacity(records.len());
    for rec in records {
        decoded.push(verify_rotation_record(rec)?);
    }
    detect_fork_in_verified(&decoded)
}

/// Verifies that `chain` bridges `(pinned_signing, pinned_static, pinned_seq)` to
/// `(current_static, current_signing)`.
///
/// Returns the final verified sequence number (`pinned_seq` when `chain` is empty and keys match).
pub fn verify_rotation_chain(
    pinned_signing: &[u8; 32],
    pinned_static: &[u8; 32],
    pinned_seq: u64,
    chain: &[RotationRecord],
    current_static: &[u8; 32],
    current_signing: &[u8; 32],
) -> Result<u64, CoreError> {
    if chain.is_empty() {
        if pinned_signing == current_signing && pinned_static == current_static {
            return Ok(pinned_seq);
        }
        return Err(CoreError::RotationEmptyChain);
    }

    let mut decoded = Vec::with_capacity(chain.len());
    for rec in chain {
        decoded.push(verify_rotation_record(rec)?);
    }

    // Only keys reachable from `pinned_signing` at `seq > pinned_seq` may trigger fork revocation.
    let mut trusted_keys = HashSet::from([*pinned_signing]);
    loop {
        let mut progressed = false;
        for r in &decoded {
            if r.seq > pinned_seq
                && trusted_keys.contains(&r.prev_signing_pub)
                && trusted_keys.insert(r.new_signing_pub)
            {
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    let trusted_records: Vec<VerifiedRotation> = decoded
        .iter()
        .filter(|r| trusted_keys.contains(&r.prev_signing_pub))
        .cloned()
        .collect();
    detect_fork_in_verified(&trusted_records)?;

    let mut seen_keys = HashSet::from([decoded[0].prev_signing_pub]);
    for (i, r) in decoded.iter().enumerate() {
        if i > 0 {
            let prev = &decoded[i - 1];
            let Some(expected_seq) = prev.seq.checked_add(1) else {
                return Err(CoreError::RotationNonContiguous);
            };
            if r.seq != expected_seq {
                return Err(CoreError::RotationNonMonotonicSeq {
                    expected_min: expected_seq,
                    got: r.seq,
                });
            }
            if r.prev_signing_pub != prev.new_signing_pub {
                return Err(CoreError::RotationNonContiguous);
            }
        }
        if !seen_keys.insert(r.new_signing_pub) {
            return Err(CoreError::RotationNonContiguous);
        }
    }

    let last = decoded.last().ok_or(CoreError::RotationEmptyChain)?;
    if &last.new_signing_pub == pinned_signing
        && &last.new_static_pub == pinned_static
        && last.seq == pinned_seq
    {
        if current_signing == pinned_signing && current_static == pinned_static {
            return Ok(pinned_seq);
        }
        return Err(CoreError::RotationEndpointMismatch);
    }

    let start = decoded
        .iter()
        .position(|r| &r.prev_signing_pub == pinned_signing)
        .ok_or(CoreError::RotationRootMismatch)?;

    let Some(expected_anchor_seq) = pinned_seq.checked_add(1) else {
        return Err(CoreError::RotationNonContiguous);
    };
    if decoded[start].seq != expected_anchor_seq {
        return Err(CoreError::RotationNonMonotonicSeq {
            expected_min: expected_anchor_seq,
            got: decoded[start].seq,
        });
    }
    if start > 0 && &decoded[start - 1].new_static_pub != pinned_static {
        return Err(CoreError::RotationRootMismatch);
    }
    if &last.new_signing_pub != current_signing || &last.new_static_pub != current_static {
        return Err(CoreError::RotationEndpointMismatch);
    }

    Ok(last.seq)
}

/// Formats post-1970 Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn format_rfc3339_utc(unix_secs: u64) -> Result<String, CoreError> {
    if unix_secs > MAX_UNIX_SECS {
        return Err(CoreError::InvalidTimestamp(
            "timestamps after 9999-12-31T23:59:59Z are unsupported".to_string(),
        ));
    }
    let secs_i64 = unix_secs as i64;
    let days = secs_i64.div_euclid(86_400);
    let secs_of_day = secs_i64.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Strictly parses a whole-second UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` into `u64` Unix seconds.
pub(crate) fn parse_rfc3339_utc(input: &str) -> Result<u64, CoreError> {
    let b = input.as_bytes();
    if b.len() != 20
        || !input.is_ascii()
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(CoreError::InvalidTimestamp(input.to_string()));
    }
    let year: i64 = parse_digits(&input[0..4], input)?;
    let month: u32 = parse_digits(&input[5..7], input)?;
    let day: u32 = parse_digits(&input[8..10], input)?;
    let hour: u32 = parse_digits(&input[11..13], input)?;
    let minute: u32 = parse_digits(&input[14..16], input)?;
    let second: u32 = parse_digits(&input[17..19], input)?;

    if year < 1970 || !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(CoreError::InvalidTimestamp(input.to_string()));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(CoreError::InvalidTimestamp(input.to_string()));
    }

    let days = days_from_civil(year, month, day);
    let unix_secs =
        days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second);
    u64::try_from(unix_secs).map_err(|_| CoreError::InvalidTimestamp(input.to_string()))
}

fn parse_digits<T: std::str::FromStr>(slice: &str, full: &str) -> Result<T, CoreError> {
    if !slice.bytes().all(|c| c.is_ascii_digit()) {
        return Err(CoreError::InvalidTimestamp(full.to_string()));
    }
    slice
        .parse()
        .map_err(|_| CoreError::InvalidTimestamp(full.to_string()))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

// Howard Hinnant civil/days conversions (proleptic Gregorian calendar).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let m = i64::from(m);
    let d = i64::from(d);
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_keys(seed: u8) -> (SigningKey, [u8; 32], [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        let stat = [seed.wrapping_add(0x40); 32];
        (sk, pk, stat)
    }

    #[test]
    fn strict_utc_timestamp_parsing_and_formatting() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            format_rfc3339_utc(0).unwrap(),
            "1970-01-01T00:00:00Z".to_string()
        );
        let leap = parse_rfc3339_utc("2024-02-29T00:00:00Z").unwrap();
        assert_eq!(format_rfc3339_utc(leap).unwrap(), "2024-02-29T00:00:00Z");
        assert_eq!(
            format_rfc3339_utc(MAX_UNIX_SECS).unwrap(),
            "9999-12-31T23:59:59Z"
        );
        assert!(matches!(
            format_rfc3339_utc(MAX_UNIX_SECS + 1),
            Err(CoreError::InvalidTimestamp(_))
        ));

        for bad in [
            "1969-12-31T23:59:59Z",
            "2026-11-20T00:00:00.500Z",
            "2026-11-20T00:00:00+00:00",
            "2026-11-20t00:00:00z",
            "2026-02-29T00:00:00Z",
        ] {
            assert!(
                matches!(parse_rfc3339_utc(bad), Err(CoreError::InvalidTimestamp(_))),
                "expected InvalidTimestamp for {bad}"
            );
        }
    }

    #[test]
    fn rotation_record_rejects_seq_zero_and_tampering() {
        let (sk0, _, _) = mk_keys(0x01);
        let (_, pk1, stat1) = mk_keys(0x02);
        assert_eq!(
            sign_rotation(0, &sk0, &pk1, &stat1, 1_795_132_800),
            Err(CoreError::RotationNonMonotonicSeq {
                expected_min: 1,
                got: 0
            })
        );

        let mut rec = sign_rotation(1, &sk0, &pk1, &stat1, 1_795_132_800).unwrap();
        assert!(verify_rotation_record(&rec).is_ok());

        rec.seq = 0;
        assert_eq!(
            verify_rotation_record(&rec),
            Err(CoreError::RotationNonMonotonicSeq {
                expected_min: 1,
                got: 0
            })
        );

        rec.seq = 2;
        assert_eq!(
            verify_rotation_record(&rec),
            Err(CoreError::InvalidSignature)
        );
    }

    #[test]
    fn rotation_chain_fast_path_historical_tail_and_cycles() {
        let (sk0, pk0, stat0) = mk_keys(0x01);
        let (sk1, pk1, stat1) = mk_keys(0x02);
        let (_, pk2, stat2) = mk_keys(0x03);
        let ts = 1_795_132_800;

        // Empty chain fast path preserves pinned_seq and rejects key change.
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[], &stat0, &pk0).unwrap(),
            0
        );
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[], &stat1, &pk1),
            Err(CoreError::RotationEmptyChain)
        );

        let r1 = sign_rotation(1, &sk0, &pk1, &stat1, ts).unwrap();
        let r2 = sign_rotation(2, &sk1, &pk2, &stat2, ts + 60).unwrap();

        // Already pinned at seq = 1 (mid-chain): advances to 2.
        assert_eq!(
            verify_rotation_chain(&pk1, &stat1, 1, &[r1.clone(), r2.clone()], &stat2, &pk2)
                .unwrap(),
            2
        );
        // Already pinned at tail seq = 2: returns 2 when endpoint matches pinned keys.
        assert_eq!(
            verify_rotation_chain(&pk2, &stat2, 2, &[r1.clone(), r2.clone()], &stat2, &pk2)
                .unwrap(),
            2
        );

        // Skipping pinned_seq + 1 fails strict anchor monotonicity.
        let skipped = sign_rotation(5, &sk0, &pk1, &stat1, ts).unwrap();
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[skipped], &stat1, &pk1),
            Err(CoreError::RotationNonMonotonicSeq {
                expected_min: 1,
                got: 5
            })
        );

        // Cycle K0 -> K1 -> K0 must be rejected even when pinned == current.
        let r_back = sign_rotation(2, &sk1, &pk0, &stat0, ts + 60).unwrap();
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[r1.clone(), r_back], &stat0, &pk0),
            Err(CoreError::RotationNonContiguous)
        );

        // Tampered non-empty chain must not pass fast path when pinned == current.
        let mut bad_r1 = r1.clone();
        bad_r1.ts = "2026-11-20T00:00:01Z".to_string();
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[bad_r1], &stat0, &pk0),
            Err(CoreError::InvalidSignature)
        );

        // Non-contiguous gap, wrong endpoint, and unrelated root.
        let (sk_other, pk_other, _) = mk_keys(0x09);
        let bad_link = sign_rotation(2, &sk_other, &pk2, &stat2, ts + 60).unwrap();
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[r1.clone(), bad_link], &stat2, &pk2),
            Err(CoreError::RotationNonContiguous)
        );
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, std::slice::from_ref(&r1), &stat2, &pk2),
            Err(CoreError::RotationEndpointMismatch)
        );
        assert_eq!(
            verify_rotation_chain(&pk_other, &stat0, 0, &[r1, r2], &stat2, &pk2),
            Err(CoreError::RotationRootMismatch)
        );
    }

    #[test]
    fn rotation_fork_detection_rejects_unanchored_mitm_false_positive() {
        let (sk0, pk0, stat0) = mk_keys(0x11);
        let (sk1, pk1, stat1) = mk_keys(0x12);
        let (_, pk2, stat2) = mk_keys(0x13);
        let (sk_mitm, _, _) = mk_keys(0x99);
        let (_, pk_a, stat_a) = mk_keys(0x9A);
        let (_, pk_b, stat_b) = mk_keys(0x9B);
        let ts = 1_795_132_800;

        let r1 = sign_rotation(1, &sk0, &pk1, &stat1, ts).unwrap();

        // MITM injecting another record at seq = 1 signed by an unrelated key must NOT fork-revoke.
        let mitm_seq1 = sign_rotation(1, &sk_mitm, &pk_a, &stat_a, ts + 5).unwrap();
        let res1 = verify_rotation_chain(&pk0, &stat0, 0, &[r1.clone(), mitm_seq1], &stat1, &pk1);
        assert!(!matches!(res1, Err(CoreError::RotationForkDetected { .. })));
        assert!(res1.is_err());

        // MITM injecting two conflicting records signed by an unrelated key at seq = 2 must NOT fork-revoke.
        let mitm_a = sign_rotation(2, &sk_mitm, &pk_a, &stat_a, ts + 10).unwrap();
        let mitm_b = sign_rotation(2, &sk_mitm, &pk_b, &stat_b, ts + 20).unwrap();
        let res2 = verify_rotation_chain(
            &pk0,
            &stat0,
            0,
            &[r1.clone(), mitm_a, mitm_b],
            &stat_b,
            &pk_b,
        );
        assert!(!matches!(res2, Err(CoreError::RotationForkDetected { .. })));
        assert!(res2.is_err());

        // Authentic fork signed by K1 (reachable from K0) triggers RotationForkDetected { seq: 2 }.
        let r2 = sign_rotation(2, &sk1, &pk2, &stat2, ts + 60).unwrap();
        let r2_fork = sign_rotation(2, &sk1, &pk_a, &stat_a, ts + 90).unwrap();
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[r1, r2, r2_fork], &stat2, &pk2),
            Err(CoreError::RotationForkDetected { seq: 2 })
        );
    }

    #[test]
    fn rotation_chain_rejects_u64_max_seq_without_overflow() {
        let (sk0, pk0, stat0) = mk_keys(0x21);
        let (sk1, pk1, stat1) = mk_keys(0x22);
        let (sk_other, _, _) = mk_keys(0x23);
        let (_, pk2, stat2) = mk_keys(0x24);
        let ts = 1_795_132_800;

        let r_max = sign_rotation(u64::MAX, &sk_other, &pk1, &stat1, ts).unwrap();
        let r_next = sign_rotation(1, &sk1, &pk2, &stat2, ts + 10).unwrap();
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, 0, &[r_max, r_next], &stat2, &pk2),
            Err(CoreError::RotationNonContiguous)
        );

        let r_pinned = sign_rotation(1, &sk0, &pk1, &stat1, ts).unwrap();
        assert_eq!(
            verify_rotation_chain(&pk0, &stat0, u64::MAX, &[r_pinned], &stat1, &pk1),
            Err(CoreError::RotationNonContiguous)
        );
    }
}
