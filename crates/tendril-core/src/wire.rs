//! Wire constants, preamble encoding, outer framing, and handshake payloads.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::error::CoreError;
use crate::grants::Grant;
use crate::identity::RotationRecord;

/// Fixed Noise protocol pattern for Tendril v1 and v2.
pub const NOISE_PATTERN: &str = "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256";

/// Three-byte ASCII magic opening every Tendril preamble.
pub const PREAMBLE_MAGIC: [u8; 3] = *b"TND";

/// Exact byte length of the cleartext preamble (and standard Noise prologue).
pub const PREAMBLE_LEN: usize = 6;

/// Wire protocol version v1 encoded in the cleartext preamble.
pub const WIRE_VERSION: u8 = 0x01;

/// Wire protocol version v2 (privacy profile) encoded in the cleartext preamble.
pub const WIRE_VERSION_V2: u8 = 0x02;

/// Reserved byte in the v1 preamble; must always be zero.
pub const PREAMBLE_RESERVED: u8 = 0x00;

/// Default v2 preamble flags byte (standard v2 session or standard v2 pairing).
pub const PREAMBLE_FLAG_NONE: u8 = 0x00;

/// Wire v2 pairing preamble flag enabling hybrid PAKE + ML-KEM-768 pairing (`intent == 0x02` only).
pub const FLAG_PAKE_PAIR: u8 = 0x01;

/// Length in bytes of the Noise ChaChaPoly AEAD authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Maximum length in bytes of a single outer framed body (`65535 - 16`).
pub const MAX_FRAME_LEN: usize = 65_519;

/// Maximum decrypted plaintext bytes inside a single transport AEAD frame.
pub const MAX_TRANSPORT_PLAINTEXT: usize = MAX_FRAME_LEN - AEAD_TAG_LEN;

/// Maximum application bytes carried inside a `0x01 DATA` inner frame.
pub const MAX_APP_DATA_LEN: usize = MAX_TRANSPORT_PLAINTEXT - 1;

/// Maximum total bytes queued inside [`ResumableFrameReader`] before rejecting unbounded buffering.
pub const MAX_READ_BUFFER_LEN: usize = 4 * (2 + MAX_FRAME_LEN);

/// Handshake intent carried in the 6-byte cleartext preamble.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Intent {
    /// Authenticated session for application data and capability enforcement.
    Session = 0x01,
    /// Pairing ceremony proving possession of a single-use pairing code.
    Pair = 0x02,
}

impl TryFrom<u8> for Intent {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Session),
            0x02 => Ok(Self::Pair),
            other => Err(CoreError::UnknownIntent(other)),
        }
    }
}

/// Parsed 6-byte cleartext preamble (and verbatim Noise prologue for v1 and standard v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preamble {
    pub version: u8,
    pub intent: Intent,
    pub flags: u8,
}

impl Preamble {
    /// Constructs a v1 preamble for `intent`.
    #[must_use]
    pub const fn v1(intent: Intent) -> Self {
        Self {
            version: WIRE_VERSION,
            intent,
            flags: PREAMBLE_RESERVED,
        }
    }

    /// Constructs a v2 preamble for `intent` and `flags`.
    #[must_use]
    pub const fn v2(intent: Intent, flags: u8) -> Self {
        Self {
            version: WIRE_VERSION_V2,
            intent,
            flags,
        }
    }

    /// Constructs a v2 PAKE pairing preamble (`version = 0x02`, `intent = Pair`, `flags = 0x01`).
    #[must_use]
    pub const fn v2_pake_pair() -> Self {
        Self {
            version: WIRE_VERSION_V2,
            intent: Intent::Pair,
            flags: FLAG_PAKE_PAIR,
        }
    }

    /// Encodes the preamble as its exact 6 wire bytes.
    #[must_use]
    pub const fn encode(self) -> [u8; PREAMBLE_LEN] {
        [
            PREAMBLE_MAGIC[0],
            PREAMBLE_MAGIC[1],
            PREAMBLE_MAGIC[2],
            self.version,
            self.intent as u8,
            self.flags,
        ]
    }

    /// Strictly decodes and validates a 6-byte cleartext preamble (v1 and v2).
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != PREAMBLE_LEN {
            return Err(CoreError::InvalidPreambleLength {
                expected: PREAMBLE_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..3] != PREAMBLE_MAGIC {
            return Err(CoreError::BadPreambleMagic);
        }
        let version = bytes[3];
        let intent_raw = bytes[4];
        let flags = bytes[5];
        match version {
            WIRE_VERSION => {
                let intent = Intent::try_from(intent_raw)?;
                if flags != PREAMBLE_RESERVED {
                    return Err(CoreError::NonZeroReserved(flags));
                }
                Ok(Self {
                    version,
                    intent,
                    flags,
                })
            }
            WIRE_VERSION_V2 => {
                let intent = Intent::try_from(intent_raw)?;
                let allowed = match intent {
                    Intent::Session => flags == PREAMBLE_FLAG_NONE,
                    Intent::Pair => flags == PREAMBLE_FLAG_NONE || flags == FLAG_PAKE_PAIR,
                };
                if !allowed {
                    return Err(CoreError::InvalidPreambleFlags {
                        intent: intent_raw,
                        flags,
                    });
                }
                Ok(Self {
                    version,
                    intent,
                    flags,
                })
            }
            other => Err(CoreError::UnsupportedVersion(other)),
        }
    }
}

/// Encodes `body` as `uint16_be len || body`, enforcing [`MAX_FRAME_LEN`].
pub fn encode_frame(body: &[u8]) -> Result<Vec<u8>, CoreError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(CoreError::FrameTooLarge {
            len: body.len(),
            max: MAX_FRAME_LEN,
        });
    }
    let len = u16::try_from(body.len()).map_err(|_| CoreError::FrameTooLarge {
        len: body.len(),
        max: MAX_FRAME_LEN,
    })?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Decodes one `uint16_be len || body` frame from `bytes`, returning `(body, total_consumed)`.
pub fn decode_frame(bytes: &[u8]) -> Result<(&[u8], usize), CoreError> {
    if bytes.len() < 2 {
        return Err(CoreError::TruncatedFrame {
            expected: 2,
            actual: bytes.len(),
        });
    }
    let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    if len > MAX_FRAME_LEN {
        return Err(CoreError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    let total = 2 + len;
    if bytes.len() < total {
        return Err(CoreError::TruncatedFrame {
            expected: total,
            actual: bytes.len(),
        });
    }
    Ok((&bytes[2..total], total))
}

/// Inner encrypted frame type inside Noise transport mode for `intent = session`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InnerFrameType {
    Data = 0x01,
    Grant = 0x02,
    Revocation = 0x03,
    Rekey = 0x04,
    Ping = 0x05,
    Pong = 0x06,
    Close = 0x07,
    /// Wire v2 pure cover traffic frame (`0x08`), zero-filled and silently discarded after AEAD decrypt.
    Padding = 0x08,
    /// Wire v2 bucketed padded envelope (`0x09`) wrapping one `0x01..=0x07` inner frame.
    Padded = 0x09,
}

impl TryFrom<u8> for InnerFrameType {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Grant),
            0x03 => Ok(Self::Revocation),
            0x04 => Ok(Self::Rekey),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::Close),
            0x08 => Ok(Self::Padding),
            0x09 => Ok(Self::Padded),
            other => Err(CoreError::UnknownInnerFrameType(other)),
        }
    }
}

/// Encodes one inner encrypted transport frame (`type || payload`), validating per-type payload rules.
pub fn encode_inner_frame(kind: InnerFrameType, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
    validate_inner_payload(kind, payload)?;
    let total = 1 + payload.len();
    if total > MAX_TRANSPORT_PLAINTEXT {
        return Err(CoreError::FrameTooLarge {
            len: total,
            max: MAX_TRANSPORT_PLAINTEXT,
        });
    }
    let mut out = Vec::with_capacity(total);
    out.push(kind as u8);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes and validates one inner encrypted transport frame from decrypted plaintext.
pub fn decode_inner_frame(plaintext: &[u8]) -> Result<(InnerFrameType, &[u8]), CoreError> {
    if plaintext.len() > MAX_TRANSPORT_PLAINTEXT {
        return Err(CoreError::FrameTooLarge {
            len: plaintext.len(),
            max: MAX_TRANSPORT_PLAINTEXT,
        });
    }
    let (&tag, payload) = plaintext.split_first().ok_or(CoreError::EmptyInnerFrame)?;
    let kind = InnerFrameType::try_from(tag)?;
    validate_inner_payload(kind, payload)?;
    Ok((kind, payload))
}

pub(crate) fn validate_inner_payload(
    kind: InnerFrameType,
    payload: &[u8],
) -> Result<(), CoreError> {
    match kind {
        InnerFrameType::Data | InnerFrameType::Grant | InnerFrameType::Revocation => {
            if payload.len() > MAX_APP_DATA_LEN {
                return Err(CoreError::FrameTooLarge {
                    len: 1 + payload.len(),
                    max: MAX_TRANSPORT_PLAINTEXT,
                });
            }
        }
        InnerFrameType::Rekey if !payload.is_empty() => {
            return Err(CoreError::InvalidInnerFramePayload(
                "REKEY frame payload must be empty",
            ));
        }
        InnerFrameType::Ping | InnerFrameType::Pong if payload.len() != 8 => {
            return Err(CoreError::InvalidInnerFramePayload(
                "PING/PONG payload must be exactly 8 bytes",
            ));
        }
        InnerFrameType::Close if payload.len() < 2 => {
            return Err(CoreError::InvalidInnerFramePayload(
                "CLOSE payload must include 2-byte reason code",
            ));
        }
        InnerFrameType::Close if payload.len() > MAX_APP_DATA_LEN => {
            return Err(CoreError::FrameTooLarge {
                len: 1 + payload.len(),
                max: MAX_TRANSPORT_PLAINTEXT,
            });
        }
        InnerFrameType::Padding => {
            if payload.len() > MAX_APP_DATA_LEN {
                return Err(CoreError::FrameTooLarge {
                    len: 1 + payload.len(),
                    max: MAX_TRANSPORT_PLAINTEXT,
                });
            }
            let mut nonzero = 0u8;
            for &b in payload {
                nonzero |= b;
            }
            if !bool::from(nonzero.ct_eq(&0u8)) {
                return Err(CoreError::InvalidInnerFramePayload(
                    "PADDING cover frame must contain only zero bytes",
                ));
            }
        }
        InnerFrameType::Padded => {
            if payload.len() > MAX_APP_DATA_LEN {
                return Err(CoreError::FrameTooLarge {
                    len: 1 + payload.len(),
                    max: MAX_TRANSPORT_PLAINTEXT,
                });
            }
            let mut full = Vec::with_capacity(1 + payload.len());
            full.push(InnerFrameType::Padded as u8);
            full.extend_from_slice(payload);
            crate::v2::unpad_inner_frame(&full)?;
        }
        InnerFrameType::Rekey
        | InnerFrameType::Ping
        | InnerFrameType::Pong
        | InnerFrameType::Close => {}
    }
    Ok(())
}

/// Encrypted `msg2` payload (`responder -> initiator`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHello {
    pub host_id: String,
    pub proto_version: u8,
    pub signing_pub: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotation: Vec<RotationRecord>,
}

/// Encrypted `msg3` payload for `intent = session` (`initiator -> responder`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHello {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_seq: Option<u64>,
}

/// Encrypted `msg3` payload for `intent = pair` (`initiator -> responder`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairClaim {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_pub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll_proof: Option<String>,
}

/// Encrypted post-handshake response frame for `intent = pair` (`responder -> initiator`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum PairResponse {
    Success {
        device_id: String,
        status: String,
        host_signing_pub: String,
    },
    Error {
        error: String,
    },
}

/// Incremental, bounded decoder for Tendril preambles and `uint16_be len || body` frames.
#[derive(Debug, Default)]
pub struct ResumableFrameReader {
    buf: Vec<u8>,
    offset: usize,
    expect_preamble: bool,
    preamble: Option<Preamble>,
}

impl ResumableFrameReader {
    /// Creates a reader expecting length-prefixed frames immediately (initiator side).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a reader expecting a 6-byte cleartext [`Preamble`] before any frames (responder side).
    #[must_use]
    pub fn with_preamble() -> Self {
        Self {
            buf: Vec::new(),
            offset: 0,
            expect_preamble: true,
            preamble: None,
        }
    }

    /// Returns the decoded preamble once [`Self::take_preamble`] has succeeded.
    #[must_use]
    pub const fn preamble(&self) -> Option<Preamble> {
        self.preamble
    }

    /// Appends received transport bytes, enforcing [`MAX_READ_BUFFER_LEN`] before allocation.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), CoreError> {
        if self.offset > 0 {
            let unread = self.buf.len() - self.offset;
            if unread == 0 {
                self.buf.clear();
                self.offset = 0;
            } else if self.offset >= 4096
                || self.buf.len().saturating_add(chunk.len()) > MAX_READ_BUFFER_LEN
            {
                self.buf.copy_within(self.offset.., 0);
                self.buf.truncate(unread);
                self.offset = 0;
            }
        }

        let unread = self.buf.len() - self.offset;
        let Some(total) = unread.checked_add(chunk.len()) else {
            return Err(CoreError::BufferOverflow {
                len: usize::MAX,
                max: MAX_READ_BUFFER_LEN,
            });
        };
        if total > MAX_READ_BUFFER_LEN {
            return Err(CoreError::BufferOverflow {
                len: total,
                max: MAX_READ_BUFFER_LEN,
            });
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// Consumes and validates the initial 6-byte [`Preamble`] once all 6 bytes have arrived.
    pub fn take_preamble(&mut self) -> Result<Option<Preamble>, CoreError> {
        if !self.expect_preamble {
            return Ok(self.preamble);
        }
        let unread = &self.buf[self.offset..];
        if unread.len() < PREAMBLE_LEN {
            return Ok(None);
        }
        let decoded = Preamble::decode(&unread[..PREAMBLE_LEN])?;
        self.offset += PREAMBLE_LEN;
        self.expect_preamble = false;
        self.preamble = Some(decoded);
        if self.offset >= self.buf.len() {
            self.buf.clear();
            self.offset = 0;
        }
        Ok(Some(decoded))
    }

    /// Decodes the next complete outer frame, immediately rejecting declared lengths above
    /// [`MAX_FRAME_LEN`] before buffering the payload.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, CoreError> {
        if self.expect_preamble {
            return Err(CoreError::ProtocolViolation(
                "preamble must be decoded before reading frames",
            ));
        }
        let unread = &self.buf[self.offset..];
        if unread.len() < 2 {
            return Ok(None);
        }
        let len = usize::from(u16::from_be_bytes([unread[0], unread[1]]));
        if len > MAX_FRAME_LEN {
            return Err(CoreError::FrameTooLarge {
                len,
                max: MAX_FRAME_LEN,
            });
        }
        let total = 2 + len;
        if unread.len() < total {
            return Ok(None);
        }
        let body = unread[2..total].to_vec();
        self.offset += total;
        if self.offset >= self.buf.len() {
            self.buf.clear();
            self.offset = 0;
        } else if self.offset >= 4096 {
            let rem = self.buf.len() - self.offset;
            self.buf.copy_within(self.offset.., 0);
            self.buf.truncate(rem);
            self.offset = 0;
        }
        Ok(Some(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_decode_validates_all_fields() {
        let sess = Preamble::v1(Intent::Session).encode();
        assert_eq!(
            Preamble::decode(&sess).unwrap(),
            Preamble::v1(Intent::Session)
        );

        let pair = Preamble::v1(Intent::Pair).encode();
        assert_eq!(Preamble::decode(&pair).unwrap(), Preamble::v1(Intent::Pair));

        assert_eq!(
            Preamble::decode(&sess[..5]),
            Err(CoreError::InvalidPreambleLength {
                expected: PREAMBLE_LEN,
                actual: 5
            })
        );
        assert_eq!(
            Preamble::decode(b"BAD\x01\x01\x00"),
            Err(CoreError::BadPreambleMagic)
        );
        assert_eq!(
            Preamble::decode(b"TND\x03\x01\x00"),
            Err(CoreError::UnsupportedVersion(0x03))
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x01\x00"),
            Ok(Preamble::v2(Intent::Session, PREAMBLE_FLAG_NONE))
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x02\x01"),
            Ok(Preamble::v2_pake_pair())
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x01\x01"),
            Err(CoreError::InvalidPreambleFlags {
                intent: 0x01,
                flags: 0x01
            })
        );
        assert_eq!(
            Preamble::decode(b"TND\x02\x02\x02"),
            Err(CoreError::InvalidPreambleFlags {
                intent: 0x02,
                flags: 0x02
            })
        );
        assert_eq!(
            Preamble::decode(b"TND\x01\x03\x00"),
            Err(CoreError::UnknownIntent(0x03))
        );
        assert_eq!(
            Preamble::decode(b"TND\x01\x01\x01"),
            Err(CoreError::NonZeroReserved(0x01))
        );
    }

    #[test]
    fn outer_frame_bounds_and_truncation() {
        let empty = encode_frame(&[]).unwrap();
        assert_eq!(empty, [0x00, 0x00]);
        assert_eq!(decode_frame(&empty).unwrap(), ([].as_slice(), 2));

        let max_body = vec![0xAA; MAX_FRAME_LEN];
        let max_framed = encode_frame(&max_body).unwrap();
        let (decoded, consumed) = decode_frame(&max_framed).unwrap();
        assert_eq!(decoded.len(), MAX_FRAME_LEN);
        assert_eq!(consumed, 2 + MAX_FRAME_LEN);

        let oversized = vec![0xBB; MAX_FRAME_LEN + 1];
        assert_eq!(
            encode_frame(&oversized),
            Err(CoreError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );

        assert_eq!(
            decode_frame(&[0x00]),
            Err(CoreError::TruncatedFrame {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            decode_frame(&[0x00, 0x05, 0x01, 0x02]),
            Err(CoreError::TruncatedFrame {
                expected: 7,
                actual: 4
            })
        );
        // Header length ceiling must be rejected before expecting the remaining payload bytes.
        let too_large_header = ((MAX_FRAME_LEN + 1) as u16).to_be_bytes();
        assert_eq!(
            decode_frame(&too_large_header),
            Err(CoreError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );
    }

    #[test]
    fn inner_frame_validation_and_close_ceiling() {
        assert_eq!(decode_inner_frame(&[]), Err(CoreError::EmptyInnerFrame));
        assert_eq!(
            decode_inner_frame(&[0x7F]),
            Err(CoreError::UnknownInnerFrameType(0x7F))
        );

        let max_data = vec![0x11; MAX_APP_DATA_LEN];
        let enc_data = encode_inner_frame(InnerFrameType::Data, &max_data).unwrap();
        assert_eq!(enc_data.len(), MAX_TRANSPORT_PLAINTEXT);
        assert_eq!(
            decode_inner_frame(&enc_data).unwrap(),
            (InnerFrameType::Data, max_data.as_slice())
        );

        let too_big_data = vec![0x11; MAX_APP_DATA_LEN + 1];
        assert_eq!(
            encode_inner_frame(InnerFrameType::Data, &too_big_data),
            Err(CoreError::FrameTooLarge {
                len: MAX_TRANSPORT_PLAINTEXT + 1,
                max: MAX_TRANSPORT_PLAINTEXT
            })
        );

        assert!(matches!(
            encode_inner_frame(InnerFrameType::Rekey, &[0x01]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));
        assert!(matches!(
            encode_inner_frame(InnerFrameType::Ping, &[0u8; 7]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));
        assert!(matches!(
            decode_inner_frame(&[InnerFrameType::Pong as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));
        assert!(matches!(
            encode_inner_frame(InnerFrameType::Close, &[0x00]),
            Err(CoreError::InvalidInnerFramePayload(_))
        ));

        let mut oversized_close_raw =
            vec![InnerFrameType::Close as u8; MAX_TRANSPORT_PLAINTEXT + 1];
        oversized_close_raw[1] = 0x00;
        oversized_close_raw[2] = 0x01;
        assert_eq!(
            decode_inner_frame(&oversized_close_raw),
            Err(CoreError::FrameTooLarge {
                len: MAX_TRANSPORT_PLAINTEXT + 1,
                max: MAX_TRANSPORT_PLAINTEXT
            })
        );
    }

    #[test]
    fn resumable_reader_handles_single_byte_splits_coalesced_frames_and_bounds() {
        let mut reader = ResumableFrameReader::with_preamble();
        assert_eq!(
            reader.next_frame(),
            Err(CoreError::ProtocolViolation(
                "preamble must be decoded before reading frames"
            ))
        );

        let mut stream = Preamble::v1(Intent::Session).encode().to_vec();
        stream.extend_from_slice(&encode_frame(&[]).unwrap());
        stream.extend_from_slice(&encode_frame(b"alpha").unwrap());
        stream.extend_from_slice(&encode_frame(b"beta").unwrap());

        let mut preamble = None;
        let mut frames = Vec::new();
        for b in &stream {
            reader.push(std::slice::from_ref(b)).unwrap();
            if preamble.is_none() {
                preamble = reader.take_preamble().unwrap();
                if preamble.is_none() {
                    continue;
                }
            }
            while let Some(frame) = reader.next_frame().unwrap() {
                frames.push(frame);
            }
        }

        assert_eq!(preamble, Some(Preamble::v1(Intent::Session)));
        assert_eq!(
            frames,
            vec![Vec::new(), b"alpha".to_vec(), b"beta".to_vec()]
        );

        // Two oversized length header bytes must fail immediately before payload arrives.
        let mut hdr_reader = ResumableFrameReader::new();
        hdr_reader
            .push(&((MAX_FRAME_LEN + 1) as u16).to_be_bytes())
            .unwrap();
        assert_eq!(
            hdr_reader.next_frame(),
            Err(CoreError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN
            })
        );

        // Buffer overflow must trigger cleanly before unbounded allocation.
        let mut overflow_reader = ResumableFrameReader::new();
        overflow_reader
            .push(&vec![0u8; MAX_READ_BUFFER_LEN])
            .unwrap();
        assert_eq!(
            overflow_reader.push(&[0x01]),
            Err(CoreError::BufferOverflow {
                len: MAX_READ_BUFFER_LEN + 1,
                max: MAX_READ_BUFFER_LEN
            })
        );
    }
}
