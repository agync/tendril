//! Wire message schema and Ed25519 challenge-response proofs for `spec/relay-v1.md`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tendril_core::MAX_FRAME_LEN;
use tendril_core::crypto::{b64url_decode_array, b64url_encode};
use tendril_core::error::CoreError;
use tendril_core::relay_auth::RelayAuthProof;

/// Canonical WebSocket path for Tendril v1 relays.
pub const RELAY_PATH: &str = "/v1/relay";

/// Canonical WebSocket path for Tendril v2 blinded-epoch relays (`spec/relay-v2.md`).
pub const RELAY_V2_PATH: &str = "/v2/relay";

/// 21-byte domain prefix for mailbox registration signatures.
pub const RELAY_REG_DOMAIN: &[u8] = b"tendril-relay-reg-v1\0";

/// 24-byte domain prefix for incoming stream acceptance signatures.
pub const RELAY_ACCEPT_DOMAIN: &[u8] = b"tendril-relay-accept-v1\0";

/// Maximum binary frame length forwarded by the relay (`2 B len + 65519 B body`).
pub const MAX_RELAY_FRAME_LEN: usize = 2 + MAX_FRAME_LEN;

/// Messages sent from the relay server to a WebSocket client during the control phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RelayServerMsg {
    Challenge {
        nonce: String,
        host: String,
        max_frame: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_required: Option<Vec<String>>,
    },
    Registered {
        #[serde(rename = "pub")]
        pub_key: String,
    },
    Incoming {
        conn_id: String,
    },
    Ready {
        conn_id: String,
    },
    Error {
        code: String,
    },
}

/// Messages sent from a WebSocket client to the relay server during the control phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RelayClientMsg {
    Register {
        #[serde(rename = "pub")]
        pub_key: String,
        sig: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<RelayAuthProof>,
    },
    Dial {
        target_pub: String,
        conn_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<RelayAuthProof>,
    },
    Accept {
        #[serde(rename = "pub")]
        pub_key: String,
        conn_id: String,
        sig: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<RelayAuthProof>,
    },
}

/// Messages sent from the `/v2/relay` server to a WebSocket client during the control phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RelayV2ServerMsg {
    Challenge {
        nonce: String,
        host: String,
        epoch: u64,
        max_frame: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_required: Option<Vec<String>>,
    },
    Registered {
        mailbox_id: String,
        epoch: u64,
    },
    Incoming {
        mailbox_id: String,
        epoch: u64,
        conn_id: String,
        dial_nonce: String,
        dial_token: String,
    },
    Ready {
        conn_id: String,
    },
    Error {
        code: String,
    },
}

/// Messages sent from a WebSocket client to the `/v2/relay` server during the control phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RelayV2ClientMsg {
    Register {
        mailbox_id: String,
        epoch: u64,
        sig: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<RelayAuthProof>,
    },
    Dial {
        target_mailbox_id: String,
        epoch: u64,
        conn_id: String,
        dial_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<RelayAuthProof>,
    },
    Accept {
        mailbox_id: String,
        epoch: u64,
        conn_id: String,
        sig: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<RelayAuthProof>,
    },
}

/// Builds the exact byte slice signed for `register`:
/// `"tendril-relay-reg-v1\0" || UTF-8(relay_host) || nonce`.
#[must_use]
pub fn relay_register_signed_bytes(relay_host: &str, nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELAY_REG_DOMAIN.len() + relay_host.len() + nonce.len());
    out.extend_from_slice(RELAY_REG_DOMAIN);
    out.extend_from_slice(relay_host.as_bytes());
    out.extend_from_slice(nonce);
    out
}

/// Builds the exact byte slice signed for `accept`:
/// `"tendril-relay-accept-v1\0" || UTF-8(relay_host) || nonce || conn_id`.
#[must_use]
pub fn relay_accept_signed_bytes(
    relay_host: &str,
    nonce: &[u8; 32],
    conn_id: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        RELAY_ACCEPT_DOMAIN.len() + relay_host.len() + nonce.len() + conn_id.len(),
    );
    out.extend_from_slice(RELAY_ACCEPT_DOMAIN);
    out.extend_from_slice(relay_host.as_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(conn_id);
    out
}

/// Signs a mailbox `register` proof using `signing_key` and returns `(b64url_pub, b64url_sig)`.
#[must_use]
pub fn sign_relay_register(
    signing_key: &SigningKey,
    relay_host: &str,
    nonce: &[u8; 32],
) -> (String, String) {
    let msg = relay_register_signed_bytes(relay_host, nonce);
    let sig: Signature = signing_key.sign(&msg);
    (
        b64url_encode(&signing_key.verifying_key().to_bytes()),
        b64url_encode(&sig.to_bytes()),
    )
}

/// Strictly verifies a mailbox `register` proof and returns the 32-byte mailbox Ed25519 key.
pub fn verify_relay_register(
    pub_b64: &str,
    sig_b64: &str,
    relay_host: &str,
    nonce: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    let pub_bytes: [u8; 32] = b64url_decode_array(pub_b64)?;
    let sig_bytes: [u8; 64] = b64url_decode_array(sig_b64)?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| CoreError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = relay_register_signed_bytes(relay_host, nonce);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| CoreError::InvalidSignature)?;
    Ok(pub_bytes)
}

/// Signs a stream `accept` proof using `signing_key` and returns `b64url_sig`.
#[must_use]
pub fn sign_relay_accept(
    signing_key: &SigningKey,
    relay_host: &str,
    nonce: &[u8; 32],
    conn_id: &[u8; 16],
) -> String {
    let msg = relay_accept_signed_bytes(relay_host, nonce, conn_id);
    let sig: Signature = signing_key.sign(&msg);
    b64url_encode(&sig.to_bytes())
}

/// Strictly verifies a stream `accept` proof and returns `(pub_bytes, conn_id_bytes)`.
pub fn verify_relay_accept(
    pub_b64: &str,
    conn_id_b64: &str,
    sig_b64: &str,
    relay_host: &str,
    nonce: &[u8; 32],
) -> Result<([u8; 32], [u8; 16]), CoreError> {
    let pub_bytes: [u8; 32] = b64url_decode_array(pub_b64)?;
    let conn_id: [u8; 16] = b64url_decode_array(conn_id_b64)?;
    let sig_bytes: [u8; 64] = b64url_decode_array(sig_b64)?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| CoreError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = relay_accept_signed_bytes(relay_host, nonce, &conn_id);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| CoreError::InvalidSignature)?;
    Ok((pub_bytes, conn_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_register_and_accept_proofs_bind_host_nonce_and_conn_id() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let other_sk = SigningKey::from_bytes(&[0x99; 32]);
        let nonce = [0x11; 32];
        let conn_id = [0x22; 16];

        let (pub_b64, reg_sig) = sign_relay_register(&sk, "relay.example", &nonce);
        assert_eq!(
            verify_relay_register(&pub_b64, &reg_sig, "relay.example", &nonce).unwrap(),
            sk.verifying_key().to_bytes()
        );
        assert!(verify_relay_register(&pub_b64, &reg_sig, "evil.example", &nonce).is_err());
        assert!(verify_relay_register(&pub_b64, &reg_sig, "relay.example", &[0x12; 32]).is_err());

        let (other_pub, _) = sign_relay_register(&other_sk, "relay.example", &nonce);
        assert!(verify_relay_register(&other_pub, &reg_sig, "relay.example", &nonce).is_err());

        let acc_sig = sign_relay_accept(&sk, "relay.example", &nonce, &conn_id);
        let conn_b64 = b64url_encode(&conn_id);
        assert_eq!(
            verify_relay_accept(&pub_b64, &conn_b64, &acc_sig, "relay.example", &nonce).unwrap(),
            (sk.verifying_key().to_bytes(), conn_id)
        );
        assert!(
            verify_relay_accept(
                &pub_b64,
                &b64url_encode(&[0x23; 16]),
                &acc_sig,
                "relay.example",
                &nonce
            )
            .is_err()
        );
    }
}
