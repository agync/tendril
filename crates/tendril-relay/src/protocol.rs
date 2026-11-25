//! Wire message schema and re-exported v1 challenge-response proofs for `spec/relay-v1.md`.

use serde::{Deserialize, Serialize};
pub use tendril_core::relay_auth::{
    MAX_RELAY_FRAME_LEN, MAX_STANDBY_PER_MAILBOX, RELAY_ACCEPT_DOMAIN, RELAY_HEALTH_PATH,
    RELAY_PATH, RELAY_REG_DOMAIN, RELAY_V2_PATH, RelayAuthProof, decode_init_frame,
    relay_accept_signed_bytes, relay_register_signed_bytes, sign_relay_accept, sign_relay_register,
    verify_relay_accept, verify_relay_register,
};

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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fast_open: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        standby: Option<bool>,
    },
    Registered {
        #[serde(rename = "pub")]
        pub_key: String,
    },
    StandbyReady,
    Incoming {
        conn_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        init_frame: Option<String>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fast_open: Option<bool>,
    },
    Standby {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        init_frame: Option<String>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fast_open: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        standby: Option<bool>,
    },
    Registered {
        mailbox_id: String,
        epoch: u64,
    },
    StandbyReady {
        mailbox_id: String,
        epoch: u64,
    },
    Incoming {
        mailbox_id: String,
        epoch: u64,
        conn_id: String,
        dial_nonce: String,
        dial_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        init_frame: Option<String>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fast_open: Option<bool>,
    },
    Standby {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        init_frame: Option<String>,
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

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use tendril_core::crypto::b64url_encode;

    use super::*;

    #[test]
    fn reexported_relay_proofs_roundtrip() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let nonce = [0x11; 32];
        let conn_id = [0x22; 16];
        let (pub_b64, reg_sig) = sign_relay_register(&sk, "relay.example", &nonce);
        assert!(verify_relay_register(&pub_b64, &reg_sig, "relay.example", &nonce).is_ok());
        let acc_sig = sign_relay_accept(&sk, "relay.example", &nonce, &conn_id);
        assert!(
            verify_relay_accept(
                &pub_b64,
                &b64url_encode(&conn_id),
                &acc_sig,
                "relay.example",
                &nonce,
            )
            .is_ok()
        );
    }
}
