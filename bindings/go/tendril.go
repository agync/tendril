// Package tendril provides Go bindings over the callback-free tendril-ffi C ABI.
package tendril

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/tendril-ffi/include
#cgo linux LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -ltendril_ffi -Wl,-rpath,${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/release
#cgo darwin LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -ltendril_ffi -Wl,-rpath,${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/release

#include <stdlib.h>
#include "tendril.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

const (
	// SigningPubLen is the byte length of a hybrid Ed25519 + ML-DSA-65 public key.
	SigningPubLen = int(C.TENDRIL_SIGNING_PUB_LEN)
	// SigningHashLen is the byte length of a SHA-256 signing public key hash pin.
	SigningHashLen = int(C.TENDRIL_SIGNING_HASH_LEN)
)

// ErrWouldBlock indicates a polled FFI call timed out with no new event ready.
var ErrWouldBlock = errors.New("tendril: would block")

// EndpointInfo holds an endpoint's public identifiers returned by Endpoint.Info.
type EndpointInfo struct {
	HostID         string `json:"host_id"`
	DeviceID       string `json:"device_id"`
	StaticPub      string `json:"static_pub"`
	SigningPub     string `json:"signing_pub"`
	SigningPubHash string `json:"signing_pub_hash"`
	RelayPub       string `json:"relay_pub"`
}

// PairInitiateResult holds the client-side outcome of pairing initiation.
type PairInitiateResult struct {
	DeviceID      string `json:"device_id"`
	HostID        string `json:"host_id"`
	SAS           string `json:"sas"`
	Status        string `json:"status,omitempty"`
	HostConfirmed bool   `json:"host_confirmed,omitempty"`
}

// PairAcceptResult holds the server-side outcome of accepting a pairing connection.
type PairAcceptResult struct {
	DeviceID   string `json:"device_id"`
	SAS        string `json:"sas,omitempty"`
	Status     string `json:"status,omitempty"`
	TokenNonce string `json:"token_nonce,omitempty"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
}

// EnrollInitiateResult holds the client-side outcome of M2M enrollment initiation.
type EnrollInitiateResult struct {
	DeviceID        string `json:"device_id"`
	HostID          string `json:"host_id"`
	Status          string `json:"status"`
	HostRotationSeq uint64 `json:"host_rotation_seq"`
	TokenNonce      string `json:"token_nonce"`
}

// SessionEvent represents one polled decrypted session event from Session.PollEvent.
type SessionEvent struct {
	Event     string          `json:"event"`
	DataB64   string          `json:"data_b64,omitempty"`
	Direction string          `json:"direction,omitempty"`
	Grant     json.RawMessage `json:"grant,omitempty"`
	Issuer    string          `json:"issuer,omitempty"`
	Seq       uint64          `json:"seq,omitempty"`
	Cookie    uint64          `json:"cookie,omitempty"`
	Code      uint16          `json:"code,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Audit     json.RawMessage `json:"audit,omitempty"`
}

func lastError() string {
	var probe [256]C.char
	needed := C.tendril_last_error(&probe[0], C.size_t(len(probe)))
	if needed <= 1 {
		return ""
	}
	if int(needed) <= len(probe) {
		return C.GoString(&probe[0])
	}
	buf := make([]C.char, int(needed))
	C.tendril_last_error(&buf[0], C.size_t(len(buf)))
	return C.GoString(&buf[0])
}

func ffiErr(code C.int32_t) error {
	msg := lastError()
	if msg == "" {
		msg = fmt.Sprintf("code %d", int(code))
	}
	return fmt.Errorf("tendril ffi error (%d): %s", int(code), msg)
}

func toCStr(s, name string) (*C.char, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, fmt.Errorf("tendril: %s contains interior NUL byte", name)
	}
	return C.CString(s), nil
}

func withOptCStr(s, name string, fn func(*C.char) error) error {
	if s == "" {
		return fn(nil)
	}
	cs, err := toCStr(s, name)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(cs))
	return fn(cs)
}

func takeOutCStr(p *C.char) string {
	if p == nil {
		return ""
	}
	defer C.tendril_string_free(p)
	return C.GoString(p)
}

// DeviceID computes the dev_<hex16> identifier for a 32-byte X25519 static public key.
func DeviceID(staticPub [32]byte) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var out *C.char
	rc := C.tendril_device_id((*C.uint8_t)(unsafe.Pointer(&staticPub[0])), &out)
	if rc != C.TENDRIL_OK {
		return "", ffiErr(rc)
	}
	return takeOutCStr(out), nil
}

// FingerprintHost computes the base32 host fingerprint for a 32-byte public key.
func FingerprintHost(staticPub [32]byte) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var out *C.char
	rc := C.tendril_fingerprint_host((*C.uint8_t)(unsafe.Pointer(&staticPub[0])), &out)
	if rc != C.TENDRIL_OK {
		return "", ffiErr(rc)
	}
	return takeOutCStr(out), nil
}

// FingerprintDevice computes the uppercase hex device fingerprint for a 32-byte public key.
func FingerprintDevice(staticPub [32]byte) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var out *C.char
	rc := C.tendril_fingerprint_device((*C.uint8_t)(unsafe.Pointer(&staticPub[0])), &out)
	if rc != C.TENDRIL_OK {
		return "", ffiErr(rc)
	}
	return takeOutCStr(out), nil
}

// PairingSAS derives the 4x4 pairing SAS from a 32-byte handshake hash.
func PairingSAS(handshakeHash [32]byte) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var out *C.char
	rc := C.tendril_pairing_sas((*C.uint8_t)(unsafe.Pointer(&handshakeHash[0])), &out)
	if rc != C.TENDRIL_OK {
		return "", ffiErr(rc)
	}
	return takeOutCStr(out), nil
}

// ComputeCodeMAC computes Argon2id + HMAC-SHA256 pairing proof via tendril-ffi.
func ComputeCodeMAC(code string, handshakeHash [32]byte) ([32]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var mac [32]byte
	ccode, err := toCStr(code, "code")
	if err != nil {
		return [32]byte{}, err
	}
	defer C.free(unsafe.Pointer(ccode))
	rc := C.tendril_compute_code_mac(
		ccode,
		(*C.uint8_t)(unsafe.Pointer(&handshakeHash[0])),
		(*C.uint8_t)(unsafe.Pointer(&mac[0])),
	)
	if rc != C.TENDRIL_OK {
		return [32]byte{}, ffiErr(rc)
	}
	return mac, nil
}

// VerifyRotationChainJSON verifies a JSON array of rotation records against pinned keys.
func VerifyRotationChainJSON(
	pinnedSigningB64, pinnedStaticB64 string,
	pinnedSeq uint64,
	chainJSON, curStaticB64, curSigningB64 string,
) (uint64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cpsig, err := toCStr(pinnedSigningB64, "pinnedSigningB64")
	if err != nil {
		return 0, err
	}
	defer C.free(unsafe.Pointer(cpsig))
	cpstat, err := toCStr(pinnedStaticB64, "pinnedStaticB64")
	if err != nil {
		return 0, err
	}
	defer C.free(unsafe.Pointer(cpstat))
	cchain, err := toCStr(chainJSON, "chainJSON")
	if err != nil {
		return 0, err
	}
	defer C.free(unsafe.Pointer(cchain))
	ccstat, err := toCStr(curStaticB64, "curStaticB64")
	if err != nil {
		return 0, err
	}
	defer C.free(unsafe.Pointer(ccstat))
	ccsig, err := toCStr(curSigningB64, "curSigningB64")
	if err != nil {
		return 0, err
	}
	defer C.free(unsafe.Pointer(ccsig))

	var finalSeq C.uint64_t
	rc := C.tendril_verify_rotation_chain_json(
		cpsig, cpstat, C.uint64_t(pinnedSeq), cchain, ccstat, ccsig, &finalSeq,
	)
	if rc != C.TENDRIL_OK {
		return 0, ffiErr(rc)
	}
	return uint64(finalSeq), nil
}

// VerifyGrantJSON verifies a JSON capability grant and optional CRL against requestedCap.
func VerifyGrantJSON(
	grantJSON, issuerKeysJSON, expectedSubject, expectedRootIssuer, requestedCap string,
	nowUnix uint64,
	crlJSON string,
) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cgrant, err := toCStr(grantJSON, "grantJSON")
	if err != nil {
		return false, err
	}
	defer C.free(unsafe.Pointer(cgrant))
	ckeys, err := toCStr(issuerKeysJSON, "issuerKeysJSON")
	if err != nil {
		return false, err
	}
	defer C.free(unsafe.Pointer(ckeys))
	csubj, err := toCStr(expectedSubject, "expectedSubject")
	if err != nil {
		return false, err
	}
	defer C.free(unsafe.Pointer(csubj))
	croot, err := toCStr(expectedRootIssuer, "expectedRootIssuer")
	if err != nil {
		return false, err
	}
	defer C.free(unsafe.Pointer(croot))
	ccap, err := toCStr(requestedCap, "requestedCap")
	if err != nil {
		return false, err
	}
	defer C.free(unsafe.Pointer(ccap))

	var allowed C.uint8_t
	var rc C.int32_t
	if err := withOptCStr(crlJSON, "crlJSON", func(ccrl *C.char) error {
		rc = C.tendril_verify_grant_json(
			cgrant, ckeys, csubj, croot, ccap, C.uint64_t(nowUnix), ccrl, &allowed,
		)
		return nil
	}); err != nil {
		return false, err
	}
	if rc != C.TENDRIL_OK {
		return false, ffiErr(rc)
	}
	return allowed == 1, nil
}

// Endpoint wraps an opaque C TendrilEndpoint handle.
type Endpoint struct {
	mu  sync.RWMutex
	ptr *C.TendrilEndpoint
}

// NewEndpoint creates a new endpoint backed by stateDir (or ephemeral in-memory when empty).
func NewEndpoint(stateDir, hostID string) (*Endpoint, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var raw *C.TendrilEndpoint
	if err := withOptCStr(stateDir, "stateDir", func(cd *C.char) error {
		return withOptCStr(hostID, "hostID", func(ch *C.char) error {
			raw = C.tendril_endpoint_new(cd, ch)
			return nil
		})
	}); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("tendril_endpoint_new failed: %s", lastError())
	}
	ep := &Endpoint{ptr: raw}
	runtime.SetFinalizer(ep, (*Endpoint).Close)
	return ep, nil
}

// Close frees the underlying native TendrilEndpoint handle idempotently without blocking on active accepts.
func (ep *Endpoint) Close() error {
	ep.mu.RLock()
	h := ep.ptr
	if h != nil {
		C.tendril_endpoint_close(h)
	}
	runtime.KeepAlive(ep)
	ep.mu.RUnlock()

	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.ptr != nil {
		C.tendril_endpoint_free(ep.ptr)
		ep.ptr = nil
		runtime.SetFinalizer(ep, nil)
	}
	return nil
}

func (ep *Endpoint) withHandle(fn func(*C.TendrilEndpoint) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	defer runtime.KeepAlive(ep)
	if ep.ptr == nil {
		return errors.New("tendril: endpoint closed")
	}
	return fn(ep.ptr)
}

// Info returns the endpoint's public identifiers.
func (ep *Endpoint) Info() (EndpointInfo, error) {
	var info EndpointInfo
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var out *C.char
		if rc := C.tendril_endpoint_info_json(h, &out); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return json.Unmarshal([]byte(takeOutCStr(out)), &info)
	})
	return info, err
}

// ServeDirect binds a direct TCP listener (defaults to 127.0.0.1:0 when empty).
func (ep *Endpoint) ServeDirect(listenAddr string) (string, error) {
	var endpoint string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(listenAddr, "listenAddr", func(ca *C.char) error {
			rc = C.tendril_endpoint_serve_direct(h, ca, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		endpoint = takeOutCStr(out)
		return nil
	})
	return endpoint, err
}

// ServeRelay registers this endpoint on a relay URL and returns the bound relay endpoint.
func (ep *Endpoint) ServeRelay(relayURL, expectedHost string) (string, error) {
	var endpoint string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		curl, err := toCStr(relayURL, "relayURL")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(curl))
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(expectedHost, "expectedHost", func(ch *C.char) error {
			rc = C.tendril_endpoint_serve_relay(h, curl, ch, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		endpoint = takeOutCStr(out)
		return nil
	})
	return endpoint, err
}

// ServeP2p binds an iroh P2P listener ("default", "disabled", or relay URL) using the endpoint's derived P2P key.
func (ep *Endpoint) ServeP2p(relayMode string) (string, error) {
	var endpoint string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(relayMode, "relayMode", func(cm *C.char) error {
			rc = C.tendril_endpoint_serve_p2p(h, cm, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		endpoint = takeOutCStr(out)
		return nil
	})
	return endpoint, err
}

// IssueCode creates a one-time pairing code ("lan" or "remote").
func (ep *Endpoint) IssueCode(kind string) (string, error) {
	var code string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(kind, "kind", func(ck *C.char) error {
			rc = C.tendril_endpoint_issue_code(h, ck, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		code = takeOutCStr(out)
		return nil
	})
	return code, err
}

// PairInitiate dials endpoint with a pairing code and records the responder host pin
// (`Pending` awaiting ConfirmPeer on manual pairing).
func (ep *Endpoint) PairInitiate(endpoint, relayHost, code, name, kind string) (PairInitiateResult, error) {
	var res PairInitiateResult
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cep, err := toCStr(endpoint, "endpoint")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cep))
		ccode, err := toCStr(code, "code")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ccode))

		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(relayHost, "relayHost", func(cr *C.char) error {
			return withOptCStr(name, "name", func(cn *C.char) error {
				return withOptCStr(kind, "kind", func(ck *C.char) error {
					rc = C.tendril_endpoint_pair_initiate(h, cep, cr, ccode, cn, ck, &out)
					return nil
				})
			})
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return json.Unmarshal([]byte(takeOutCStr(out)), &res)
	})
	return res, err
}

// PairAccept waits up to timeoutMs for an incoming pairing connection.
func (ep *Endpoint) PairAccept(timeoutMs uint64) (PairAcceptResult, error) {
	var res PairAcceptResult
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var out *C.char
		rc := C.tendril_endpoint_pair_accept(h, C.uint64_t(timeoutMs), &out)
		if rc == C.TENDRIL_WOULD_BLOCK {
			return ErrWouldBlock
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return json.Unmarshal([]byte(takeOutCStr(out)), &res)
	})
	return res, err
}

// ConfirmPeer promotes a paired peer to Active, asserting sas when non-empty.
func (ep *Endpoint) ConfirmPeer(peerID, sas string) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		cp, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cp))
		var rc C.int32_t
		if err := withOptCStr(sas, "sas", func(cs *C.char) error {
			rc = C.tendril_endpoint_confirm_peer(h, cp, cs)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// MintGrant signs and stores a capability grant JSON for an Active peer.
func (ep *Endpoint) MintGrant(peerID string, caps []string, ttlSecs uint64) (string, error) {
	var grant string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		capsBytes, err := json.Marshal(caps)
		if err != nil {
			return err
		}
		cp, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cp))
		ccaps, err := toCStr(string(capsBytes), "caps")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ccaps))

		var out *C.char
		rc := C.tendril_endpoint_mint_grant(h, cp, ccaps, C.uint64_t(ttlSecs), &out)
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		grant = takeOutCStr(out)
		return nil
	})
	return grant, err
}

// RevokePeer marks peerID as Revoked and clears its grants.
func (ep *Endpoint) RevokePeer(peerID string) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		cp, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cp))
		if rc := C.tendril_endpoint_revoke_peer(h, cp); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// AddTrustAnchor registers an active hybrid signing trust anchor for autonomous M2M enrollment.
func (ep *Endpoint) AddTrustAnchor(anchorID string, signingPub []byte) error {
	if len(signingPub) != SigningPubLen {
		return fmt.Errorf("tendril: signingPub must be %d bytes (got %d)", SigningPubLen, len(signingPub))
	}
	defer runtime.KeepAlive(signingPub)
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		ca, err := toCStr(anchorID, "anchorID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ca))
		rc := C.tendril_endpoint_add_trust_anchor(
			h,
			ca,
			(*C.uint8_t)(unsafe.Pointer(&signingPub[0])),
			C.size_t(len(signingPub)),
		)
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// RevokeTrustAnchor revokes an external trust anchor and sibling anchors sharing its key.
func (ep *Endpoint) RevokeTrustAnchor(anchorID string) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		ca, err := toCStr(anchorID, "anchorID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ca))
		if rc := C.tendril_endpoint_revoke_trust_anchor(h, ca); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// MintEnrollmentToken mints a single-use M2M enrollment token JSON document.
func (ep *Endpoint) MintEnrollmentToken(targetHostID, subject string, ttlSecs uint64) (string, error) {
	var tokenJSON string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		ct, err := toCStr(targetHostID, "targetHostID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ct))

		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(subject, "subject", func(cs *C.char) error {
			rc = C.tendril_endpoint_mint_enrollment_token(h, ct, cs, C.uint64_t(ttlSecs), &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		tokenJSON = takeOutCStr(out)
		return nil
	})
	return tokenJSON, err
}

// EnrollInitiate dials endpoint with a pinned host key and single-use M2M enrollment token.
func (ep *Endpoint) EnrollInitiate(
	endpoint, relayHost, hostID string,
	hostStaticPub, hostSigningPub []byte,
	hostRotationSeq uint64,
	tokenJSON, name, kind string,
) (EnrollInitiateResult, error) {
	var res EnrollInitiateResult
	if len(hostStaticPub) != 32 {
		return res, fmt.Errorf("tendril: hostStaticPub must be 32 bytes (got %d)", len(hostStaticPub))
	}
	if len(hostSigningPub) != SigningPubLen && len(hostSigningPub) != SigningHashLen {
		return res, fmt.Errorf("tendril: hostSigningPub must be %d or %d bytes (got %d)", SigningPubLen, SigningHashLen, len(hostSigningPub))
	}
	defer runtime.KeepAlive(hostStaticPub)
	defer runtime.KeepAlive(hostSigningPub)
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cep, err := toCStr(endpoint, "endpoint")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cep))
		chid, err := toCStr(hostID, "hostID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(chid))
		ctok, err := toCStr(tokenJSON, "tokenJSON")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ctok))

		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(relayHost, "relayHost", func(cr *C.char) error {
			return withOptCStr(name, "name", func(cn *C.char) error {
				return withOptCStr(kind, "kind", func(ck *C.char) error {
					rc = C.tendril_endpoint_enroll_initiate(
						h,
						cep,
						cr,
						chid,
						(*C.uint8_t)(unsafe.Pointer(&hostStaticPub[0])),
						(*C.uint8_t)(unsafe.Pointer(&hostSigningPub[0])),
						C.size_t(len(hostSigningPub)),
						C.uint64_t(hostRotationSeq),
						ctok,
						cn,
						ck,
						&out,
					)
					return nil
				})
			})
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return json.Unmarshal([]byte(takeOutCStr(out)), &res)
	})
	return res, err
}

// Connect opens an authenticated Noise XX session toward targetHostID.
func (ep *Endpoint) Connect(endpoint, relayHost, targetHostID, grantJSON string) (*Session, error) {
	var sess *Session
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cep, err := toCStr(endpoint, "endpoint")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cep))
		ctarget, err := toCStr(targetHostID, "targetHostID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ctarget))

		var raw *C.TendrilSession
		if err := withOptCStr(relayHost, "relayHost", func(cr *C.char) error {
			return withOptCStr(grantJSON, "grantJSON", func(cg *C.char) error {
				raw = C.tendril_session_connect(h, cep, cr, ctarget, cg)
				return nil
			})
		}); err != nil {
			return err
		}
		if raw == nil {
			return fmt.Errorf("tendril_session_connect failed: %s", lastError())
		}
		sess = newSession(raw)
		return nil
	})
	return sess, err
}

// AcceptSession waits up to timeoutMs for an inbound authenticated session.
func (ep *Endpoint) AcceptSession(timeoutMs uint64) (*Session, error) {
	var sess *Session
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		raw := C.tendril_session_accept(h, C.uint64_t(timeoutMs))
		if raw == nil {
			return fmt.Errorf("tendril_session_accept failed: %s", lastError())
		}
		sess = newSession(raw)
		return nil
	})
	return sess, err
}

// Session wraps an opaque C TendrilSession handle.
type Session struct {
	mu  sync.RWMutex
	ptr *C.TendrilSession
}

func newSession(raw *C.TendrilSession) *Session {
	s := &Session{ptr: raw}
	runtime.SetFinalizer(s, (*Session).Close)
	return s
}

// Close frees the underlying native TendrilSession handle idempotently without blocking on active PollEvent calls.
func (s *Session) Close() error {
	s.mu.RLock()
	h := s.ptr
	if h != nil {
		C.tendril_session_shutdown(h)
	}
	runtime.KeepAlive(s)
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr != nil {
		C.tendril_session_free(s.ptr)
		s.ptr = nil
		runtime.SetFinalizer(s, nil)
	}
	return nil
}

func (s *Session) withHandle(fn func(*C.TendrilSession) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s.mu.RLock()
	defer s.mu.RUnlock()
	defer runtime.KeepAlive(s)
	if s.ptr == nil {
		return errors.New("tendril: session freed")
	}
	return fn(s.ptr)
}

// SendData sends encrypted 0x01 DATA over the session.
func (s *Session) SendData(payload []byte) error {
	defer runtime.KeepAlive(payload)
	return s.withHandle(func(h *C.TendrilSession) error {
		var ptr *C.uint8_t
		if len(payload) > 0 {
			ptr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
		}
		if rc := C.tendril_session_send_data(h, ptr, C.size_t(len(payload))); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// PollEvent waits up to timeoutMs for the next decrypted session event.
func (s *Session) PollEvent(timeoutMs uint64) (*SessionEvent, error) {
	var ev *SessionEvent
	err := s.withHandle(func(h *C.TendrilSession) error {
		var out *C.char
		rc := C.tendril_session_poll_event(h, C.uint64_t(timeoutMs), &out)
		switch rc {
		case C.TENDRIL_OK:
			var parsed SessionEvent
			if err := json.Unmarshal([]byte(takeOutCStr(out)), &parsed); err != nil {
				return err
			}
			ev = &parsed
			return nil
		case C.TENDRIL_WOULD_BLOCK:
			return ErrWouldBlock
		case C.TENDRIL_EOF:
			return io.EOF
		default:
			return ffiErr(rc)
		}
	})
	return ev, err
}

// Authorize checks requestedCap via default-deny evaluation on the session's roster state.
func (s *Session) Authorize(requestedCap string) (bool, error) {
	var allowedBool bool
	err := s.withHandle(func(h *C.TendrilSession) error {
		ccap, err := toCStr(requestedCap, "requestedCap")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ccap))
		var allowed C.uint8_t
		if rc := C.tendril_session_authorize(h, ccap, &allowed); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		allowedBool = allowed == 1
		return nil
	})
	return allowedBool, err
}

// Rekey rotates outgoing session keys (0x04 REKEY).
func (s *Session) Rekey() error {
	return s.withHandle(func(h *C.TendrilSession) error {
		if rc := C.tendril_session_rekey(h); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// CloseSession sends encrypted 0x07 CLOSE before freeing.
func (s *Session) CloseSession(code uint16, reason string) error {
	return s.withHandle(func(h *C.TendrilSession) error {
		var rc C.int32_t
		if err := withOptCStr(reason, "reason", func(cr *C.char) error {
			rc = C.tendril_session_close(h, C.uint16_t(code), cr)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}
