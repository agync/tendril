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
	"sync"
	"unsafe"
)

// ErrWouldBlock indicates a polled FFI call timed out with no new event ready.
var ErrWouldBlock = errors.New("tendril: would block")

// EndpointInfo holds an endpoint's public identifiers returned by Endpoint.Info.
type EndpointInfo struct {
	HostID     string `json:"host_id"`
	DeviceID   string `json:"device_id"`
	StaticPub  string `json:"static_pub"`
	SigningPub string `json:"signing_pub"`
}

// PairInitiateResult holds the client-side outcome of pairing initiation.
type PairInitiateResult struct {
	DeviceID string `json:"device_id"`
	HostID   string `json:"host_id"`
	SAS      string `json:"sas"`
}

// PairAcceptResult holds the server-side outcome of accepting a pairing connection.
type PairAcceptResult struct {
	DeviceID string `json:"device_id"`
	SAS      string `json:"sas"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
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

func withOptCStr(s string, fn func(*C.char)) {
	if s == "" {
		fn(nil)
		return
	}
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	fn(cs)
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
	ccode := C.CString(code)
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
	cpsig := C.CString(pinnedSigningB64)
	cpstat := C.CString(pinnedStaticB64)
	cchain := C.CString(chainJSON)
	ccstat := C.CString(curStaticB64)
	ccsig := C.CString(curSigningB64)
	defer func() {
		C.free(unsafe.Pointer(cpsig))
		C.free(unsafe.Pointer(cpstat))
		C.free(unsafe.Pointer(cchain))
		C.free(unsafe.Pointer(ccstat))
		C.free(unsafe.Pointer(ccsig))
	}()

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
	cgrant := C.CString(grantJSON)
	ckeys := C.CString(issuerKeysJSON)
	csubj := C.CString(expectedSubject)
	croot := C.CString(expectedRootIssuer)
	ccap := C.CString(requestedCap)
	defer func() {
		C.free(unsafe.Pointer(cgrant))
		C.free(unsafe.Pointer(ckeys))
		C.free(unsafe.Pointer(csubj))
		C.free(unsafe.Pointer(croot))
		C.free(unsafe.Pointer(ccap))
	}()

	var allowed C.uint8_t
	var rc C.int32_t
	withOptCStr(crlJSON, func(ccrl *C.char) {
		rc = C.tendril_verify_grant_json(
			cgrant, ckeys, csubj, croot, ccap, C.uint64_t(nowUnix), ccrl, &allowed,
		)
	})
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
	withOptCStr(stateDir, func(cd *C.char) {
		withOptCStr(hostID, func(ch *C.char) {
			raw = C.tendril_endpoint_new(cd, ch)
		})
	})
	if raw == nil {
		return nil, fmt.Errorf("tendril_endpoint_new failed: %s", lastError())
	}
	ep := &Endpoint{ptr: raw}
	runtime.SetFinalizer(ep, (*Endpoint).Close)
	return ep, nil
}

// Close frees the underlying native TendrilEndpoint handle idempotently.
func (ep *Endpoint) Close() error {
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
		withOptCStr(listenAddr, func(ca *C.char) {
			rc = C.tendril_endpoint_serve_direct(h, ca, &out)
		})
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
		curl := C.CString(relayURL)
		defer C.free(unsafe.Pointer(curl))
		var out *C.char
		var rc C.int32_t
		withOptCStr(expectedHost, func(ch *C.char) {
			rc = C.tendril_endpoint_serve_relay(h, curl, ch, &out)
		})
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
		withOptCStr(kind, func(ck *C.char) {
			rc = C.tendril_endpoint_issue_code(h, ck, &out)
		})
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		code = takeOutCStr(out)
		return nil
	})
	return code, err
}

// PairInitiate dials endpoint with a pairing code and pins the responder host.
func (ep *Endpoint) PairInitiate(endpoint, relayHost, code, name, kind string) (PairInitiateResult, error) {
	var res PairInitiateResult
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cep := C.CString(endpoint)
		ccode := C.CString(code)
		defer C.free(unsafe.Pointer(cep))
		defer C.free(unsafe.Pointer(ccode))

		var out *C.char
		var rc C.int32_t
		withOptCStr(relayHost, func(cr *C.char) {
			withOptCStr(name, func(cn *C.char) {
				withOptCStr(kind, func(ck *C.char) {
					rc = C.tendril_endpoint_pair_initiate(h, cep, cr, ccode, cn, ck, &out)
				})
			})
		})
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
		cp := C.CString(peerID)
		defer C.free(unsafe.Pointer(cp))
		var rc C.int32_t
		withOptCStr(sas, func(cs *C.char) {
			rc = C.tendril_endpoint_confirm_peer(h, cp, cs)
		})
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
		cp := C.CString(peerID)
		ccaps := C.CString(string(capsBytes))
		defer C.free(unsafe.Pointer(cp))
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
		cp := C.CString(peerID)
		defer C.free(unsafe.Pointer(cp))
		if rc := C.tendril_endpoint_revoke_peer(h, cp); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// Connect opens an authenticated Noise XX session toward targetHostID.
func (ep *Endpoint) Connect(endpoint, relayHost, targetHostID, grantJSON string) (*Session, error) {
	var sess *Session
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cep := C.CString(endpoint)
		ctarget := C.CString(targetHostID)
		defer C.free(unsafe.Pointer(cep))
		defer C.free(unsafe.Pointer(ctarget))

		var raw *C.TendrilSession
		withOptCStr(relayHost, func(cr *C.char) {
			withOptCStr(grantJSON, func(cg *C.char) {
				raw = C.tendril_session_connect(h, cep, cr, ctarget, cg)
			})
		})
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
	mu  sync.Mutex
	ptr *C.TendrilSession
}

func newSession(raw *C.TendrilSession) *Session {
	s := &Session{ptr: raw}
	runtime.SetFinalizer(s, (*Session).Close)
	return s
}

// Close frees the underlying native TendrilSession handle idempotently.
func (s *Session) Close() error {
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
		ccap := C.CString(requestedCap)
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
		withOptCStr(reason, func(cr *C.char) {
			rc = C.tendril_session_close(h, C.uint16_t(code), cr)
		})
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}
