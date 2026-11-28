// Package tendril provides Go bindings over the callback-free tendril-ffi C ABI.
package tendril

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/tendril-ffi/include
#cgo linux LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -ltendril_ffi -Wl,-rpath,${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/release
#cgo darwin LDFLAGS: -L${SRCDIR}/../../target/debug -L${SRCDIR}/../../target/release -ltendril_ffi -Wl,-rpath,${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/release

#include <stdlib.h>
#include <string.h>
#include "tendril.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	// MlDsa65PubLen is the byte length of an ML-DSA-65 public key.
	MlDsa65PubLen = int(C.TENDRIL_MLDSA65_PUB_LEN)
	// MlDsa65SigLen is the byte length of an ML-DSA-65 signature.
	MlDsa65SigLen = int(C.TENDRIL_MLDSA65_SIG_LEN)
)

const (
	// CloseCodePeerRevoked is the close code of a host that refuses a revoked peer.
	CloseCodePeerRevoked uint16 = C.TENDRIL_CLOSE_PEER_REVOKED
	// CloseCodePeerPending is the close code of a host that refuses a peer it has not confirmed.
	CloseCodePeerPending uint16 = C.TENDRIL_CLOSE_PEER_PENDING
)

// ErrWouldBlock indicates a polled FFI call timed out with no new event ready.
var ErrWouldBlock = errors.New("tendril: would block")

// RefusalReason says why a host refused this device.
type RefusalReason string

const (
	// RefusalRevoked means the host blocks this device's key permanently. Re-pairing needs a new
	// device identity.
	RefusalRevoked RefusalReason = "revoked"
	// RefusalPending means the host has not confirmed this device yet. Retry with backoff.
	RefusalPending RefusalReason = "pending"
	// RefusalOther is a refusal with a close code in the 4400..4499 range.
	RefusalOther RefusalReason = "other"
)

// RefusedError reports an authenticated refusal: the host proved it knows this device and will
// not serve it. Match it with errors.As.
type RefusedError struct {
	Reason RefusalReason
	// CloseCode is the wire close code: CloseCodePeerRevoked or CloseCodePeerPending, and 0 for
	// RefusalOther when only the reason is known.
	CloseCode uint16
	// Code is the stable machine code: "refused_revoked", "refused_pending" or "refused".
	Code string
	// Message is the redacted last-error text of the failing call.
	Message string
}

func (e *RefusedError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("tendril: refused by peer (%s)", e.Reason)
	}
	return fmt.Sprintf("tendril: refused by peer (%s): %s", e.Reason, e.Message)
}

// refusalFromCode maps a stable last-error code to a *RefusedError, nil when it is no refusal.
func refusalFromCode(code, msg string) *RefusedError {
	switch code {
	case "refused_revoked":
		return &RefusedError{Reason: RefusalRevoked, CloseCode: CloseCodePeerRevoked, Code: code, Message: msg}
	case "refused_pending":
		return &RefusedError{Reason: RefusalPending, CloseCode: CloseCodePeerPending, Code: code, Message: msg}
	case "refused":
		return &RefusedError{Reason: RefusalOther, Code: code, Message: msg}
	}
	return nil
}

// RevokeOptions tunes Endpoint.RevokePeerWithOptions.
type RevokeOptions struct {
	// Notify chooses whether to record a refusal notice. Nil follows the endpoint policy.
	Notify *bool `json:"notify,omitempty"`
}

// RefusalPolicy is the host policy for refusing known peers. It persists with the roster.
type RefusalPolicy struct {
	// Pending refuses unconfirmed peers with close code 4004.
	Pending bool `json:"pending"`
	// RevokedNoticeTTLSecs is the lifetime of a notice recorded at revocation; 0 records none.
	RevokedNoticeTTLSecs uint64 `json:"revoked_notice_ttl_secs"`
}

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
	WireVersion   uint8  `json:"wire_version,omitempty"`
}

// PairAcceptResult holds the server-side outcome of accepting a pairing connection.
type PairAcceptResult struct {
	DeviceID    string `json:"device_id"`
	SAS         string `json:"sas,omitempty"`
	Status      string `json:"status,omitempty"`
	TokenNonce  string `json:"token_nonce,omitempty"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	WireVersion uint8  `json:"wire_version,omitempty"`
}

// EnrollInitiateResult holds the client-side outcome of M2M enrollment initiation.
type EnrollInitiateResult struct {
	DeviceID        string `json:"device_id"`
	HostID          string `json:"host_id"`
	Status          string `json:"status"`
	HostRotationSeq uint64 `json:"host_rotation_seq"`
	TokenNonce      string `json:"token_nonce"`
	// RoutesPersisted lists the Day-2 routes stored with the enrollment.
	RoutesPersisted []Route `json:"routes_persisted"`
	// RouteWarnings holds snake-case warning or reason codes for routes that were not stored.
	RouteWarnings []string `json:"route_warnings"`
	// RoutesReason is "no_state_dir" for a memory-only endpoint, which stores no routes,
	// and empty otherwise.
	RoutesReason string `json:"routes_reason"`
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
	// Refusal is "revoked", "pending" or "other" on a closed event of a session this endpoint
	// dialed that the host ended with a refusal code, and empty otherwise.
	Refusal string          `json:"refusal,omitempty"`
	Audit   json.RawMessage `json:"audit,omitempty"`
	// Endpoints with a state directory ingest ordinary-session group frames in the runtime and
	// report "group_manifest_ingested", "group_manifest_rejected", "group_rendezvous_ingested" or
	// "group_rendezvous_rejected" with GroupID, Seq and, on a rejection, Error. Rendezvous keys
	// never cross the boundary. Store-less endpoints report "group_manifest_unverified" (with
	// ManifestJSON, the input to Endpoint.GroupIngestManifest) and "group_rendezvous_unverified".
	GroupID      string `json:"group_id,omitempty"`
	ManifestJSON string `json:"manifest_json,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Refused returns the refusal a closed event carries, or nil.
func (e *SessionEvent) Refused() *RefusedError {
	if e == nil || e.Event != "closed" {
		return nil
	}
	switch RefusalReason(e.Refusal) {
	case RefusalRevoked:
		return refusalFromCode("refused_revoked", e.Reason)
	case RefusalPending:
		return refusalFromCode("refused_pending", e.Reason)
	case RefusalOther:
		r := refusalFromCode("refused", e.Reason)
		r.CloseCode = e.Code
		return r
	}
	return nil
}

// readLast copies the last FFI error text, or its stable code when code is true. The error
// state is thread-local: call it on the thread of the failing FFI call, before any other call.
func readLast(code bool) string {
	read := func(buf *C.char, n C.size_t) C.int32_t {
		if code {
			return C.tendril_last_error_code(buf, n)
		}
		return C.tendril_last_error(buf, n)
	}
	var probe [256]C.char
	needed := read(&probe[0], C.size_t(len(probe)))
	if needed <= 1 {
		return ""
	}
	if int(needed) <= len(probe) {
		return C.GoString(&probe[0])
	}
	buf := make([]C.char, int(needed))
	read(&buf[0], C.size_t(len(buf)))
	return C.GoString(&buf[0])
}

func lastError() string { return readLast(false) }

func lastErrorCode() string { return readLast(true) }

// failure reads the message and the stable code of the failing call together, as the last
// error of the calling thread. Every caller is inside a runtime.LockOSThread scope that
// started before the failing call, so no other call can replace or clear either value.
func failure() (msg, code string) {
	return lastError(), lastErrorCode()
}

func ffiErr(rc C.int32_t) error {
	msg, code := failure()
	if refused := refusalFromCode(code, msg); refused != nil {
		return refused
	}
	if msg == "" {
		msg = fmt.Sprintf("code %d", int(rc))
	}
	return fmt.Errorf("tendril ffi error (%d): %s", int(rc), msg)
}

// callFailed is the error of a pointer-returning call that returned NULL.
func callFailed(call string) error {
	msg, code := failure()
	if refused := refusalFromCode(code, msg); refused != nil {
		return refused
	}
	return fmt.Errorf("%s failed: %s", call, msg)
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

// VerifyWakeTag verifies wakeTagB64 against wakeSecret across the +-1 hour epoch window around
// nowUnixSecs.
func VerifyWakeTag(wakeSecret [32]byte, wakeTagB64 string, nowUnixSecs uint64) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ctag, err := toCStr(wakeTagB64, "wakeTagB64")
	if err != nil {
		return false, err
	}
	defer C.free(unsafe.Pointer(ctag))

	var matched C.uint8_t
	rc := C.tendril_verify_wake_tag(
		(*C.uint8_t)(unsafe.Pointer(&wakeSecret[0])),
		ctag,
		C.uint64_t(nowUnixSecs),
		&matched,
	)
	runtime.KeepAlive(wakeSecret)
	if rc != C.TENDRIL_OK {
		return false, ffiErr(rc)
	}
	return matched == 1, nil
}

// Endpoint wraps an opaque C TendrilEndpoint handle.
type Endpoint struct {
	mu  sync.RWMutex
	ptr *C.TendrilEndpoint

	// cfgMu serializes transport configuration and guards cfg, the last full transport
	// configuration sent through ConfigureTransportsJSON or ConfigureRoutes. The C ABI replaces
	// the whole configuration on every call, so ConfigureRoutes merges into this cache.
	// The cache holds relay tickets and secrets as Go strings that cannot be zeroized; Close
	// drops the reference, but the memory lives until the garbage collector reclaims it.
	cfgMu sync.Mutex
	cfg   map[string]json.RawMessage
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
// It also clears the transport configuration cache, which holds secrets until close.
func (ep *Endpoint) Close() error {
	ep.cfgMu.Lock()
	ep.cfg = nil
	ep.cfgMu.Unlock()
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

// ConfigureTransportsJSON applies a JSON transport configuration (relay auth, P2P, wake) to this endpoint.
// It replaces the whole configuration and updates the cache that ConfigureRoutes merges into.
func (ep *Endpoint) ConfigureTransportsJSON(transportConfigJSON string) error {
	ep.cfgMu.Lock()
	defer ep.cfgMu.Unlock()
	return ep.configureTransportsLocked(transportConfigJSON)
}

// configureTransportsLocked sends transportConfigJSON and caches it on success. cfgMu must be held.
func (ep *Endpoint) configureTransportsLocked(transportConfigJSON string) error {
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		ccfg, err := toCStr(transportConfigJSON, "transportConfigJSON")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ccfg))
		rc := C.tendril_endpoint_configure_transports_json(h, ccfg)
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
	if err != nil {
		return err
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(transportConfigJSON), &cfg); err != nil || cfg == nil {
		// Keep the previous cache rather than silently dropping credentials on the next merge.
		return fmt.Errorf("transport configuration applied but is not a JSON object; route cache unchanged")
	}
	ep.cfg = cfg
	return nil
}

// MintRelayTicket mints a canonical signed stateless Ed25519 RelayTicket JSON object.
func (ep *Endpoint) MintRelayTicket(relayHost, role, targetPubOrWildcard string, ttlSecs uint64) (string, error) {
	var ticket string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		chost, err := toCStr(relayHost, "relayHost")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(chost))
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(role, "role", func(cr *C.char) error {
			return withOptCStr(targetPubOrWildcard, "targetPubOrWildcard", func(ct *C.char) error {
				rc = C.tendril_endpoint_mint_relay_ticket(h, chost, cr, ct, C.uint64_t(ttlSecs), &out)
				return nil
			})
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		ticket = takeOutCStr(out)
		return nil
	})
	return ticket, err
}

// ServeRelayV2 registers blinded /v2/relay epoch mailboxes for peerIDOpt (or all active v2 peers when empty).
func (ep *Endpoint) ServeRelayV2(relayURL, expectedHost, peerIDOpt string) (string, error) {
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
			return withOptCStr(peerIDOpt, "peerIDOpt", func(cp *C.char) error {
				rc = C.tendril_endpoint_serve_relay_v2(h, curl, ch, cp, &out)
				return nil
			})
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

// ServeP2p binds an iroh P2P listener ("default", "disabled", or relay URL) using the endpoint's derived P2P key (or an ephemeral key when configured).
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

// ServeP2pV2 binds hourly-rotating iroh://v2 listener(s) ("default", "disabled", or relay URL) and tracks roster changes when peerID is empty.
func (ep *Endpoint) ServeP2pV2(relayMode, peerID string) (string, error) {
	var endpoint string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(relayMode, "relayMode", func(cm *C.char) error {
			return withOptCStr(peerID, "peerID", func(cp *C.char) error {
				rc = C.tendril_endpoint_serve_p2p_v2(h, cm, cp, &out)
				return nil
			})
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

// PairV2Initiate initiates a Wire v2 hybrid Argon2id PAKE + ML-KEM-768 pairing handshake toward endpoint.
func (ep *Endpoint) PairV2Initiate(endpoint, relayHost, code, name, kind, pinnedHostJSON string) (PairInitiateResult, error) {
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
					return withOptCStr(pinnedHostJSON, "pinnedHostJSON", func(cp *C.char) error {
						rc = C.tendril_endpoint_pair_v2_initiate(h, cep, cr, ccode, cn, ck, cp, &out)
						return nil
					})
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

// PairV2Accept accepts the next incoming Wire v2 PAKE pairing connection within timeoutMs.
func (ep *Endpoint) PairV2Accept(timeoutMs uint64) (PairAcceptResult, error) {
	var res PairAcceptResult
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var out *C.char
		rc := C.tendril_endpoint_pair_v2_accept(h, C.uint64_t(timeoutMs), &out)
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

// RevokePeer marks peerID as Revoked and clears its grants. Unless the endpoint refusal policy
// records no notice, the peer receives an authenticated refusal on its next session attempt. It
// shows up as a *RefusedError from ConnectV2, ConnectWithOptions with Wire 2, SendData, Rekey
// or CloseSession, or as SessionEvent.Refused on PollEvent.
func (ep *Endpoint) RevokePeer(peerID string) error {
	return ep.RevokePeerWithOptions(peerID, nil)
}

// RevokePeerWithOptions revokes peerID like RevokePeer. A nil opts, or a nil opts.Notify,
// follows the endpoint refusal policy; Notify set to false revokes silently.
func (ep *Endpoint) RevokePeerWithOptions(peerID string, opts *RevokeOptions) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		cp, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cp))
		var o any
		if opts != nil {
			o = opts
		}
		return withOptJSON(o, "opts", func(co *C.char) error {
			if rc := C.tendril_endpoint_revoke_peer_with_options(h, cp, co); rc != C.TENDRIL_OK {
				return ffiErr(rc)
			}
			return nil
		})
	})
}

// SetRefusalPolicy sets and persists the host refusal policy.
func (ep *Endpoint) SetRefusalPolicy(policy RefusalPolicy) error {
	raw, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		cp, err := toCStr(string(raw), "policy")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cp))
		if rc := C.tendril_endpoint_set_refusal_policy_json(h, cp); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// ClearRefusalNotice drops the refusal notice of peerID, which stays Revoked.
func (ep *Endpoint) ClearRefusalNotice(peerID string) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		cp, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cp))
		if rc := C.tendril_endpoint_clear_refusal_notice(h, cp); rc != C.TENDRIL_OK {
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

// Connect opens an authenticated Noise XX session toward targetHostID. An empty endpoint dials the
// peer's stored routes (signed, operator and committed); a non-empty one is an explicit operator
// endpoint, normalized and dialed alone.
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
			return callFailed("tendril_session_connect")
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

// ConnectV2 opens an authenticated Wire v2 pseudonymous session toward targetHostID via endpoint.
// An empty endpoint dials the peer's stored routes.
func (ep *Endpoint) ConnectV2(endpoint, relayHost, targetHostID, grantJSON string) (*Session, error) {
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
				raw = C.tendril_session_connect_v2(h, cep, cr, ctarget, cg)
				return nil
			})
		}); err != nil {
			return err
		}
		if raw == nil {
			return callFailed("tendril_session_connect_v2")
		}
		sess = newSession(raw)
		return nil
	})
	return sess, err
}

// AcceptV2 accepts and authenticates the next inbound Wire v2 session stream within timeoutMs.
func (ep *Endpoint) AcceptV2(timeoutMs uint64) (*Session, error) {
	var sess *Session
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		raw := C.tendril_session_accept_v2(h, C.uint64_t(timeoutMs))
		if raw == nil {
			return fmt.Errorf("tendril_session_accept_v2 failed: %s", lastError())
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

// PeerID returns the authenticated roster peer identifier for this session.
// Capability checks remain separate via Authorize.
func (s *Session) PeerID() (string, error) {
	var peerID string
	err := s.withHandle(func(h *C.TendrilSession) error {
		var out *C.char
		if rc := C.tendril_session_peer_id(h, &out); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		peerID = takeOutCStr(out)
		return nil
	})
	return peerID, err
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

func takeOutCBytes(p *C.char) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	defer C.tendril_string_free(p)
	n := C.strlen(p)
	if n == 0 {
		return []byte{}, nil
	}
	if n > C.size_t(math.MaxInt32) {
		return nil, errors.New("tendril: exported buffer exceeds max C.int size")
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// ExportRosterJSON returns the endpoint's current roster JSON. The result is secret material;
// callers should zero the returned slice once persisted.
func (ep *Endpoint) ExportRosterJSON() ([]byte, error) {
	var out []byte
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var raw *C.char
		if rc := C.tendril_endpoint_export_roster_json(h, &raw); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		var err error
		out, err = takeOutCBytes(raw)
		return err
	})
	return out, err
}

// ExportRosterJSON returns the session's shared roster JSON. The result is secret material;
// callers should zero the returned slice once persisted.
func (s *Session) ExportRosterJSON() ([]byte, error) {
	var out []byte
	err := s.withHandle(func(h *C.TendrilSession) error {
		var raw *C.char
		if rc := C.tendril_session_export_roster_json(h, &raw); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		var err error
		out, err = takeOutCBytes(raw)
		return err
	})
	return out, err
}

// BroadcastReport is the per-peer outcome of Group.Broadcast. Each Failed entry is
// [deviceID, error].
type BroadcastReport struct {
	Delivered []string    `json:"delivered"`
	Offline   []string    `json:"offline"`
	Failed    [][2]string `json:"failed"`
}

// GroupEvent is one event from Group.PollEvent. Event is one of "app_data", "manifest_updated",
// "member_joined", "member_revoked", or "audit".
type GroupEvent struct {
	Event          string          `json:"event"`
	SenderDeviceID string          `json:"sender_device_id,omitempty"`
	PayloadB64     string          `json:"payload_b64,omitempty"`
	Seq            uint64          `json:"seq,omitempty"`
	DeviceID       string          `json:"device_id,omitempty"`
	Audit          json.RawMessage `json:"audit,omitempty"`
}

// Payload decodes the application payload of an "app_data" event.
func (e *GroupEvent) Payload() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(e.PayloadB64)
}

func optJSONList(items []string, name string, fn func(*C.char) error) error {
	if len(items) == 0 {
		return fn(nil)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("tendril: encode %s: %w", name, err)
	}
	return withOptCStr(string(raw), name, fn)
}

// GroupCreate creates a group rooted at this endpoint's identity and returns the signed manifest
// JSON. The endpoint needs a state directory.
func (ep *Endpoint) GroupCreate(name string, minWireVersion uint8, endpoints []string) (string, error) {
	var manifest string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cname, err := toCStr(name, "name")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cname))
		var out *C.char
		var rc C.int32_t
		if err := optJSONList(endpoints, "endpoints", func(ce *C.char) error {
			rc = C.tendril_group_create(h, cname, C.uint8_t(minWireVersion), ce, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		manifest = takeOutCStr(out)
		return nil
	})
	return manifest, err
}

// GroupAddMember adds the enrolled peer peerID to a group this endpoint roots and returns the new
// manifest JSON. Empty caps grant the default send and receive capabilities.
func (ep *Endpoint) GroupAddMember(groupID, peerID string, caps, endpoints []string) (string, error) {
	var manifest string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cgid, err := toCStr(groupID, "groupID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cgid))
		cpeer, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cpeer))
		var out *C.char
		var rc C.int32_t
		if err := optJSONList(caps, "caps", func(cc *C.char) error {
			return optJSONList(endpoints, "endpoints", func(ce *C.char) error {
				rc = C.tendril_group_add_member(h, cgid, cpeer, cc, ce, &out)
				return nil
			})
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		manifest = takeOutCStr(out)
		return nil
	})
	return manifest, err
}

// GroupRemoveMember revokes peerID from a group this endpoint roots, rotates its keys, and returns
// the new manifest JSON.
func (ep *Endpoint) GroupRemoveMember(groupID, peerID string) (string, error) {
	var manifest string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cgid, err := toCStr(groupID, "groupID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cgid))
		cpeer, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cpeer))
		var out *C.char
		if rc := C.tendril_group_remove_member(h, cgid, cpeer, &out); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		manifest = takeOutCStr(out)
		return nil
	})
	return manifest, err
}

// GroupIngestManifest ingests a manifest received from the authenticated peer senderPeerID and
// returns its group id.
func (ep *Endpoint) GroupIngestManifest(manifestJSON, senderPeerID string) (string, error) {
	var groupID string
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cm, err := toCStr(manifestJSON, "manifestJSON")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cm))
		cs, err := toCStr(senderPeerID, "senderPeerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cs))
		var out *C.char
		if rc := C.tendril_group_ingest_manifest(h, cm, cs, &out); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		groupID = takeOutCStr(out)
		return nil
	})
	return groupID, err
}

// OpenGroup opens the lazy full-mesh pool for groupID. A non-empty listenAddr also binds a direct
// listener that the group serves, reported by Group.LocalEndpoint. Configure transports before the
// first call; after it, inbound sessions are routed through the group hub and ordinary sessions
// still arrive through AcceptSession and AcceptV2. Call ServeRelay before the first call too: the
// hub leaves the relay hosts served that way to the endpoint only for calls that returned before
// it, and a later ServeRelay on a relay host in the member's own entry competes with the group.
func (ep *Endpoint) OpenGroup(groupID, listenAddr string) (*Group, error) {
	var grp *Group
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cgid, err := toCStr(groupID, "groupID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cgid))
		var raw *C.TendrilGroup
		var rc C.int32_t
		if err := withOptCStr(listenAddr, "listenAddr", func(cl *C.char) error {
			rc = C.tendril_group_open(h, cgid, cl, &raw)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		grp = &Group{ptr: raw}
		runtime.SetFinalizer(grp, (*Group).Close)
		return nil
	})
	return grp, err
}

// Group wraps an opaque C TendrilGroup handle.
type Group struct {
	mu  sync.RWMutex
	ptr *C.TendrilGroup
}

// Close closes the group handle and frees it. It is idempotent. A PollEvent already waiting
// returns io.EOF promptly instead of running out its timeout.
func (g *Group) Close() error {
	g.mu.RLock()
	h := g.ptr
	if h != nil {
		C.tendril_group_close(h)
	}
	runtime.KeepAlive(g)
	g.mu.RUnlock()

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ptr != nil {
		C.tendril_group_free(g.ptr)
		g.ptr = nil
		runtime.SetFinalizer(g, nil)
	}
	return nil
}

func (g *Group) withHandle(fn func(*C.TendrilGroup) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	g.mu.RLock()
	defer g.mu.RUnlock()
	defer runtime.KeepAlive(g)
	if g.ptr == nil {
		return errors.New("tendril: group closed")
	}
	return fn(g.ptr)
}

// Broadcast sends data to every reachable member holding the receive capability. An empty
// requiredCap uses the group's default send capability.
func (g *Group) Broadcast(data []byte, requiredCap string) (*BroadcastReport, error) {
	defer runtime.KeepAlive(data)
	var report BroadcastReport
	err := g.withHandle(func(h *C.TendrilGroup) error {
		var ptr *C.uint8_t
		if len(data) > 0 {
			ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
		}
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(requiredCap, "requiredCap", func(cc *C.char) error {
			rc = C.tendril_group_broadcast(h, cc, ptr, C.size_t(len(data)), &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return json.Unmarshal([]byte(takeOutCStr(out)), &report)
	})
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// PollEvent waits up to timeoutMs for the next group event. It returns (nil, nil) on timeout and
// io.EOF once the pool is closed or this handle is closed while the call is waiting.
func (g *Group) PollEvent(timeoutMs uint64) (*GroupEvent, error) {
	var ev *GroupEvent
	err := g.withHandle(func(h *C.TendrilGroup) error {
		var out *C.char
		rc := C.tendril_group_poll_event(h, C.uint64_t(timeoutMs), &out)
		switch rc {
		case C.TENDRIL_OK:
			var parsed GroupEvent
			if err := json.Unmarshal([]byte(takeOutCStr(out)), &parsed); err != nil {
				return err
			}
			ev = &parsed
			return nil
		case C.TENDRIL_WOULD_BLOCK:
			return nil
		case C.TENDRIL_EOF:
			return io.EOF
		default:
			return ffiErr(rc)
		}
	})
	return ev, err
}

// Sync pushes the stored manifest (and, for an admin, the rendezvous key) to every member. Wire v2
// groups need it to keep members current; the runtime refuses it for non-admins.
func (g *Group) Sync() (*BroadcastReport, error) {
	var report BroadcastReport
	err := g.withHandle(func(h *C.TendrilGroup) error {
		var out *C.char
		if rc := C.tendril_group_sync(h, &out); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return json.Unmarshal([]byte(takeOutCStr(out)), &report)
	})
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// LocalEndpoint returns the endpoint bound by OpenGroup's listenAddr, or "" when none was set.
func (g *Group) LocalEndpoint() (string, error) {
	var endpoint string
	err := g.withHandle(func(h *C.TendrilGroup) error {
		var out *C.char
		if rc := C.tendril_group_local_endpoint(h, &out); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		endpoint = takeOutCStr(out)
		return nil
	})
	return endpoint, err
}

// AuthorizePeer returns nil when peerID currently holds capability in the group, and the core error
// otherwise.
func (g *Group) AuthorizePeer(peerID, capability string) error {
	return g.withHandle(func(h *C.TendrilGroup) error {
		cpeer, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cpeer))
		ccap, err := toCStr(capability, "capability")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ccap))
		if rc := C.tendril_group_authorize_peer(h, cpeer, ccap); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// RouteConfig holds the route and power keys of the transport configuration. Nil and empty-string
// fields are left unchanged, so the endpoint keeps its defaults ("auto" advertising, "all_signed"
// policy, signed routes). For the list fields, nil leaves the current value and a pointer to an
// empty slice clears it.
type RouteConfig struct {
	// AdvertisedEndpoints lists extra hints added to the announced route set.
	AdvertisedEndpoints *[]string `json:"advertised_endpoints,omitempty"`
	// RelayAuthOrigins lists "scheme://host[:port]" origins that may receive relay admission material.
	RelayAuthOrigins *[]string `json:"relay_auth_origins,omitempty"`
	// Advertise is "auto" (default) or "explicit".
	Advertise string `json:"advertise,omitempty"`
	// RoutePolicy is "all_signed" (default), "committed_only" or "none".
	RoutePolicy string `json:"route_policy,omitempty"`
	// SignRoutes overrides route signing for issued URIs; nil keeps the default (true).
	SignRoutes *bool `json:"sign_routes,omitempty"`
	// PowerProfile selects "standard" or "low_power" background socket/probe policy.
	PowerProfile string `json:"power_profile,omitempty"`
}

// ConfigureRoutes merges the set route keys of c into the last full transport configuration
// this binding sent and applies the result. Other keys, such as relay credentials, are kept.
func (ep *Endpoint) ConfigureRoutes(c RouteConfig) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var routes map[string]json.RawMessage
	if err := json.Unmarshal(raw, &routes); err != nil {
		return err
	}
	ep.cfgMu.Lock()
	defer ep.cfgMu.Unlock()
	merged := make(map[string]json.RawMessage, len(ep.cfg)+len(routes))
	for k, v := range ep.cfg {
		merged[k] = v
	}
	for k, v := range routes {
		merged[k] = v
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	return ep.configureTransportsLocked(string(out))
}

// IssuePairingURIOptions selects how Endpoint.IssuePairingURI builds a URI. Zero values keep defaults.
type IssuePairingURIOptions struct {
	// Kind is "auto", "lan" or "remote".
	Kind     string `json:"kind,omitempty"`
	HostName string `json:"host_name,omitempty"`
	// SignRoutes overrides the endpoint's route signing default; nil keeps it.
	SignRoutes *bool `json:"sign_routes,omitempty"`
}

// DroppedHint is a hint left out of the announced set or the URI, with the reason.
type DroppedHint struct {
	Hint   string `json:"hint"`
	Reason string `json:"reason"`
}

// IssuedPairingURI is the result of Endpoint.IssuePairingURI.
type IssuedPairingURI struct {
	URI        string        `json:"uri"`
	CodeKind   string        `json:"code_kind"`
	Dropped    []DroppedHint `json:"dropped"`
	URILen     int           `json:"uri_len"`
	QRVersionM int           `json:"qr_version_m"`
	// RouteSeq is nil when the URI carries no route statement.
	RouteSeq *uint64 `json:"route_seq"`
}

// withOptJSON marshals v and passes it as a C string, or passes nil when v is nil.
func withOptJSON(v any, name string, fn func(*C.char) error) error {
	if v == nil {
		return fn(nil)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("tendril: %s: %w", name, err)
	}
	return withOptCStr(string(raw), name, fn)
}

// decodeOut frees out and decodes its JSON into v.
func decodeOut(out *C.char, v any) error {
	return json.Unmarshal([]byte(takeOutCStr(out)), v)
}

// IssuePairingURI builds a pairing URI from the announced route set. The endpoint becomes a
// route-announcing host on first use. A nil opts keeps every default.
func (ep *Endpoint) IssuePairingURI(opts *IssuePairingURIOptions) (IssuedPairingURI, error) {
	var res IssuedPairingURI
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var o any
		if opts != nil {
			o = opts
		}
		var out *C.char
		var rc C.int32_t
		if err := withOptJSON(o, "opts", func(co *C.char) error {
			rc = C.tendril_endpoint_issue_pairing_uri(h, co, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return decodeOut(out, &res)
	})
	return res, err
}

// PairURIOptions tunes Endpoint.PairURI and Endpoint.PairV2URI. Zero values keep defaults.
type PairURIOptions struct {
	// RoutePolicy is "all_signed", "committed_only" or "none".
	RoutePolicy string `json:"route_policy,omitempty"`
	// SaveRoute persists the committed route of an unsigned URI.
	SaveRoute bool `json:"save_route,omitempty"`
	// Endpoint is dialed alone and stored as an operator route.
	Endpoint string `json:"endpoint,omitempty"`
	// Code overrides the code carried by the URI.
	Code string `json:"code,omitempty"`
}

// Route is one stored route and the source that produced it ("operator", "signed", "committed").
type Route struct {
	Hint   string `json:"hint"`
	Source string `json:"source"`
}

// SkippedHint is a hint that was reported and never dialed.
type SkippedHint struct {
	Hint   string `json:"hint"`
	Reason string `json:"reason"`
}

// PairURIResult is the client-side outcome of pairing through a URI.
type PairURIResult struct {
	DeviceID      string `json:"device_id"`
	HostID        string `json:"host_id"`
	SAS           string `json:"sas"`
	Status        string `json:"status"`
	HostConfirmed bool   `json:"host_confirmed"`
	Provider      string `json:"provider"`
	Endpoint      string `json:"endpoint"`
	Committed     bool   `json:"committed"`
	// RouteCheck is "verified", "unsigned" or "route_key_rotated".
	RouteCheck      string  `json:"route_check"`
	RoutesPersisted []Route `json:"routes_persisted"`
	// RoutesReason is "unsigned_uri", "route_key_rotated" or "stale_route_seq" when the
	// pairing wrote no routes, and empty otherwise.
	RoutesReason string        `json:"routes_reason"`
	Skipped      []SkippedHint `json:"skipped"`
}

func (ep *Endpoint) pairURI(v2 bool, uri, name, kind string, opts *PairURIOptions) (PairURIResult, error) {
	var res PairURIResult
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		curi, err := toCStr(uri, "uri")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(curi))
		var o any
		if opts != nil {
			o = opts
		}
		var out *C.char
		var rc C.int32_t
		if err := withOptCStr(name, "name", func(cn *C.char) error {
			return withOptCStr(kind, "kind", func(ck *C.char) error {
				return withOptJSON(o, "opts", func(co *C.char) error {
					if v2 {
						rc = C.tendril_endpoint_pair_v2_uri(h, curi, cn, ck, co, &out)
					} else {
						rc = C.tendril_endpoint_pair_uri(h, curi, cn, ck, co, &out)
					}
					return nil
				})
			})
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return decodeOut(out, &res)
	})
	return res, err
}

// PairURI pairs through a pairing URI over Wire v1: the URI hints race and the first success
// commits. An empty name or kind keeps the runtime default. A nil opts keeps every default.
func (ep *Endpoint) PairURI(uri, name, kind string, opts *PairURIOptions) (PairURIResult, error) {
	return ep.pairURI(false, uri, name, kind, opts)
}

// PairV2URI pairs through a pairing URI over Wire v2, trying one hint at a time.
func (ep *Endpoint) PairV2URI(uri, name, kind string, opts *PairURIOptions) (PairURIResult, error) {
	return ep.pairURI(true, uri, name, kind, opts)
}

// ConnectOptions tunes Endpoint.ConnectWithOptions. Zero values keep defaults.
type ConnectOptions struct {
	// Wire is 1 (default) or 2.
	Wire uint8 `json:"wire,omitempty"`
	// Grant is a grant JSON object.
	Grant json.RawMessage `json:"grant,omitempty"`
	// Endpoint is dialed alone as an operator endpoint; empty dials the stored routes.
	Endpoint string `json:"endpoint,omitempty"`
	// RelayHost is the expected relay host of an explicit Endpoint, or the Iroh relay mode for
	// an iroh:// Endpoint. It is ignored without Endpoint.
	RelayHost string `json:"relay_host,omitempty"`
	// RecoveryURI is a signed pairing URI whose routes are tried and, when newer, applied.
	RecoveryURI   string `json:"recovery_uri,omitempty"`
	ReplaceRoutes bool   `json:"replace_routes,omitempty"`
	// RoutePolicy is "all_signed", "committed_only" or "none".
	RoutePolicy string `json:"route_policy,omitempty"`
	// IdleTimeoutMs closes an idle session after this many milliseconds of no application frames.
	IdleTimeoutMs uint64 `json:"idle_timeout_ms,omitempty"`
}

// ConnectWithOptions opens a session toward targetHostID, dialing its stored routes unless
// opts.Endpoint is set. A nil opts connects over Wire v1 without a grant. With Wire 2 a host
// refusal returns a *RefusedError; over Wire v1 the refusal arrives after the call, as a closed
// SessionEvent.
func (ep *Endpoint) ConnectWithOptions(targetHostID string, opts *ConnectOptions) (*Session, error) {
	var sess *Session
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		ctarget, err := toCStr(targetHostID, "targetHostID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(ctarget))
		var o any
		if opts != nil {
			o = opts
		}
		var raw *C.TendrilSession
		if err := withOptJSON(o, "opts", func(co *C.char) error {
			raw = C.tendril_session_connect_with_options(h, ctarget, co)
			return nil
		}); err != nil {
			return err
		}
		if raw == nil {
			return callFailed("tendril_session_connect_with_options")
		}
		sess = newSession(raw)
		return nil
	})
	return sess, err
}

// RouteMeta is the provenance of a peer's signed routes.
type RouteMeta struct {
	Seq      uint64 `json:"seq"`
	IssuedAt uint64 `json:"issued_at"`
	// Origin is how the routes arrived, for example "uri", "session" or "approved".
	Origin string `json:"origin"`
}

// RouteSetOutcome is the last route set a session delivered for a peer.
type RouteSetOutcome struct {
	Outcome string `json:"outcome"`
	Seq     uint64 `json:"seq"`
}

// PeerRoutes is the stored routing view of one peer.
type PeerRoutes struct {
	Routes []Route `json:"routes"`
	// RouteMeta is nil until signed routes were stored.
	RouteMeta *RouteMeta `json:"route_meta"`
	// LastRouteSet is nil until a route set arrived.
	LastRouteSet *RouteSetOutcome `json:"last_route_set"`
}

// SetPeerRoutes replaces peerID's operator routes with routes (at most six). One invalid entry
// rejects the whole list and nothing is written.
func (ep *Endpoint) SetPeerRoutes(peerID string, routes []string) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		cpeer, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cpeer))
		if routes == nil {
			routes = []string{}
		}
		raw, err := json.Marshal(routes)
		if err != nil {
			return err
		}
		croutes, err := toCStr(string(raw), "routes")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(croutes))
		if rc := C.tendril_endpoint_set_peer_routes(h, cpeer, croutes); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}

// PeerRoutes returns the stored routes and route provenance of peerID.
func (ep *Endpoint) PeerRoutes(peerID string) (PeerRoutes, error) {
	var res PeerRoutes
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		cpeer, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cpeer))
		var out *C.char
		if rc := C.tendril_endpoint_peer_routes(h, cpeer, &out); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return decodeOut(out, &res)
	})
	return res, err
}

// ClearPeerRoutes removes peerID's routes of one source: "operator" (the default for an empty
// source), "signed", "committed" or "all". The route provenance is kept.
func (ep *Endpoint) ClearPeerRoutes(peerID, source string) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		cpeer, err := toCStr(peerID, "peerID")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(cpeer))
		return withOptCStr(source, "source", func(cs *C.char) error {
			if rc := C.tendril_endpoint_clear_peer_routes(h, cpeer, cs); rc != C.TENDRIL_OK {
				return ffiErr(rc)
			}
			return nil
		})
	})
}

// ApplyRouteURIOptions tunes Endpoint.ApplyRouteURI. Zero values keep defaults.
type ApplyRouteURIOptions struct {
	// ReplaceRoutes approves replacing the stored signed routes when the URI is not newer.
	ReplaceRoutes bool `json:"replace_routes,omitempty"`
	// RoutePolicy is "all_signed", "committed_only" or "none".
	RoutePolicy string `json:"route_policy,omitempty"`
}

// ApplyRouteURIResult is the outcome of Endpoint.ApplyRouteURI.
type ApplyRouteURIResult struct {
	PeerID  string `json:"peer_id"`
	Applied bool   `json:"applied"`
	// Reason names why the URI was not applied (for example "stale_route_seq"); empty when applied.
	Reason   string  `json:"reason"`
	RouteSeq *uint64 `json:"route_seq"`
}

// ApplyRouteURI applies a fresh host-signed pairing URI offline to the paired host whose keys it
// carries. A nil opts keeps every default.
func (ep *Endpoint) ApplyRouteURI(uri string, opts *ApplyRouteURIOptions) (ApplyRouteURIResult, error) {
	var res ApplyRouteURIResult
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		curi, err := toCStr(uri, "uri")
		if err != nil {
			return err
		}
		defer C.free(unsafe.Pointer(curi))
		var o any
		if opts != nil {
			o = opts
		}
		var out *C.char
		var rc C.int32_t
		if err := withOptJSON(o, "opts", func(co *C.char) error {
			rc = C.tendril_endpoint_apply_route_uri(h, curi, co, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return decodeOut(out, &res)
	})
	return res, err
}

// Network is one network of a NetworkSnapshot.
type Network struct {
	ID      string `json:"id"`
	Iface   string `json:"iface"`
	IfIndex uint32 `json:"if_index"`
	// Transports lists "wifi", "ethernet", "cellular", "vpn" or "other".
	Transports []string `json:"transports"`
	Addrs      []string `json:"addrs"`
}

// NetworkSnapshot is the complete current network state, never a delta.
type NetworkSnapshot struct {
	Networks []Network `json:"networks"`
}

// normalized returns a copy whose nil slices are empty, since the C ABI rejects JSON null lists.
func (s *NetworkSnapshot) normalized() NetworkSnapshot {
	out := NetworkSnapshot{Networks: make([]Network, len(s.Networks))}
	for i, n := range s.Networks {
		if n.Transports == nil {
			n.Transports = []string{}
		}
		if n.Addrs == nil {
			n.Addrs = []string{}
		}
		out.Networks[i] = n
	}
	return out
}

// RefreshRoutesResult is the outcome of Endpoint.RefreshRoutes.
type RefreshRoutesResult struct {
	RouteSeq uint64 `json:"route_seq"`
	Changed  bool   `json:"changed"`
}

// RefreshRoutes re-scans the host's addresses and announces a new route set when they changed.
// A nil snapshot lets the runtime enumerate natively (or reuse the retained snapshot).
func (ep *Endpoint) RefreshRoutes(snapshot *NetworkSnapshot) (RefreshRoutesResult, error) {
	var res RefreshRoutesResult
	err := ep.withHandle(func(h *C.TendrilEndpoint) error {
		var s any
		if snapshot != nil {
			s = snapshot.normalized()
		}
		var out *C.char
		var rc C.int32_t
		if err := withOptJSON(s, "snapshot", func(cs *C.char) error {
			rc = C.tendril_endpoint_refresh_routes(h, cs, &out)
			return nil
		}); err != nil {
			return err
		}
		if rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return decodeOut(out, &res)
	})
	return res, err
}

// SetExternalPathMonitor informs the route announcer whether an external OS path monitor delivers
// network change events (active == true suppresses periodic background route polling).
func (ep *Endpoint) SetExternalPathMonitor(active bool) error {
	return ep.withHandle(func(h *C.TendrilEndpoint) error {
		var flag C.int32_t
		if active {
			flag = 1
		}
		if rc := C.tendril_endpoint_set_external_path_monitor(h, flag); rc != C.TENDRIL_OK {
			return ffiErr(rc)
		}
		return nil
	})
}
