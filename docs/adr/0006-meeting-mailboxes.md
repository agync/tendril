---
type: Decision
title: "0006 Meeting mailboxes from a shared secret"
description: Proposed design for short-lived relay mailboxes derived from a typed pairing code and a 15-minute epoch, admitted on allowlist relays by narrow host-delegated tickets whose lifetime and stream budget the relay enforces.
status: draft
tags: [adr, relay, pairing, privacy, security]
---

# 0006 Meeting mailboxes from a shared secret

> **Status: Proposed.** No spec or code changes yet. The follow-up work at the end lists what acceptance would start and the existing relay and roster behaviour the design relies on.

## Context

A **meeting mailbox** is a relay mailbox whose key both peers derive from a short shared secret, so a client that holds only a typed code and a relay origin can find the host without a QR code, an `rp` key, or any address. The host registers the derived key; the client dials it; Wire v2 PAKE pairing then runs over the bridged stream.

What exists today:

- Pairing over a relay uses the host's **identity mailbox**: the `/v1/relay` key `rp`, which is the Ed25519 half of the host's signing key (`spec/pairing-v1.md` Sections 6.4, 6.6). `/v2/relay` hints are never dialed during pairing (`spec/pairing-v1.md` Section 6.6, `spec/wire-v2.md` Section 3.2.3 rule 5), because the per-epoch mailbox needs a `mailbox_secret` that only a completed pairing exports (`spec/wire-v2.md` Section 3.1.1).
- A derived key already works on an **open** `/v1/relay`: `register` needs only a strict Ed25519 signature under the registered key over the challenge nonce and host (`spec/relay-v1.md` Section 2.1). An embedding app's prototype paired from typed characters alone this way, and a wrong code failed at once with `offline`.

Three gaps block a first-class pattern:

1. **Admission.** A Tier 1 allowlist relay admits only listed keys (`spec/relay-v1.md` Section 2.5, `verify_register_or_accept_admission` in `crates/tendril-relay/src/server.rs`). A derived key is not listed, so the pattern fails on the kind of relay an embedding app would ship on.
2. **Lifetime.** On an open relay, and for a key admitted by the allowlist, a `/v1/relay` registration lives until its control socket closes. A registration admitted by a ticket ends at `not_after + 30 s` (`spec/relay-v1.md` Section 2.5), but nothing gives a derived key a short ticket today, and a stream bridged before the deadline runs on until either side closes it or `idle_timeout` (`300 s`) passes. `/v2/relay` registrations end at the epoch window, `(epoch + 2) * 3600` (`handle_v2_register`), which is hours, not minutes.
3. **QR size.** An M2M enrollment token is a hybrid signed grant whose `3,373`-byte signature (`spec/pairing-v1.md` Sections 1, 7.1) makes it about 4.7 KB as JSON. Tendril QR codes use ECC M (`spec/pairing-v1.md` Section 6.2), whose largest version holds `2,331` bytes (`QR_BYTE_CAPACITY_M` in `crates/tendril-core/src/pairing.rs`), and the soft target is `711` bytes.

This ADR answers six questions: derivation, lifetime, admission, compact QR, interaction with pairing URIs and M2M routes, and abuse.

### Threat model

| Actor | Sees | Can do |
|---|---|---|
| Relay operator (or the platform hosting the relay) | Every `register`, `dial`, `accept` frame, admission tickets, client and host IPs, and the cleartext Noise `msg1` payload including PAKE `channel_salt` and `init_mac` (`spec/pairing-v1.md` Section 6.8, Disclosure before `HostHello`) | Test code guesses offline against any oracle it holds, batched across every meeting it sees; precompute for salts it can predict; withhold, inject or race dials; register keys it can sign for |
| Passive network observer | WSS ciphertext and timing | Nothing at the mailbox layer (`spec/relay-v1.md` Section 1) |
| Code holder (shoulder-surfer, forwarded screenshot, another host on the same relay) | The code | Everything the legitimate client can do with it, and on an open relay everything the host can do with the meeting key |
| Online guesser | Relay responses | Dial derived keys at the relay's per-IP rate (`spec/relay-v1.md` Section 3) |

## Decision

### 1. Derivation: Argon2id over the code, salted by the relay host and a 15-minute epoch

| Option | Offline attack from `mailbox_pub` | Notes |
|---|---|---|
| A. HKDF-SHA256 of the code, fixed salt | One hash and one Ed25519 key generation per guess; one table serves every relay forever | Far cheaper than the PAKE oracle the relay already holds |
| B. Argon2id, salt = relay host only | One `Argon2id(19 MiB)` per guess, but the salt never changes: one guess tests every meeting ever registered on that relay, and a table built months ahead stays valid | Rejected |
| C. **Argon2id, salt = relay host and a 15-minute epoch** | One `Argon2id(19 MiB)` per guess tests every meeting live on that relay in one epoch; a table serves one named epoch only | Recommended |
| D. Split code: mailbox from the first group, PAKE over the rest | About 19.8 bits leak from the mailbox; the relay also sees `init_mac`, so offline PAKE strength drops to 8 characters (`2^39.6`), the `Lan2Group` strength that `spec/pairing-v1.md` Section 3.1 keeps off relay paths | Rejected |
| E. Salt supplied by the relay | The relay is the adversary | Rejected |

**Recommendation: C.**

```text
MEETING_EPOCH_SECS = 900
meeting_epoch = unix_secs / MEETING_EPOCH_SECS
meeting_salt  = SHA-256("tendril-meeting-salt-v1\0" || UTF-8(canonical(relay_host))
                        || uint64_be(meeting_epoch))[0..16]
meeting_key   = argon2id(password = UTF-8(code_normalized), salt = meeting_salt,
                         t = 2, m = 19456, p = 1, keyLen = 32, version = 0x13)
mailbox_seed  = HKDF-SHA256(ikm = meeting_key, salt = meeting_salt, info = "tendril-meeting-v1-ed25519")
(mailbox_sk, mailbox_pub) = Ed25519_Keypair_From_Seed(mailbox_seed)
```

- `code_normalized` follows `spec/pairing-v1.md` Section 3.2. `canonical` is `canonical_relay_host` (`crates/tendril-core/src/v2.rs`; rules in `spec/relay-v2.md` Section 3 and `spec/relay-v1.md` Section 2.5). It drops the port, so all ports on one host share a salt. The labels are placeholders until the spec fixes them with vectors.
- The code MUST be `Remote3Group` (`31^12 ~= 2^59.4`). A `Lan2Group` code never travels a relay path (`spec/pairing-v1.md` Sections 3.1, 6.3 rule 1), and a meeting mailbox is always a relay path. The core API takes a validated, issued, single-use `Remote3Group` code type, not raw bytes or strings, so an embedding app cannot feed it a reusable room code or a passphrase. A reused secret would make `mailbox_pub` a cross-session beacon and a dictionary target.
- PAKE is unchanged. It still runs `Argon2id` over the same code with a fresh random `channel_salt` and different HKDF labels (`spec/wire-v2.md` Section 3.2.1), so the meeting key and the PAKE keys are independent.

**Epoch handling.** Before it displays the code, the host registers the key of **every** epoch from `epoch(issued_at - 120 s)` to `epoch(expires_at + 120 s)`. That span is at most `900 + 240 = 1,140 s`, so a code has **at most 3** registrations, all live before anyone sees the code. Registering them up front matters: a code holder cannot pre-register a later epoch's key and so slip past the issuer binding of Section 3. Each registration has its own ticket (Section 3) with `not_before = issued_at` and `not_after = min(expires_at, end of that epoch) + 120 s`.

The client derives the key for its own current epoch `E` and dials. On `offline` it makes one second dial: to `E - 1` in the first half of its epoch, to `E + 1` in the second half. At most 2 `Argon2id` derivations. Skew tolerance: the first dial always hits while the client and host clocks differ by at most `120 s`, because the host covers `120 s` past both ends of the code's lifetime. The second dial extends this to any skew under `450 s` (half an epoch): the epoch the host is in is always registered and is always the neighbour the client probes. A dial on the wrong epoch gets `offline` before any `msg1` and reveals nothing. The derivation spec must define `E - 1` at `E = 0` (no underflow; skip the probe).

**Offline attack: the corrected comparison with PAKE.** The first draft said option C costs the same as the `init_mac` oracle. That was wrong for a static salt, and it is still not exactly true with an epoch:

| Property | PAKE `init_mac` (`spec/wire-v2.md` Section 3.2.1) | Meeting key, option C |
|---|---|---|
| Salt | 16 random bytes, fresh in every `msg1` | Predictable: relay host and epoch |
| One `Argon2id` guess tests | One code against one handshake | One code against every meeting key of that epoch under that relay host. Keys of different epochs never share an evaluation |
| Precomputation | Impossible | Possible for one named future epoch on one relay; useless for any other epoch |
| Oracle available from | `msg1` | Registration |

Only the relay operator sees `mailbox_pub` (in `register`, `spec/relay-v1.md` Section 2.1). Batching gains it a factor of `M`, the number of distinct meeting keys registered under that relay host in one epoch. A hostile relay is not bound by its own `max_mailboxes` setting, so `M` is set by how many meetings honest hosts open there; `M = 1024` is only an example. With `N = 31^12` codes, the expected number of guesses to recover any one of `M` codes is `N / (M + 1)`, about `2^49.45` `Argon2id(19 MiB)` evaluations for `M = 1024`, and the median is `N ln 2 / M`, about `2^48.9`. Both must fit inside the epoch's 900 seconds. A precomputed table of `2^40` evaluations for one epoch hits each meeting in that epoch with probability `2^40 / 31^12 ~= 1.4 * 10^-6`, and has to be rebuilt for each of the 96 epochs in a day. Targeting a chosen meeting stays infeasible. The residual weakness against `init_mac` is the batching factor and per-epoch precomputation. It cannot be removed: the only inputs both sides share are the code, the relay and the clock, and anything random would have to be typed. If the residual is ever unacceptable, the next step is a longer code, which needs a new code kind (`spec/pairing-v1.md` Section 6.3 accepts only 2 or 3 groups).

**What a code holder can do**, however the code was learned:

- Dial first and complete PAKE as the client. This burns the host's code and leaves a `pending` host-side entry that cannot open sessions until the operator compares the SAS (`spec/pairing-v1.md` Section 5). The result is denial: the user issues a new code.
- Displace the host and answer the client. On an open relay the code holder can sign with `mailbox_sk`, and registration is last writer wins (`spec/relay-v1.md` Section 2.4). PAKE then succeeds, because PAKE proves knowledge of the code and nothing about host identity. A typed-code client holds no host pin. Section 5 states the defence and its limits.
- Learn nothing about completed sessions: Noise keys do not derive from the code.

**What PAKE protects.** The code never crosses the wire; a peer without it gets an indistinguishable decoy `msg2`, never sees `HostHello`, and charges no live code (`spec/wire-v2.md` Section 3.2.2). PAKE does not protect against a code holder. Code secrecy, the single-use burn, and the SAS or a QR pin remain the security of the pairing.

**Discovery and squatting without the code.** The relay learns that some meeting is open and when, not which code. Registering or accepting on a meeting key requires a signature under `mailbox_sk` (`spec/relay-v1.md` Sections 2.1, 2.3), so nobody without the code can squat it.

### 2. Lifetime: the ticket's `not_after`, enforced by the relay on registrations and streams

| Option | Relay-enforced | Cost |
|---|---|---|
| A. Host only (open relays today) | No: an unticketed registration and its streams outlive the code | None, but a crashed or hostile host leaves a mailbox open indefinitely |
| B. **Reuse `RelayTicket` validity, which already ends ticket-admitted registrations at `not_after + 30 s`, and for meeting tickets also end bridged streams there** | Yes | One meeting-only relay rule, no new bytes |
| C. New lifetime field in `register` | Yes | New control frame field in both relay specs and every client |
| D. Use `/v2/relay` epoch expiry | Yes, at hour scale | Too coarse, and `/v2/relay` has no workable Tier 1 (Section 3) |

**Recommendation: B.** The ticket format and its `1..=86400 s` bound (`spec/relay-v1.md` Section 2.5, `MAX_RELAY_TICKET_TTL_SECS` in `crates/tendril-core/src/relay_auth.rs`) stay unchanged. For a registration admitted by a delegated meeting ticket (Section 3):

- The relay caps `not_after - not_before` at a configurable `max_meeting_ttl`, default `1,200 s`: the default pairing code TTL of `900 s` (`spec/pairing-v1.md` Section 5) plus the `120 s` skew cover of Section 1 and headroom, since every ticket starts at `issued_at`.
- At `not_after + 30 s` the relay ends the registration as `spec/relay-v1.md` Section 2.5 already requires for every ticket-admitted registration: it closes the control socket, delivers no further dial, and fails pending dials with `offline` (`spec/relay-v1.md` Section 2.2); an `accept` for a pending dial fails. For a meeting ticket the relay also **closes every bridged stream** the registration accepted, which Section 2.5 otherwise lets finish. The meeting stream budget of Section 3 bounds those streams earlier still.
- The host mints `not_after` as in Section 1. After a **successful** burn it keeps the code's registrations until the original expiry, and after every stream on a key, successful or not, it re-registers that key with a fresh ticket while the code's lifetime remains (each registration accepts only one stream, Section 3). Dials after the burn get decoys because no live code matches (`spec/wire-v2.md` Section 3.2.2). Unregistering at a successful burn, or re-registering only after failures, would tell the relay whether pairing succeeded. The hiding is partial: it holds only while the per-issuer admission window has room, and an embedding app may opt to free the slots early and accept the leak.
- After a **failed** burn (displacement, the decoy cap of Section 6) the host releases the code's registrations at once: the failure is visible anyway. When a new code needs room under the per-issuer quota (Section 3), the host evicts the registrations of its oldest successfully burned code first. If the admission window is exhausted, issuing the new code fails visibly rather than registering only part of its epochs.
- The relay deadline is the backstop for a host that does none of this.

The stream cut and the TTL cap apply only to delegated meeting tickets, so other Tier 3 deployments keep the Section 2.5 behaviour, where bridged streams finish. On an open relay there is no ticket and lifetime stays host-enforced; the helper documents that.

### 3. Admission on Tier 1 allowlist relays: narrow host-delegated meeting tickets

Today the relay accepts a ticket only from a key in `trusted_issuers`, and Tier 1 is `allowlist OR proof` (`spec/relay-v1.md` Section 2.5, `verify_admission_proof` in `crates/tendril-relay/src/server.rs`). An allowlisted key is not an issuer.

**Can Tier 3 carry a host-minted, minutes-scale meeting ticket without protocol change? Yes, with caveats.** The operator lists the host's Ed25519 key with `--issuer-pub` as well as on the allowlist, and the host mints:

```jsonc
{ "v": 1, "issuer_pub": "<host Ed25519>", "relay_host": "<relay>", "role": "register",
  "target_pub": "<mailbox_pub>", "not_before": <now>, "not_after": <see Section 1>, "sig": "..." }
```

Every field satisfies today's verification: a TTL of a few minutes is inside `1..=86400 s`, a concrete `target_pub` binds the one mailbox, and the signing domain `tendril-relay-ticket-v1\0` is distinct from the host key's other Ed25519 domains (`spec/pairing-v1.md` Section 6.5). The caveats:

- A trusted issuer's authority is unbounded: wildcard targets, role `any`, `24 h` TTLs, any number of mailboxes. The host could admit arbitrary keys, which makes the allowlist advisory.
- Configuring an issuer makes `auth_scope` default to `all`, with or without an allowlist, so dials require admission unless `register-only` is set explicitly (`spec/relay-v1.md` Section 2.5). A typed-code client holds no dial credential (`spec/pairing-v1.md` Section 6.9). The same applies to any relay that runs Tier 1 and Tier 3 together.
- The registration ends at `not_after + 30 s` (Section 2.5), but its bridged streams run on and nothing caps the TTL at meeting scale.

| Option | Protocol change | Assessment |
|---|---|---|
| (a) Host key as trusted issuer | None | Works today as a stopgap; over-grants authority; registrations end at `not_after + 30 s` but streams run on and the TTL is not capped at meeting scale |
| (b) Relay-side "meeting" scope admitting unlisted keys with rate limits | Relay policy | Anyone can mint a key, so the allowlist relay becomes open for meeting-shaped traffic. Rejected |
| (c) **Delegated meeting tickets from allowlisted keys, with a meeting stream budget** | Relay verification rule and limits; ticket bytes unchanged | Recommended |
| (d) Tier 2 HMAC secret shared with hosts | None | Any holder admits any key, with no per-host revocation. Rejected |

**Recommendation: (c).** Behind an opt-in relay setting, a `RelayTicket` whose `issuer_pub` is a Tier 1 allowlisted key and not a trusted issuer is accepted for `register` and `accept` only when all of the following hold. The relay refuses to start with the setting on while any key is both allowlisted and a trusted issuer, because a trusted-issuer ticket would satisfy the normal rule and skip every limit below; this also catches an operator migrating from option (a) who forgot to remove `--issuer-pub`.

What an issuer may mint for:

- every existing check of `spec/relay-v1.md` Section 2.5 except issuer trust, which is replaced by allowlist membership;
- `role == "register"`, and `target_pub` is a concrete key that is neither `"*"`, nor the issuer, nor any allowlisted key;
- `not_after - not_before <= max_meeting_ttl`.

How the registration behaves:

- **Bound to its issuer.** A delegated registration records its ticket's `issuer_pub`. While it is live, a `register` for the same key succeeds only with a ticket from the same issuer (a host reconnecting); any other issuer gets `unauthorized`. This stops another allowlisted host that learned a code from displacing the meeting on a multi-host relay. It holds only because the host registers every epoch of the code before showing it (Section 1).
- **Accept is checked against the binding.** Under `spec/relay-v1.md` Section 2.5 each `accept` is checked against its own proof when it arrives, not against who registered. For a delegated registration the relay additionally requires `accept.auth.ticket.issuer_pub` to equal the registration's bound issuer, and the accept consumes the registration's stream budget.
- **No standby sockets.** A parked standby socket bridges a dial without an `accept` (`spec/relay-v1.md` Section 2.2), which would skip the issuer check and the stream budget, so `standby` on a delegated registration fails with `unauthorized`. Every meeting stream therefore passes through `accept`.
- **One stream per registration, ever.** A delegated registration accepts at most **one** stream over its whole life, not one at a time. The stream closes after `60 s` or `256 KiB` in both directions together, whichever comes first, and in any case at the Section 2 deadline. A Wire v2 PAKE exchange is four frames, each at most one `63,488`-byte bucket (`spec/wire-v2.md` Section 3.2.2), so this fits the largest pairing. Further dials get `offline`; the host re-registers if it wants another stream (Section 2).
- **Per-issuer live quota.** At most `12` live delegated registrations per issuer (3 epochs for each of `MAX_LIVE_PAIRING_CODES = 4`, `crates/tendril-core/src/pairing.rs`), counting a registration until its control socket **and** its stream have closed. Closing a control socket frees nothing while its stream runs.
- **Per-issuer admission window.** At most `16` delegated registrations **admitted** per issuer in any rolling `900 s`, counting every admitted `register`, including re-registrations of the same key. Without it, closing registrations and registering fresh keys would recycle the live quota indefinitely. Above either limit: `rate_limited`. Both numbers are configurable defaults; 16 covers one code's 3 registrations for each of 4 codes plus 4 re-registrations.

With only an allowlist configured, dials stay open (`register-only` behaviour).

**What a hostile issuer can still do.** The relay cannot tell a code-derived key from any other key, so a compromised allowlisted host can hand a third party meeting slots. The window caps that at 16 streams per `900 s`, each at most `60 s` and `256 KiB`, so at most 4 MiB per 15 minutes per issuer: far less than the host could relay by proxying through its own allowlisted mailbox.

**Who presents what.**

| Operation | Presenter | Proof |
|---|---|---|
| `register` on the meeting key | Host | `sig` under `mailbox_sk` (`spec/relay-v1.md` Section 2.1) plus `auth` = the delegated ticket |
| `accept` | Host | `sig` under `mailbox_sk` over the accept input plus a ticket whose `issuer_pub` matches the registration's bound issuer (`spec/relay-v1.md` Section 2.3); consumes the one-stream budget |
| `standby` | Nobody | Refused on delegated registrations |
| `dial` | Client | Nothing under `register-only`. Under `all`, only a credential the embedding app configured for that exact relay origin (`spec/pairing-v1.md` Section 6.9), never anything derived from the code |

The ticket travels only between host and relay. The client never sees it.

**Linkability.** A ticket is presented verbatim, and `issuer_pub` names the host's allowlisted key, so the relay links the meeting mailbox, and the client IP and time that dial it, to that key. For a host that already keeps its identity mailbox on that `/v1/relay`, this adds little: the relay already sees the key and the host's IP, and a QR pairing already shows `rp` to the relay operator (`spec/pairing-v1.md` Section 6.8). For a host that never registers there, for example a Wire v2 host using `/v2/relay` epoch mailboxes or a direct path on day 2, it is **new**: the relay learns the host's long-term Ed25519 key, its IP, its pairing times and its clients' IPs. Such a host should use a separate per-host meeting issuer key that is allowlisted but never registers. Meetings then link to each other through that issuer, not to the identity, the same class of caveat as wildcard tickets in `spec/relay-v2.md` Section 3.5. A concrete-target ticket covers one mailbox.

**Why `/v1/relay`, not `/v2/relay`.** Tier 1 on `/v2/relay` matches concrete epoch keys only when configured per epoch (`spec/relay-v2.md` Section 3.5), so it cannot admit meetings; PAKE pairing already runs on `/v1/relay`; and a single-use, minutes-scale key gains nothing from hourly epoch rotation. Feeding `meeting_key` into the `spec/relay-v2.md` Section 2.2 derivation stays possible later for Tier 2 or Tier 3 relays.

### 4. Compact QR: the pairing URI, not the enrollment token

| Option | Fits 711 B | Host pin | Assessment |
|---|---|---|---|
| A. Enrollment token in the QR | No (about 4.7 KB, above even the `2,331`-byte ECC M maximum) | Yes | A shorter signed form means dropping ML-DSA-65 ([ADR 0004](0004-hybrid-post-quantum-v1.md)). Rejected |
| B. Code and relay only | Yes | No | Client must SAS-confirm; strictly weaker than C when a QR is available |
| C. **Pairing URI of `spec/pairing-v1.md` Section 6** | Yes: about 335 B with a 3-group code, `k`, `sh`, one `/v1/relay` hint, `rp`, `rq` and `rs` | Yes (`k`, `sh`) | Recommended |
| D. Short secret in the QR; token, pin and routes fetched through a mailbox derived from it | Yes | Via the mailbox | Rebuilds pairing as a second sealed channel in every embedding app; M2M still needs a `PinnedHost` (`spec/pairing-v1.md` Section 7.3) delivered the same way |

**Recommendation: C.** Meeting mailboxes do not change the QR; they serve the case with no QR at all. A phone scanning a QR is human code pairing, so it needs no enrollment token. M2M enrollment stays for headless machines, with the token delivered out of band (`spec/pairing-v1.md` Section 7). A pinned QR also defeats the displacement attack of Section 5, so an embedding app that can show a QR should prefer it to a typed code.

What moves on-wire instead of into the QR: the full `1,984`-byte host `signing_pub` in `msg2`, checked against `sh` ([ADR 0004](0004-hybrid-post-quantum-v1.md) Section 2, `spec/pairing-v1.md` Section 6.1); the client's signing key claim in `msg3` (`spec/pairing-v1.md` Section 4.1); and the host's routes, through the `rs` statement and later `ROUTE_SET` announcements (`spec/pairing-v1.md` Sections 6.5, 6.11).

A meeting hint inside a pairing URI, which would keep `rp` out of a photographed QR (`spec/pairing-v1.md` Section 6.10, Privacy), is deferred. It needs a new allow-listed parameter, and today's parsers reject unknown parameters (`spec/pairing-v1.md` Section 6.1).

### 5. Interaction with pairing URIs, `rp`, `rq`/`rs`, and M2M routes

- **Relay origin.** For a typed code, the relay origin comes from the embedding app's configuration, not from a URI. It is therefore an operator-configured origin: admission material may attach to it (`spec/pairing-v1.md` Section 6.9) and the operator egress rules apply (`spec/pairing-v1.md` Section 6.8).
- **A meeting selector, distinct from `rp`.** A meeting key is not a relay key in the sense of `spec/pairing-v1.md` Section 6.4. That section checks every relay key a connect supplies, including an operator `URL#key` with no URI, against the Ed25519 half of the host's signing key, and a derived key would fail with `HostKeyUnverified` before `msg3`. Today the runtime would also skip a `/v1/relay` candidate that has no relay key and persist an operator endpoint as an `operator` route (`build_pairing_candidates` in `crates/tendril-runtime/src/providers/hints.rs`, `plan_pairing` and `PairRouteBinding` in `crates/tendril-runtime/src/driver.rs` and `crates/tendril-core/src/pairing.rs`). The meeting target is therefore a separate selector type: Section 6.4 and Section 6.5 do not apply to it, it never becomes an `rp` or `URL#key`, and nothing about it is persisted. A typed-code pairing has no URI, so there is no `rs` to check. The host key is learned unpinned and recorded `pending` (`spec/pairing-v1.md` Section 5).
- **PAKE only, enforced at the listener.** A meeting listener accepts only the preamble `TND 0x02 0x02 0x01` (`intent = pair`, `FLAG_PAKE_PAIR`, `spec/wire-v2.md` Section 2.1) and closes anything else **before** any shared router or responder. Without that filter, a meeting listener attached to the general inbound router (`InboundRouter` in `crates/tendril-runtime/src/router.rs`) would answer a Wire v1 pairing `msg1`, and Wire v1 shows `HostHello` (`host_id`, `signing_pub`, rotation chain) in `msg2` before any code check (`spec/wire-v2.md` Section 3.2). A meeting mailbox never carries sessions. A meeting listener also never starts the runtime's standby acceptor pool: the relay refuses standby on delegated registrations, and the pool retries on `unauthorized`. This amends the rule that PAKE pairing runs over the identity mailbox only (`spec/pairing-v1.md` Section 6.6, `spec/wire-v2.md` Sections 3.2.2 step 3 and 3.2.3 rule 5).
- **Never advertised, never persisted.** A meeting mailbox is not an advertised relay (`spec/pairing-v1.md` Section 6.10) and is never stored as a route, including under the `committed` opt-in (`spec/pairing-v1.md` Section 6.7): its key derives from a code that burns on success.
- **Day 2: no route set in the PAKE reply.** The first draft proposed a hybrid-signed route set in the pairing reply. That is withdrawn. A signed route set is about 3.5 to 5 KB (`RouteSet` in `crates/tendril-core/src/routes.rs` carries a `3,373`-byte signature); in a Wire v2 PAKE `PairResponse` it would push success into the `16,384`-byte bucket while errors stay at `4,096`, breaking the equal-length rule of `spec/wire-v2.md` Section 3.2.2 step 5 and telling the relay whether pairing succeeded. Raising every PAKE reply to `16,384` bytes would hide that, but would cost every pairing 12 KB for routes the client may not apply anyway: an unconfirmed peer is `pending`, and announcements apply only to `Active` peers (`spec/pairing-v1.md` Section 6.11.3 step 1). This matches the M2M route work, which adds a route set to Wire v1 M2M replies only and rejects one on human and PAKE replies. A typed-code client reaches the host on day 2 through mechanisms that exist today: the embedding app's configured relay as an `operator` route, where the client derives the identity mailbox from the pinned `signing_pub` (`spec/pairing-v1.md` Section 6.4); then `ROUTE_SET` announcements on the first session after `pair.confirm` (`spec/pairing-v1.md` Section 6.11).

**Code holder in the middle: defence and limits.** A code holder can burn the host's code by dialing first, or, where it can register the meeting key, displace the host and answer the unpinned client while claiming the genuine host's `host_id`. The design relies on three properties:

1. **Unconfirmed host claims hold no label.** Until `pair.confirm` by SAS, an unpinned host is an unconfirmed claim in a pending host store, unique per `(device_id(host_static_pub), host_id)`, that lookups, sessions and routes by that `host_id` never see. Rejecting or revoking a claim never touches the `host_id` label, and a `host_id` is at most `256` bytes with no control characters and no `#` (`spec/pairing-v1.md` Section 5). A false claim therefore cannot block or revoke the genuine host.
2. **No SAS bypass on meeting pairings.** A meeting pairing is always unpinned, so the meeting helper refuses fingerprint-only confirmation (`--allow-no-sas`, `spec/pairing-v1.md` Section 5) on both sides. This is still to be built.
3. **Displacement is visible.** When a later `register` replaces a registration, the relay fails its pending dials with `offline` at once and closes its control socket with the `replaced` error code (`spec/relay-v1.md` Sections 2.2, 2.4), distinct from a transport drop, and a listener that receives it stops and does not re-register. A meeting host that receives `replaced` while the code is live also burns the code, releases its other registrations and reports it; on a plain transport drop it reconnects and re-registers under the same issuer. On delegated-ticket relays, issuer binding (Section 3) stops other hosts from displacing it at all.

Limits: an attacker who knows the code can always burn it by dialing first, and on an open relay can still win a race to answer the client. With the defences above the outcome is a failed pairing that the SAS reveals and a new code repairs, never a confirmed peer or a poisoned roster. The SAS is the only defence an unpinned client has, which is why Section 4 prefers a pinned QR. A "PAKE-confirmed host pin" is rejected: PAKE proves knowledge of the code, not host identity, so it adds nothing against a code holder.

### 6. Abuse

| Threat | Bound | Grounding |
|---|---|---|
| Wrong-code probing | Each guess costs the guesser one `Argon2id` and one relay dial. A wrong code names an unregistered key and gets `offline` before any `msg1`: no host work, no retry charge. Success odds per guess are `N / 31^12` with `N` live meetings on the relay | `spec/relay-v1.md` Sections 2.2, 3 (per-IP buckets, `max_active_per_ip`) |
| Offline batching by the relay | One guess tests the `M` meeting keys of one epoch under one relay host; expected `N / (M + 1)` guesses (about `2^49.45` at `M = 1024`); per-epoch tables only | Section 1 |
| Presence probing | Under `register-only`, `dial` shows online versus offline. Naming a meeting key requires the code, so this is online code guessing, bounded as above | `spec/relay-v1.md` Section 2.5 (no presence leak only under `all`) |
| Host CPU | Only parties that know `mailbox_pub` reach the host: the client and the relay. A hostile relay can inject PAKE `msg1`s; each costs the host `V2_PAKE_FIXED_ARGON2_PASSES = 4` derivations and gets a decoy. Today the runtime shares one Argon2id semaphore across all listeners (`V2ResponderState` in `crates/tendril-runtime/src/v2_driver.rs`, `DEFAULT_ARGON2_CONCURRENCY = 4`), so a hostile meeting relay could starve LAN and identity-mailbox pairing. Meeting listeners therefore get their own budget of `1` concurrent derivation, and after `8` decoy `msg1`s on one meeting the host unregisters it and fails the code visibly. A hostile relay can always deny a meeting; this turns CPU drain into a visible failure | `spec/wire-v2.md` Sections 3.2.1, 3.2.2 |
| Retry budget burn | On the identity mailbox, any failed claim charges every live code (5 failures per code). On a meeting mailbox, only code holders reach the host, so strangers cannot burn the code | `spec/pairing-v1.md` Section 5 |
| Squatting and displacement | Needs `mailbox_sk`, therefore the code. On delegated-ticket relays also needs a ticket from the same issuer as the live registration. On open relays a code holder can displace the host (last writer wins), and the host sees `replaced`; Section 5 covers the result | `spec/relay-v1.md` Sections 2.1, 2.4; Sections 3, 5 |
| Relay misuse through delegation | 16 admitted registrations per issuer per rolling `900 s`, at most 12 live, each exactly one stream of at most `60 s` and `256 KiB`; accept bound to the registering issuer | Section 3 |
| Mailbox exhaustion | Per-issuer quota and window above; `max_mailboxes = 1024` relay-wide | `spec/relay-v1.md` Section 3 |
| Collision | Distinct codes give independent keys. On one relay, `N` live meetings collide with probability about `N^2 / 2^60.4`; the relay host and epoch salt separate relays and epochs | Section 1 |
| Outcome timing | After a successful burn the host keeps its registrations until the code's original expiry and re-registers after every stream, so neither unregistering nor re-registering reveals success while the admission window has room; PAKE replies have equal length (no route set, Section 5) | Section 2; `spec/wire-v2.md` Section 3.2.2 |
| Replay after expiry | `register` and `accept` signatures bind a fresh nonce and host; tickets fail after `not_after + 30 s`; the relay closes the registration and its streams at that point; the code burns on success and expires at its TTL; a replayed `msg1` hits the PAKE replay cache and gets a decoy | `spec/relay-v1.md` Sections 2.1, 2.3, 2.5; `spec/pairing-v1.md` Section 5; `spec/wire-v2.md` Section 3.2.2 |

## Consequences

- **No new wire bytes.** Ticket bytes, relay control frames and error codes (including `replaced`, `spec/relay-v1.md` Section 2.4), PAKE, `PairResponse` and the pairing URI stay as they are. Changes: a relay admission rule with its limits and deadline (`spec/relay-v1.md` Section 2.5), a derivation with vectors, a meeting selector distinct from relay keys (`spec/pairing-v1.md` Section 6.4), and the pairing relay-target rule (`spec/pairing-v1.md` Section 6.6, `spec/wire-v2.md` Sections 3.2.2 step 3 and 3.2.3).
- **Both relay implementations** (`crates/tendril-relay` and `deploy/cloudflare/src/relay_core.js`) must implement delegated meeting tickets. A relay without them answers a meeting `register` on a Tier 1 relay with `unauthorized` and the host fails closed.
- **Open relays work today** and keep working, but without relay-enforced lifetime and with code-holder displacement; Section 5 bounds the result. The helper says so.
- **Client cost.** Up to two `Argon2id(19 MiB)` derivations to find the mailbox and one for PAKE, per attempt.
- **Residual offline weakness.** Against a hostile relay, the meeting key is weaker than `init_mac` by the batching factor within one epoch and allows per-epoch precomputation (Section 1). Targeting a chosen meeting stays infeasible for `Remote3Group`.
- **Compatibility.** Older clients never derive meeting keys, older open relays carry meetings unchanged, and older Tier 1 relays refuse them. No existing frame, ticket or URI changes meaning.

## Follow-up work

**Already in place.** The design relies on behaviour the specs now define:

- Ticket-admitted registrations and standby sockets end at `not_after + 30 s`, and expired registrations receive no dial (`spec/relay-v1.md` Section 2.5).
- A replaced registration fails its pending dials with `offline` and closes with `replaced`; its listener stops (`spec/relay-v1.md` Sections 2.2, 2.4).
- Unconfirmed host claims live in a pending host store keyed by `(device_id(host_static_pub), host_id)` and never revoke a label (`spec/pairing-v1.md` Section 5).
- `auth_scope` defaults to `register-only` on allowlist-only relays and to `all` once Tier 2 or 3 is configured, and the relay validates allowlist keys (`spec/relay-v1.md` Section 2.5).

Issues to file if this ADR is accepted:

1. **spec: meeting mailbox derivation.** Fix the labels and epoch rules of Section 1 (registration span, symmetric second dial, no underflow at epoch `0`), add vectors under `spec/vectors/` and the Go cross-check, and state the `Remote3Group` requirement.
2. **relay: delegated meeting tickets.** Opt-in setting, issuer and target rules, issuer binding checked on `register` and `accept`, no standby, one stream per registration with its budget, per-issuer live quota and rolling admission window, `max_meeting_ttl`, closing bridged meeting streams at the `not_after + 30 s` deadline, and the start-up conflict check, in `spec/relay-v1.md` Section 2.5, `crates/tendril-relay` and the Workers relay under `deploy/`.
3. **pairing: meeting mailbox as a PAKE relay target.** Amend `spec/pairing-v1.md` Sections 6.4 and 6.6 and `spec/wire-v2.md` Section 3.2.2 step 3 and Section 3.2.3 rule 5: a meeting selector distinct from relay keys, PAKE only, never sessions, never advertised or persisted.
4. **core and runtime: meeting helpers.** Host: issue a `Remote3Group` code, register every epoch it overlaps before showing it, mint tickets, re-register after each stream, hold registrations after a successful burn and release them after a failed one, evict the oldest burned code for room, burn on `replaced`, never start the standby pool, filter the preamble before routing, and use a dedicated Argon2id budget with the decoy cap. Client: typed code plus configured relay origin, derive with the symmetric second dial, dial, PAKE, SAS required.
5. **bindings: expose the helpers** through FFI, Swift, Kotlin, Go, Python, Node and the browser SDK, with tests replaying the new vectors.
6. **docs: relay hosting guide.** Configure delegated meeting tickets, the `register-only` requirement on mixed Tier 1 and Tier 3 relays, and the stopgap of option (a) with its caveats.
7. **Later, optional: meeting hint in the pairing URI**, to keep `rp` out of photographed QR codes.
