# P2.4 — the security layer

**Status: PASS.** `NullCipher` is no longer the only `IRecordCipher`. Sessions
run `Noise_XX` / `Noise_IK` over X25519 + ChaCha20-Poly1305 + BLAKE2s, verified
byte for byte against an independent implementation's vectors.

---

## 1. Goal

P1 plan §3.14, as far as the handshake reaches:

- `Noise_XX_25519_ChaChaPoly_BLAKE2s` on first contact
- `Noise_IK_25519_ChaChaPoly_BLAKE2s` once the peer's static key is pinned
- an Ed25519 identity key bound to the X25519 static key by a signature
- the six-digit SAS both users compare
- a real `IRecordCipher`, replacing the stand-in

The session layer that drives it followed in the same phase: the L0 preamble,
the handshake over `RecordLayer`, the trust gate and the pin store. Out of scope
and still to do: the `PAIR_*` messages and the pairing rate limiter (§7).

---

## 2. What was built

```
airusb/
  third_party/                  vendored, pinned, checksummed — PROVENANCE.md
    monocypher/                 X25519, Ed25519 (RFC 8032), ChaCha20-Poly1305
    blake2s/                    the BLAKE2 designers' reference implementation
  crypto/
    Primitives.{h,cpp}          the ONLY caller of third_party
    Identity.{h,cpp}            identity keys, binding signature, fingerprint, SAS
  protocol/
    Noise.{h,cpp}               CipherState, SymmetricState, HandshakeState
  transport/
    NoiseCipher.{h,cpp}         IRecordCipher over the two transport CipherStates
  session/
    SecureSession.{h,cpp}       preamble -> handshake -> trust gate -> transport
    PeerStore.{h,cpp}           pinned identities, grants, atomic persistence
  tests/
    unit/test_crypto.cpp        primitives vs. the RFCs
    unit/test_noise.cpp         handshake vs. the official cross-impl vectors
    unit/test_identity.cpp      identity, SAS, record cipher, end to end
    unit/test_session.cpp       the session layer, including a real man in the middle
    fuzz/fuzz_noise.cpp         the handshake parser
    vectors/CryptoVectors.h     extracted from RFC 7693/8439/7748/8032
    vectors/NoiseVectors.h      extracted from the cacophony vector set
```

---

## 3. The decisions worth recording

### 3.1 Vendored, not linked

The exporter is a **root LaunchDaemon**. Linking it against a library in
`/opt/homebrew/lib` — a directory the console user can write to on a default
install — is a local privilege escalation waiting to happen. That rules out
Homebrew OpenSSL and Homebrew libsodium for this process on the merits, before
any argument about which library is better.

macOS also ships no public C API for X25519 or Ed25519 (Security.framework does
NIST curves; CryptoKit is Swift-only), and the same code must build on Windows
and Linux. So: vendored, pinned, checksummed, identical everywhere, no
build-time network access. `third_party/PROVENANCE.md` records versions, hashes,
licences and the upgrade procedure.

### 3.2 Two hash functions, on purpose

The suite is fixed at BLAKE2s by §3.14 and by the wire format. Monocypher ships
BLAKE2**b**, which is a different function. The alternatives were to respecify
the suite as `..._BLAKE2b` — equally valid Noise, one fewer dependency — or to
vendor the BLAKE2 designers' own ~200-line reference implementation.

The reference implementation won: the wire protocol was specified and reviewed
with BLAKE2s, BLAKE2s is the variant the rest of the Noise ecosystem uses, and a
wire-format change made to suit a build convenience is the wrong direction of
travel.

### 3.3 HMAC, not BLAKE2's keyed mode

Noise's key schedule is HMAC (RFC 2104) applied to the hash. BLAKE2s *also* has a
native keyed mode, which is faster and is a different construction. Substituting
it produces a protocol that round-trips against itself perfectly, passes every
self-test, and interoperates with nothing — while silently discarding the review
the real construction has had.

`crypto::hmacBlake2s` is the real HMAC. The native keyed mode is deliberately not
exposed at all, and `test_crypto` asserts the two differ.

### 3.4 The fingerprint hash changed from SHA-256 to BLAKE2s

§3.14 specified `SHA-256("AirUSB-fp-v1" || I_pk)`. Nothing else in the system
needs SHA-256, and adding a fourth hash function to a root daemon's attack
surface to compute a display string is a bad trade. The fingerprint is internal —
it names a pin, no other implementation parses it — so this is not a
wire-compatibility change. Recorded here and in `crypto/Identity.h`.

### 3.5 One seed, two keypairs

The identity key and the Noise static key are separate keys — no key signs and
does Diffie-Hellman — but they derive from one stored seed by domain-separated
expansion. Storing two independent secrets doubles the number of things that can
be lost, leaked, or fall out of step with each other.

---

## 4. Evidence

### 4.1 Primitives against the standards

`test_crypto` runs the published vectors, extracted **mechanically from the RFC
text**, not transcribed. A mistyped constant in a crypto test is worse than no
test: it fails loudly against correct code and passes quietly against nothing.

| primitive | source | result |
|---|---|---|
| BLAKE2s-256 | RFC 7693 Appendix B | pass, and cross-checked against OpenSSL 3 |
| ChaCha20-Poly1305 | RFC 8439 Appendix A.5 | pass, both directions |
| X25519 | RFC 7748 §5.2 and §6.1 | pass |
| Ed25519 | RFC 8032 §7.1 TEST 1 | pass |

The Ed25519 vector is load-bearing beyond "the maths works": Monocypher's default
`crypto_eddsa_*` is EdDSA over BLAKE2b, not RFC 8032. If the build ever picked up
the wrong one, the public key derived from the RFC's seed would not match and
this test fails — rather than shipping an identity key no TLS stack can verify.

### 4.2 The handshake against somebody else's implementation

This is the test that matters, and it passed on the first run.

```
official Noise vectors (independent implementation)
  Noise_IK_25519_ChaChaPoly_BLAKE2s   ..........................................
  Noise_XX_25519_ChaChaPoly_BLAKE2s   ........................................
```

Every handshake message is compared byte for byte against ciphertext produced by
the `cacophony` vector generator, then every transport message after the split,
then the final handshake hash — the value the SAS is derived from.

A Noise implementation that only talks to itself agrees with itself perfectly
while being wrong: HKDF arguments swapped, the nonce encoded big-endian, the
plaintext hashed instead of the ciphertext. Each of those yields a
self-consistent private protocol. Matching an independent implementation is the
only test that rules them out.

### 4.3 Properties the vectors cannot check

```
11 suites / 0 failures    (1297 checks in test_identity, 379 in test_session)
3 fuzz targets, 120,000 executions each, 0 crashes, 0 UB findings
Zero warnings under -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
  -Wshadow, Objective-C++ included
```

- A forged record does **not** advance the nonce (Noise §5.1), so one injected
  packet cannot permanently desynchronise an otherwise healthy session.
- Replayed and reordered records fail. This is why the L1 header carries no
  sequence number: replay and reorder are not detected by a check we wrote, they
  are cryptographically impossible.
- The two directions use different keys — a peer's own receive state refuses what
  it just sent, so records cannot be reflected back at it.
- The prologue is bound: a mismatch fails the handshake, which is what stops an
  attacker rewriting the plaintext L0 preamble.
- A truncated handshake message is refused at every one of its possible lengths.
- Rekey rotates the key and leaves the nonce alone, as Noise specifies, and both
  directions rotate at the same record count.
- The plaintext does not appear on the wire — asserted by reading the record back
  out of the pipe undecrypted and searching for a marker string.

### 4.4 The impersonation attack, tested directly

`test_identity` includes the attack the binding signature exists to stop: an
eavesdropper copies a legitimate peer's `I_pk || sigS` out of an earlier
handshake and presents it in their own session, where Noise negotiated *their*
static key.

It fails, because `decodeAndVerifyIdentityPayload` checks the binding against the
key **the handshake actually negotiated** — never one taken from the payload.
Verifying a payload's own claim about itself proves only that the attacker can
sign their own pair of keys.

---

## 4a. The session layer

`SecureSession` is what turns a socket into an authenticated session:

```
L0 preamble (8 plaintext bytes, both directions)
    -> Noise handshake, carried as pre-handshake records (<= 8 KiB, R1)
    -> identity payload verified against the NEGOTIATED static key
    -> trust gate: Paired with grants, or Unpaired
    -> NoiseCipher adopted, record limit raised to the negotiated size
```

**The preamble is not protected, it is bound.** Both preambles become the Noise
prologue, so rewriting one makes the two sides compute different prologues and
the first MAC fails. That is tested with an actual man in the middle, not by
asserting two byte arrays differ: a relay sits between two `MemoryPipe`s, flips
`wire_minor` — a field nothing else validates — and the handshake dies. A second
test relays the same bytes faithfully and requires the session to come up, so
that the first test cannot pass merely because the relay is broken. The faithful
relay also confirms the attacker sees neither identity key in the clear, because
XX encrypts both statics.

**Which pattern, and who decides.** The responder cannot guess whether the
initiator has it pinned, so the initiator says so with a new `SEC_NOISE_IK` bit
in the preamble. Saying it in the clear is safe for the same reason: flipping the
bit makes the two sides run different patterns and the handshake fails, rather
than downgrading. A stale pin also fails rather than falling back to XX — falling
back is exactly what an attacker who can force a key rotation would want.

**The trust gate.** An authenticated peer that is not pinned reaches `Unpaired`,
where `mayList()` and `mayAttach()` are both false. There is no configuration
that makes an unpinned peer trusted.

**The pin store** is line-oriented text, because it is security state a user may
need to read or delete by hand, and written atomically (temp file, fsync,
rename). A partially-parsed file loads *nothing*: a half-loaded pin store looks
like a working one while silently having forgotten peers, which surfaces as an
unexplained pairing prompt and trains the user to click through it. Peer-supplied
display names are sanitised so they cannot break the format.

---

## 5. What the SAS does and does not give you

`SAS = decimal6( HKDF(handshake_hash, "AirUSB-SAS-v1")[0..8) mod 10^6 )`, read
big-endian — pinned here because the spec did not say and both peers must agree.

The handshake hash commits to both static keys, both ephemerals and both
preambles, so a man in the middle cannot make the two sides display the same
number. Security is Bluetooth Numeric Comparison: one in a million per attempt.

**That bound holds only if attempts cannot be retried.** Exponential backoff, a
hard cap of three pairing attempts per minute per listener, and a burned pairing
session on failure are session-layer obligations that do not exist yet. Until
they do, the SAS is cryptographically sound and operationally incomplete.

---

## 6. Known limits

- **No `PAIR_*` messages and no rate limiter.** A peer can reach `Unpaired` and
  both sides can compute the SAS, but there is no message exchange that carries a
  confirmation, and nothing enforces the backoff the SAS's security bound depends
  on. Until that exists, pairing is a capability the code has and the protocol
  does not.
- **Nothing calls `SecureSession` yet.** It is tested against `MemoryPipe`; no
  daemon opens a TCP socket and drives it. The exporter and the session layer are
  both finished and not yet joined.
- **No identity persistence path.** `LocalIdentity::fromSeed` and
  `PeerStore::save/load` exist and are tested; nothing yet writes them to
  `/Library/Application Support/AirUSB/`.
- **HELLO is not implemented.** §3.13's second negotiation axis — `proto_version`,
  capability ANDing, the min of every numeric parameter — has no code. The record
  limit is currently taken from config rather than negotiated.
- **The test-only fixed-ephemeral hook is compiled into the library.** It is named
  `setFixedEphemeralForTestingOnly`, refuses to run once a handshake has started,
  and is unreachable from session code — but it exists, because without it the
  official vectors cannot be replayed and this implementation would be checked
  only against itself. That trade is deliberate.
- **No formal review.** The primitives are audited; the state machine around them
  has vectors, fuzzing and tests, which is not the same as an audit.

---

## 7. Next

- `PAIR_REQUEST` / `PAIR_CONFIRM` / `PAIR_RESULT`, the pairing rate limiter, and
  identity persistence on disk.
- `HELLO` / `HELLO_OK` — the second negotiation axis (§3.13).
- Join the two halves: a daemon that accepts a TCP connection, drives
  `SecureSession`, and serves the exporter behind the trust gate.
- **P2.9** `CiHostBackend` — the entitled importer half. Blocked on OQ-5 only.
- **P2.10** real ↔ real over 127.0.0.1, which is also where the exporter's write
  path and sustained throughput first get tested.
