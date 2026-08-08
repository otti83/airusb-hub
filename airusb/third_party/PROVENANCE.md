# Vendored third-party code

Nothing in this directory was written for AirUSB. It is copied verbatim from
upstream, pinned to a specific version, and recorded here with checksums so that
"is this the code upstream published?" is a question with a mechanical answer.

**Do not edit these files.** Local fixes become invisible the next time someone
diffs against upstream. If something needs changing, change it upstream or wrap
it in `crypto/`.

---

## Why vendored rather than a system or package-manager dependency

The exporter runs as a **root LaunchDaemon**. Linking it against a library in a
user-writable prefix — `/opt/homebrew/lib` is mode 0755 owned by the console user
on a default install — hands anyone who can write there code execution as root.
That rules out Homebrew OpenSSL and Homebrew libsodium for this process
regardless of their merits.

macOS ships no public C API for X25519 or Ed25519 (`Security.framework` offers
NIST curves; CryptoKit is Swift-only), and the same code has to build on Windows
and Linux. So: vendored, one copy, identical on all three platforms, auditable in
tree, no build-time network access.

The cost is that upgrading is manual. §"Upgrading" below is the procedure.

---

## Monocypher 4.0.3

| | |
|---|---|
| Upstream | https://github.com/LoupVaillant/Monocypher |
| Version | tag `4.0.3` |
| Licence | dual **BSD-2-Clause** / **CC0-1.0** — take either (`monocypher/LICENCE.md`) |
| Audits | two independent audits (2017 by Peter Schwabe et al. of the crypto; 2019 by Cure53 of the whole library) |

Used for X25519, Ed25519 (the RFC 8032 variant, from the optional
`monocypher-ed25519` module), RFC 8439 ChaCha20-Poly1305, constant-time
comparison, and secret wiping.

| file | sha256 |
|---|---|
| `monocypher/monocypher.h` | `fcaf6ed771358bb4f40fba016f6518ae86ec02b1b877d2cc35ad92d3a26fd7b3` |
| `monocypher/monocypher.c` | `f1f838cdd483bdebe0df0ff5c5ed60535e496f769c6a2f933ac4c0b114207123` |
| `monocypher/monocypher-ed25519.h` | `3a3035181f991a158d0e1c7567258f0bae8ba0f1f23c5512b4a1db1b3c9730ce` |
| `monocypher/monocypher-ed25519.c` | `ce0d2f8e32ca8f66398ba5b3456cc74327c3eff14e7b950ce7d57be9025cc453` |
| `monocypher/LICENCE.md` | `a5781770269d2516e52ba4863f790c10a16da4089a1e81823aee19ff1e9026b0` |

### Two Ed25519s, and why the optional module is mandatory here

Monocypher's built-in `crypto_eddsa_*` is EdDSA over BLAKE2b, **not** RFC 8032
Ed25519. It is a fine signature scheme and it is not the one we need: the
identity key is specified to be reusable as a TLS 1.3 raw-public-key certificate
key (P1 plan §3.14), which requires standard Ed25519 with SHA-512. That is what
`monocypher-ed25519.{c,h}` provides, so it is vendored too and is what `crypto/`
calls. Getting this wrong would produce signatures no TLS stack could verify.

---

## BLAKE2s reference implementation

| | |
|---|---|
| Upstream | https://github.com/BLAKE2/BLAKE2 |
| Version | commit `ed1974ea83433eba7b2d95c5dcd9ac33cb847913` |
| Licence | **CC0-1.0** (also offered under OpenSSL and Apache-2.0; `blake2s/COPYING`) |
| Provenance | the reference implementation by the BLAKE2 designers; normative for RFC 7693 |

| file | sha256 |
|---|---|
| `blake2s/blake2.h` | `389bc87a83cdd9e25569a294d01a3347970d117237a66eee9df8edd6058736a4` |
| `blake2s/blake2-impl.h` | `bc0ead7f3259a415325fa40ddebb1876f903d5062d888fc5994e8b2d9e616ec4` |
| `blake2s/blake2s-ref.c` | `645fb0212db0d6e15a1568da210ac3f7123da1ab4330d4fc0e33312d742d569a` |
| `blake2s/COPYING` | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` |

### Why a second hash library

The cipher suite is `Noise_XX_25519_ChaChaPoly_BLAKE2s`, fixed in P1 plan §3.14
and on the wire. Monocypher ships BLAKE2**b**, not BLAKE2**s** — different
constants, different block size, different digest, not interchangeable.

The alternative was to respecify the suite as `..._BLAKE2b`, which is equally
valid Noise and would have avoided a second dependency. That was rejected: the
wire protocol was specified and reviewed with BLAKE2s, BLAKE2s is the variant the
rest of the Noise ecosystem uses (WireGuard among them), and ~200 lines of the
designers' own reference code is a smaller thing to take on than a wire-format
change made to suit a library.

The reference implementation is chosen over a faster SSE one deliberately.
Throughput here is irrelevant — BLAKE2s runs a few dozen times per session, on
handshake messages measured in hundreds of bytes — and the reference code is the
version that is easiest to compare against RFC 7693 by eye.

---

## Verification

`tests/unit/test_crypto.cpp` runs the official published vectors for every
primitive, on every commit:

| primitive | vectors from |
|---|---|
| BLAKE2s | RFC 7693 Appendix B, plus the BLAKE2 project's keyed vectors |
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 and Appendix A.5 |
| X25519 | RFC 7748 §5.2 and §6.1 |
| Ed25519 | RFC 8032 §7.1 |

These are not our numbers. They are the standards documents', so a vendored file
that was corrupted, truncated, or swapped for a lookalike fails the build rather
than producing plausible ciphertext.

`tests/vectors/NoiseVectors.h` additionally holds the two `cacophony` vectors for
the protocols AirUSB speaks, extracted from
https://github.com/mcginty/snow `tests/vectors/cacophony.txt`. Those were
generated by an independent Noise implementation and check the handshake — and
the handshake hash the SAS derives from — byte for byte against ours.

---

## Upgrading

1. Fetch the new files from the pinned upstream tag.
2. Update the checksum tables above.
3. `ctest` — the standards vectors must still pass. They are the acceptance test
   for the upgrade.
4. Read the upstream changelog for anything touching X25519, Ed25519 or the AEAD.
   A silent behaviour change in a primitive is a wire-format change.
