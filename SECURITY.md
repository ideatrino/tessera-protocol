# Security Policy

Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved.

## Status: EXPERIMENTAL — DO NOT USE IN PRODUCTION

TESSERA is an **original protocol design with a working reference
implementation**. It is **not** a vetted, production-grade cryptographic library.
Specifically, as of v0.1.0 it is:

- **Not independently audited** and **not formally proven**.
- **Not constant-time.** The pure-Python field and cipher operations leak timing
  and are exploitable by side-channel attackers. This alone disqualifies it from
  protecting real secrets.
- **Missing a real post-quantum KEM.** `derive_root` is a *framework*; you must
  plug in a reviewed ML-KEM (Kyber) and X25519 implementation.
- **Not memory-safe for secrets.** CPython cannot guarantee key material is
  scrubbed from memory.

Treat it as a serious design artifact and a learning/reference tool — not as
something to deploy against a real adversary.

## What *is* solid

- The **authentication** layer is information-theoretically secure *by design*
  (Carter–Wegman one-time MAC); the reference passes correctness tests.
- The **ChaCha20** primitive matches the official RFC 8439 test vectors.
- **OTP mode** provides Shannon-perfect secrecy for the inner lock *when* a true
  pre-shared entropy pool is supplied and never reused.

These are design and correctness properties — not a substitute for audit.

## Path to "trustworthy"

1. Independent cryptographic review of the protocol and code.
2. Machine-checked proofs (e.g., Tamarin / ProVerif / EasyCrypt) of the security
   claims in `docs/TESSERA_protocol.md`.
3. Constant-time, memory-safe implementation (e.g., Rust) of the field, cipher,
   and MAC, with known-answer and fuzz testing.
4. Integration of a vetted post-quantum KEM and classical ECDH.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to **ideatrino@proton.me**
rather than opening a public issue. Include a description, affected version, and
a proof-of-concept if possible. You will receive an acknowledgement; coordinated
disclosure is appreciated.
