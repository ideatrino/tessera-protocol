# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-01-01

Initial public release of the TESSERA reference implementation.

### Added
- **Protocol specification** (`docs/TESSERA_protocol.md`): the Split-Reservoir
  Universal Masking + Dual-Lock design.
- **Carter–Wegman one-time MAC** over GF(2²⁵⁵−19) — information-theoretic
  authentication (`tessera.mac`, `tessera.field`).
- **ChaCha20** outer-lock cipher, RFC 8439-conformant (`tessera.chacha20`).
- **Dual-lock confidentiality**: SHAKE-256 inner pad (or OTP) + ChaCha20 outer
  layer (`tessera.session`).
- **Forward-secure ratchet** with post-compromise **entropy injection / healing**
  (`tessera.ratchet`).
- **Replay protection** and **out-of-order delivery** with a bounded skip window.
- **OTP mode** for Shannon-perfect secrecy via a pre-shared `KeyPool`.
- **Hybrid key-agreement framework** (`tessera.keyagreement.derive_root`).
- **31 passing tests**, including RFC 8439 known-answer vectors, and a runnable
  `examples/demo_chat.py`.

### Security
- Experimental, unaudited, not constant-time. See `SECURITY.md`.
