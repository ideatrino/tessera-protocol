<!-- Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. -->

# TESSERA

**Information-theoretic authentication meets post-quantum defense-in-depth.**

TESSERA is an original secure-messaging protocol whose **integrity is
information-theoretically unbreakable**, whose **confidentiality reaches
Shannon-perfect secrecy** when a true shared-entropy budget allows, and which
**degrades gracefully** to layered post-quantum security when it doesn't.

> ⚠️ **EXPERIMENTAL — NOT AUDITED — NOT CONSTANT-TIME — DO NOT USE IN PRODUCTION.**
> This is a serious design and a working reference implementation, not a vetted
> cryptographic library. Read **[SECURITY.md](SECURITY.md)** before any use.

> *A* tessera hospitalis *in ancient Rome was a token broken into two halves; two
> parties each kept one, and fitting the halves back together proved their bond.
> That is the shared-secret metaphor this protocol is named for.*

---

## Why it exists — shortcomings it targets

| Existing system | Weakness | TESSERA's answer |
|---|---|---|
| RSA / ECC / DH | Broken by Shor's algorithm; one unproven assumption | Hybrid key agreement — secure if **any one** of pre-shared / PQ-KEM / ECDH holds |
| One-Time Pad | No authentication; brutal key distribution | Adds **unconditional** authentication; ratchet eases key supply; OTP becomes a *mode* |
| AES-GCM / ChaCha20-Poly1305 | Catastrophic on nonce reuse | Fresh one-time keys from the ratchet — the nonce-reuse failure mode can't occur |
| Symmetric crypto generally | No forward secrecy by default | Forward-secure ratchet + post-compromise **healing** |
| Modern messengers | Leak metadata | Length-bucketing + optional cover traffic + transport-agnostic |
| QKD | Special hardware, distance-limited | Pure software; the IT guarantees obtained for auth outright, and for confidentiality in OTP mode |

The full design rationale is in **[docs/TESSERA_protocol.md](docs/TESSERA_protocol.md)**.

---

## Architecture at a glance

```
plaintext ─▶ INNER LOCK ─▶ OUTER LOCK ─▶ ONE-TIME MAC ─▶ wire
            (SHAKE-256 pad   (ChaCha20,    (Carter–Wegman,
             or true OTP)     RFC 8439)     GF(2²⁵⁵−19))
                  ▲                ▲                ▲
                  └──── fresh per-message keys ─────┘
                         from a forward-secure ratchet
                      (heals via fresh entropy injection)
```

- **Dual-lock confidentiality** — two independently-keyed layers from *different*
  primitive families; an attacker must break **both**. In OTP mode the inner lock
  alone is perfectly secret.
- **Information-theoretic authentication** — forgery probability ≤ (t+1)/p against
  **any** adversary, quantum or classical (`p = 2²⁵⁵−19`).
- **Forward secrecy & healing** — one-way ratchet deletes past keys; entropy
  injection restores security after compromise.
- **Replay & reordering protection** — bounded skip window, one-time keys.

---

## Install

```bash
git clone https://github.com/ideatrino/tessera-protocol.git
cd tessera-protocol
pip install -e .          # zero runtime dependencies (stdlib only)
```

Requires Python ≥ 3.10. No third-party packages are needed to run or test.

## Quickstart

```python
from tessera import Session, derive_root

root  = derive_root(pre_shared=b"shared-out-of-band-secret")
alice = Session.initiator(root)
bob   = Session.responder(root)

wire = alice.encrypt(b"Meet at the old bridge.", associated_data=b"hdr:dm")
assert bob.decrypt(wire, associated_data=b"hdr:dm") == b"Meet at the old bridge."
```

Perfect-secrecy (OTP) mode, given a pre-shared random pool:

```python
from tessera import KeyPool
import os
pool = os.urandom(64 * 1024)
alice = Session.initiator(root, send_pool=KeyPool(pool))
bob   = Session.responder(root, recv_pool=KeyPool(pool))
```

Run the demo:

```bash
python examples/demo_chat.py
```

## Tests

```bash
python run_tests.py        # zero-dependency runner
# or, if you have pytest:
pytest
```

31 tests cover RFC 8439 ChaCha20 known-answer vectors, MAC properties, full
round-trips, tamper detection (every single-bit flip rejected), replay /
reordering, forward secrecy, healing, OTP mode, and hybrid key agreement.

---

## Project layout

```
src/tessera/      chacha20  field  mac  kdf  ratchet  keypool
                  keyagreement  session  exceptions  __init__
tests/            8 test modules (31 tests)
examples/         demo_chat.py
docs/             TESSERA_protocol.md  (full specification)
```

## The hard limit (honesty)

Shannon's theorem (1949): *unconditional* confidentiality needs key entropy ≥
message length. Anything claiming "unbreakable encryption of unlimited data from
a short key" is using computational assumptions or lying. TESSERA gives you
**unconditional authentication always**, **unconditional confidentiality up to
your true entropy budget** (OTP mode), and **best-available post-quantum
computational security** beyond it. It is built to sit on that frontier — not to
pretend the frontier doesn't exist.

## License

Source-available, **All Rights Reserved** (© 2026 Ideatrino). Free for
non-commercial evaluation and research; commercial use requires a separate
license. See **[LICENSE](LICENSE)** and **[LICENSING.md](LICENSING.md)**.

Commercial inquiries: **ideatrino@proton.me**
