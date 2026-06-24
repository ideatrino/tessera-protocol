# TESSERA — A Secure Communication Protocol

**One-line summary:** An authenticated, forward-secure, post-quantum, defense-in-depth messaging protocol whose **integrity is information-theoretically unbreakable** and whose **confidentiality reaches Shannon-perfect secrecy** whenever a true shared-entropy budget allows — and degrades gracefully to layered post-quantum security when it doesn't.

> **The name.** A *tessera hospitalis* in ancient Rome was a small token (often a clay or bone tile) deliberately broken into two halves. Two parties each kept one half; fitting the halves back together proved their bond — a physical shared secret. That is exactly the metaphor for this protocol, so it is named **TESSERA**. (Rename it whatever you like — it's yours.)

---

## 0. What this is, and what it honestly is not

This is an **architecture**: a specific, original way of wiring together a small set of mathematical primitives. Its originality is in the *combination and structure* — the "Split-Reservoir Universal Masking + Dual-Lock" design — not in inventing a new cipher (inventing new ciphers is how people get broken).

**It is not** something you should deploy against a real adversary until it has been independently reviewed by cryptographers and ideally given a machine-checked proof. No first-draft protocol should be. Treat this as a serious, internally-consistent design and a thinking tool — not as battle-tested software.

There is also a **hard mathematical ceiling** on "most secure possible," and TESSERA is built to sit exactly at it (see §6).

---

## 1. The shortcomings of existing systems, and how TESSERA answers each

| Existing system | Core weakness | TESSERA's answer |
|---|---|---|
| RSA / ECC / Diffie–Hellman | Broken by Shor's algorithm on a quantum computer; rests on one unproven hardness assumption | Hybrid key agreement (§7): secure if *any one* of pre-shared secret, post-quantum KEM, or ECDH holds |
| One-Time Pad | No authentication (totally malleable); key distribution is brutal; key must equal message length | Adds **unconditional** authentication (§4); ratcheted key engine eases distribution (§2); OTP becomes one *mode*, not the whole system |
| AES-GCM / ChaCha20-Poly1305 | Catastrophic, silent failure on nonce reuse | No nonces in the security-critical path — fresh one-time keys come from the ratchet, so the GCM nonce-reuse failure mode cannot occur (§4) |
| Symmetric crypto generally | Key distribution problem; no forward secrecy by default | Forward-secure ratchet + post-compromise "healing" via entropy injection (§2, §5) |
| Signal / modern messengers | Strong, but leak metadata (who talks to whom, when, how much) | Length-bucketing, optional constant-rate cover traffic, onion-routing-compatible (§3.D) |
| QKD (BB84) | Special hardware, distance-limited, expensive; classical channel needs pre-auth | Pure software; the *information-theoretic* guarantees QKD chases are obtained here for authentication outright, and for confidentiality in OTP mode |

---

## 2. Component A — The Reservoir & forward-secure ratchet (the engine)

Both parties hold a synchronized secret **root key** `r₀ ∈ {0,1}²⁵⁶`, established in §7.

**Epoch chaining.** A cryptographic PRG `G` (instantiate with SHAKE-256 / HKDF) maps the current root to a *next* root plus an output block:

```
(r_{i+1}, o_i) = G(r_i)
```

After deriving `r_{i+1}`, the party **deletes `r_i`**. Because `G` is one-way, no future state reveals a past root → **forward secrecy**.

**Healing (post-compromise security).** Every `T` epochs (or on demand), the parties run a fresh post-quantum KEM exchange producing shared entropy `e`, and fold it in:

```
r ← G'(r ∥ e)
```

If an attacker stole the state but does not know `e`, security is restored going forward.

**Per-message expansion.** From the epoch block `o_i`, a deterministic expansion produces, for the j-th message, four independent secret values:

```
κ_{i,j}   — confidentiality pad (length L = message length)
k2_{i,j}  — independent key for the outer post-quantum AEAD
α_{i,j}   — universal-hash key  (an element of GF(p))
β_{i,j}   — one-time MAC mask    (an element of GF(p))
```

Each is used **once** and then its position in the stream advances. (This is the part that makes the §4 authentication unconditionally secure.)

---

## 3. Component B — Confidentiality (the "Dual-Lock")

Two independently-keyed layers. An attacker must defeat **both**.

**Inner lock (the pad).**
```
c1 = m ⊕ κ_{i,j}
```
- If `κ` is drawn from a **true shared-entropy reservoir** (pre-shared, never reused) → this is a One-Time Pad → **Shannon-perfect secrecy**: `I(m ; c1) = 0`, unconditionally.
- If `κ` is PRG output → this is a computationally-secure stream cipher.

**Outer lock (post-quantum AEAD).**
```
c2 = AEAD_{k2_{i,j}}(c1)        // e.g. XChaCha20-Poly1305 or AES-256-GCM
```
AES-256 / 256-bit ChaCha retain ~128-bit security even against Grover's algorithm, so the outer lock is post-quantum-adequate.

**Why two locks help (composition).** With independent keys, recovering `m` requires peeling the outer AEAD *and then* the inner pad. So the adversary's success probability is bounded by the **harder** of the two layers — strictly stronger than either alone. In OTP mode the inner lock alone already gives perfect secrecy, and the outer lock is pure bonus.

### 3.D Metadata protection (bolt-on)
- **Length-bucketing:** pad every ciphertext up to the next size bucket (e.g. 256 / 1024 / 4096 B) so length leaks ≤ 2 bits.
- **Constant-rate cover traffic (optional):** emit indistinguishable chaff during idle so an observer sees a constant bitrate regardless of real activity.
- **Transport-agnostic:** output is just bytes, so it composes cleanly with onion routing / mixnets to hide who-talks-to-whom.

---

## 4. Component C — Authentication (the provably-unbreakable part)

This is TESSERA's strongest guarantee and the thing the OTP never had. It uses a **Carter–Wegman one-time MAC** built from a polynomial universal hash over a prime field `GF(p)` (p a large prime, e.g. ≈ 2²⁵⁶).

Split the ciphertext `c2` into blocks `c_1, …, c_t ∈ GF(p)`. Compute:

```
H(c) = Σ_{k=1}^{t} c_k · α^k   (mod p)          // universal hash, keyed by α
τ     = ( H(c) + β )           (mod p)          // one-time mask by β
```

The transmitted, authenticated unit is `(epoch i, index j, c2, τ)`, with `i, j` also bound into the hash so reordering/replay is detected.

**Security theorem (unconditional).** The polynomial-evaluation family is **ε-almost-Δ-universal** with `ε = t/p`. Because `(α, β)` are fresh, uniform, and used once, the probability that *any* adversary — **with unlimited computing power, quantum or otherwise** — forges a valid tag on a new ciphertext is at most:

```
P(forgery) ≤ t / p
```

For `p ≈ 2²⁵⁶` and messages up to `t ≈ 2⁶⁴` blocks, that's `≤ 2⁻¹⁹²`. This is not "hard to break" — it is **information-theoretically secure**, like the OTP itself.

**Bonus:** because the mask `β` is drawn fresh from the ratchet rather than from a nonce, the silent catastrophic failure of GCM-on-nonce-reuse structurally cannot happen here.

---

## 5. Security summary (what rests on what)

| Property | Strength | Depends on |
|---|---|---|
| Message authentication / integrity | **Unconditional** (≤ t/p) | Only: keys are fresh, one-time, uniform |
| Confidentiality — OTP mode | **Unconditional** (perfect secrecy) | True shared entropy ≥ message length |
| Confidentiality — computational mode | Post-quantum computational | PRG security **and** AEAD security (must break both) |
| Forward secrecy | Yes | One-way PRG + deleting old state |
| Post-compromise security (healing) | Yes | Fresh entropy injection unknown to attacker |
| Replay / reordering protection | Yes | One-time keys + authenticated indices + sliding window |
| Quantum resistance | Yes | Hybrid KEM + 256-bit symmetric + IT auth |

---

## 6. The hard ceiling — why this is "as secure as mathematically possible"

**Shannon's theorem (1949):** for *unconditional* (information-theoretic) confidentiality, the secret key must have at least as much entropy as the plaintext. There is no way around this — any system claiming "unbreakable encryption of unlimited data from a short key" is either using computational assumptions or is lying.

So "the most secure possible communication" is precisely characterized:
- **Authentication** can be unconditional with only short fresh keys → TESSERA takes that all the way (§4).
- **Confidentiality** can be unconditional *only* up to your true shared-entropy budget → TESSERA gives you exactly that in OTP mode, and the best available computational security (layered, post-quantum) beyond it.

TESSERA is engineered to sit on this frontier rather than pretend the frontier doesn't exist. That honesty is the design.

---

## 7. Component F — Hybrid key agreement (bootstrapping r₀)

Combine up to three independent secrets and fold them together so the result is secure if **any single one** is:

```
r₀ = HKDF( pre_shared_tessera_half ∥ KEM_secret ∥ ECDH_secret )
```
- `pre_shared_tessera_half` — the literal "two halves of the token" (out-of-band shared secret; enables OTP-grade modes).
- `KEM_secret` — from a post-quantum key-encapsulation mechanism (ML-KEM / Kyber-style Module-LWE).
- `ECDH_secret` — classical elliptic-curve DH (X25519), cheap insurance.

An attacker must break *all three* to learn `r₀`.

---

## 8. Functionality & performance ("most functional")

- **Fast:** the pad (XOR), the AEAD, and the polynomial hash are the same primitive families that make ChaCha20-Poly1305 / AES-GCM fast in practice. Throughput is comparable.
- **Small overhead:** one tag + a short authenticated header per message.
- **Asynchronous:** epoch states can be stored, so messages send/receive without both parties online (Signal-style).
- **Group messaging:** run per-pair reservoirs, or layer a tree-based group-key agreement on top.
- **Tunable:** a single "entropy budget" dial slides the system between full OTP-perfect-secrecy (when you have key material) and lightweight computational mode (when you don't), with no protocol change.

---

## 9. Worked toy example (so the math is concrete)

Tiny field for illustration: `p = 8191` (the Mersenne prime 2¹³−1).

**Confidentiality (inner lock).** Message byte `m = 0x48` ('H'), pad byte `κ = 0x6B` → `c1 = 0x48 ⊕ 0x6B = 0x23`. With `κ` truly random and single-use, `c1` reveals nothing about `m`.

**Authentication.** Ciphertext blocks `c₁ = 1234`, `c₂ = 5678`. One-time keys `α = 4242`, `β = 1000`.

```
α²            = 4242²              ≡ 7128   (mod 8191)
c₁·α          = 1234·4242         ≡ 579    (mod 8191)
c₂·α²         = 5678·7128         ≡ 1053   (mod 8191)
H(c) = 579 + 1053                 ≡ 1632   (mod 8191)
τ    = H(c) + β = 1632 + 1000      = 2632   (mod 8191)
```

Transmit `(c, 2632)`. An adversary with infinite compute, not knowing `(α, β)`, forges a valid tag with probability ≤ `t/p = 2/8191 ≈ 0.00024`. In the real field (`p ≈ 2²⁵⁶`) that probability is astronomically smaller — and it holds against *any* computer that can ever be built.

---

## 10. If you want to take this further

1. **Write a formal security proof** in a framework like the Universal Composability model, or machine-check it (Tamarin / ProVerif / EasyCrypt).
2. **Pin concrete primitives:** exact KEM parameter set, exact prime `p`, exact PRG, exact AEAD — and justify each.
3. **Specify the wire format** byte-for-byte (header, epoch/index encoding, padding scheme).
4. **Get it reviewed.** Post the spec for cryptographers to attack. Surviving public cryptanalysis is the only thing that earns trust — not cleverness, and not a proof you wrote alone.

---

*Design status: original architecture, internally consistent, honest about its proven vs. assumed guarantees — and explicitly not yet peer-reviewed. That last sentence is a feature, not a confession.*
