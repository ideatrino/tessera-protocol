# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
mac.py — Carter--Wegman one-time MAC over GF(p).

This is TESSERA's strongest guarantee: information-theoretic authentication.

For fresh, uniform, single-use keys (alpha, beta) drawn from the ratchet, an
adversary with UNLIMITED computing power (quantum or classical) forges a valid
tag on a new message with probability at most (t + 1) / p, where t is the number
of message blocks. With p = 2**255 - 19 this is astronomically small.

The tag is computed as:

    H_alpha(m) = sum_{k=1..t} m_k * alpha**k   (mod p)
    H'         = H_alpha(m) + L * alpha**(t+1) (mod p)   # length framing
    tag        = (H' + beta)                   (mod p)

The +beta term is a one-time pad on the hash output (Wegman--Carter), and the
length-framing term makes the family almost-Delta-universal, preventing
truncation/extension ambiguity.
"""
from __future__ import annotations

import hmac

from .field import P, to_blocks, tag_to_bytes


def _poly_hash(alpha: int, data: bytes) -> int:
    blocks = to_blocks(data)
    acc = 0
    a = 1  # will hold alpha**k
    for c in blocks:
        a = (a * alpha) % P
        acc = (acc + c * a) % P
    # length-framing term (binds the exact byte length)
    a = (a * alpha) % P
    acc = (acc + (len(data) % P) * a) % P
    return acc


def mac(alpha: int, beta: int, data: bytes) -> bytes:
    """Compute the 32-byte one-time authentication tag for `data`."""
    return tag_to_bytes((_poly_hash(alpha, data) + beta) % P)


def verify(alpha: int, beta: int, data: bytes, tag: bytes) -> bool:
    """Constant-time(-comparison) verification of a one-time tag."""
    expected = mac(alpha, beta, data)
    return hmac.compare_digest(expected, tag)
