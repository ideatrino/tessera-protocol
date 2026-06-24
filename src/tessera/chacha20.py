# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
chacha20.py — RFC 8439 ChaCha20 stream cipher (pure Python).

This is the *outer lock* primitive in TESSERA's dual-lock confidentiality
construction. It is deliberately a *different* primitive family from the
SHAKE-256 keystream used for the inner lock, so that defeating one layer does
not imply defeating the other.

NOTE: This pure-Python implementation is for reference, testing, and study.
It is NOT constant-time and must not be used where timing side-channels matter.
"""
from __future__ import annotations

import struct

_MASK = 0xFFFFFFFF
_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK; s[d] ^= s[a]; s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & _MASK; s[b] ^= s[c]; s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & _MASK; s[d] ^= s[a]; s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & _MASK; s[b] ^= s[c]; s[b] = _rotl(s[b], 7)


def block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Return the 64-byte ChaCha20 keystream block (RFC 8439 §2.3)."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce)
    state = [_CONST[0], _CONST[1], _CONST[2], _CONST[3],
             k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
             counter & _MASK, n[0], n[1], n[2]]
    w = state[:]
    for _ in range(10):  # 20 rounds = 10 double-rounds
        _quarter_round(w, 0, 4, 8, 12)
        _quarter_round(w, 1, 5, 9, 13)
        _quarter_round(w, 2, 6, 10, 14)
        _quarter_round(w, 3, 7, 11, 15)
        _quarter_round(w, 0, 5, 10, 15)
        _quarter_round(w, 1, 6, 11, 12)
        _quarter_round(w, 2, 7, 8, 13)
        _quarter_round(w, 3, 4, 9, 14)
    out = [(w[i] + state[i]) & _MASK for i in range(16)]
    return struct.pack("<16I", *out)


def stream(key: bytes, nonce: bytes, length: int, counter: int = 0) -> bytes:
    """Generate `length` keystream bytes (RFC 8439 §2.4)."""
    out = bytearray()
    blk = counter
    while len(out) < length:
        out += block(key, blk, nonce)
        blk += 1
    return bytes(out[:length])


def encrypt(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """XOR `data` with the ChaCha20 keystream. encrypt == decrypt."""
    ks = stream(key, nonce, len(data), counter)
    return bytes(a ^ b for a, b in zip(data, ks))


# decrypt is symmetric
decrypt = encrypt
