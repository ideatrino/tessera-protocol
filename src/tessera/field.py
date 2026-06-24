# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
field.py — Prime-field arithmetic and message block packing for the
Carter--Wegman universal-hash MAC.

We work in GF(p) with p = 2**255 - 19 (a well-known safe prime). Messages are
packed into 31-byte (248-bit) coefficients so that every coefficient is < 2**248
< p, which keeps the polynomial-hash analysis clean.
"""
from __future__ import annotations

# A well-known prime (the Curve25519 field prime). Used here only as the modulus
# of a universal hash family; any sufficiently large prime would serve.
P = (1 << 255) - 19

# 31 bytes -> value < 2**248 < P, guaranteeing each coefficient is a field elem.
BLOCK_BYTES = 31


def to_blocks(data: bytes) -> list[int]:
    """Split `data` into big-endian 31-byte field-element coefficients."""
    return [
        int.from_bytes(data[i:i + BLOCK_BYTES], "big")
        for i in range(0, len(data), BLOCK_BYTES)
    ]


def reduce_to_field(raw: bytes) -> int:
    """Map raw bytes (>= 48 recommended) to a near-uniform element of GF(p)."""
    return int.from_bytes(raw, "big") % P


def tag_to_bytes(tag: int) -> bytes:
    """Serialize a field element as a fixed 32-byte big-endian tag."""
    return (tag % P).to_bytes(32, "big")
