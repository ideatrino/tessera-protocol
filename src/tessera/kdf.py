# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
kdf.py — SHAKE-256 based key-derivation / pseudo-random generator.

Every derivation in TESSERA goes through `kdf()` with an explicit, unique
`label`. Domain separation guarantees that key material derived for one purpose
(e.g. the confidentiality pad) is computationally independent from material
derived for another (e.g. the MAC keys), even from the same secret.
"""
from __future__ import annotations

import hashlib

_PROTOCOL_ID = b"TESSERA-v1"


def kdf(*chunks: bytes, label: bytes, length: int) -> bytes:
    """Derive `length` bytes from the given secret chunks under `label`.

    The protocol id, the label, and the length-prefixed chunks are all absorbed,
    so no two distinct (label, inputs) tuples can collide on their absorbed
    encoding. Output is an XOF (extendable-output function) read of `length`.
    """
    h = hashlib.shake_256()
    h.update(_PROTOCOL_ID)
    h.update(len(label).to_bytes(2, "big"))
    h.update(label)
    for c in chunks:
        h.update(len(c).to_bytes(8, "big"))
        h.update(c)
    return h.digest(length)
