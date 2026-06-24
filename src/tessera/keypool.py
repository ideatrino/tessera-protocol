# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
keypool.py — Optional pre-shared true-entropy pool enabling OTP mode.

When two parties share a pool of genuine random bytes (out-of-band), the inner
confidentiality lock can draw its pad directly from the pool instead of from the
PRG. In that mode the inner lock is a One-Time Pad and provides Shannon-perfect
secrecy: the ciphertext is information-theoretically independent of the plaintext.

Both sides MUST consume the pool in lockstep (same offsets for the same
messages) and MUST NEVER reuse a region. This reference implementation indexes
the pool by absolute message offset to keep the two sides synchronized.
"""
from __future__ import annotations

from .exceptions import EntropyError


class KeyPool:
    """A finite pool of pre-shared random bytes, consumed by absolute offset."""

    def __init__(self, material: bytes):
        self._material = material
        self._used_until = 0  # high-water mark of consumed bytes (for accounting)

    @property
    def remaining(self) -> int:
        return len(self._material) - self._used_until

    def take_at(self, offset: int, length: int) -> bytes:
        """Return `length` pad bytes starting at absolute `offset`.

        Indexing by absolute offset (rather than sequential pop) lets both peers
        agree on exactly which pad bytes a given message uses, regardless of
        ordering, while still forbidding reuse within a single party.
        """
        end = offset + length
        if end > len(self._material):
            raise EntropyError(
                f"OTP pool exhausted: need bytes [{offset}:{end}], "
                f"have {len(self._material)}"
            )
        self._used_until = max(self._used_until, end)
        return self._material[offset:end]
