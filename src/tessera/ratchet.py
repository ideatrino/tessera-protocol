# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
ratchet.py — Forward-secure symmetric ratchet (the "Reservoir engine").

A chain key advances one step per message via a one-way KDF. After each step the
previous chain key is overwritten (best-effort in Python), so a state compromise
cannot recover *past* message keys -> forward secrecy.

`inject_entropy` folds fresh, externally-agreed entropy into the chain. If the
injected entropy is unknown to an attacker who previously stole the state, the
chain "heals" -> post-compromise security.

Each per-message key block is expanded by the Session into:
  - kappa  : inner-lock pad (length = plaintext length)
  - k2     : outer-lock ChaCha20 key (32 bytes)
  - alpha  : universal-hash key   (field element)
  - beta   : one-time MAC mask     (field element)
"""
from __future__ import annotations

from .kdf import kdf


class Ratchet:
    """A one-directional forward-secure chain of message keys."""

    def __init__(self, chain_key: bytes):
        if len(chain_key) != 32:
            raise ValueError("chain key must be 32 bytes")
        self._ck = chain_key
        self.index = 0  # index of the NEXT message key to be produced

    def _overwrite(self, new_ck: bytes) -> None:
        # Best-effort scrub of the old chain key. (CPython cannot guarantee no
        # copies remain; real deployments need a secure-memory allocator.)
        old = bytearray(self._ck)
        for i in range(len(old)):
            old[i] = 0
        self._ck = new_ck

    def next_message_key(self) -> tuple[int, bytes]:
        """Return (index, message_key) and advance the chain irreversibly."""
        mk = kdf(self._ck, label=b"msgkey", length=64)
        new_ck = kdf(self._ck, label=b"chain", length=32)
        idx = self.index
        self._overwrite(new_ck)
        self.index += 1
        return idx, mk

    def inject_entropy(self, entropy: bytes) -> None:
        """Fold fresh shared entropy into the chain (post-compromise healing)."""
        new_ck = kdf(self._ck, entropy, label=b"heal", length=32)
        self._overwrite(new_ck)
