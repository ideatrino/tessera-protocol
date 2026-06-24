# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
session.py — the high-level TESSERA session.

Ties the components together into an authenticated, forward-secure, dual-lock
channel with replay protection and optional One-Time-Pad (perfect-secrecy) mode.

Wire format (all integers big-endian):

    +---------+--------+-------------+----------+----------------+--------+
    | version |  flags |  msg_index  |  ct_len  |   ciphertext   |  tag   |
    |  1 byte | 1 byte |   8 bytes   |  4 bytes |   ct_len bytes |32 bytes|
    +---------+--------+-------------+----------+----------------+--------+

`flags` bit 0 = inner lock used OTP mode for this message.
The header AND any associated data are authenticated by the tag.
"""
from __future__ import annotations

from . import chacha20
from .exceptions import AuthenticationError, ReplayError, SkipLimitError
from .field import reduce_to_field
from .kdf import kdf
from .keypool import KeyPool
from .mac import mac, verify
from .ratchet import Ratchet

VERSION = 0x01
FLAG_OTP = 0x01
MAX_SKIP = 1024            # max out-of-order / dropped messages tolerated
OTP_SLOT = 4096            # fixed pool slot per message in OTP mode

_LABEL_A2B = b"chain-A2B"
_LABEL_B2A = b"chain-B2A"


def _derive_keys(mk: bytes, pad_len: int):
    """Expand a 64-byte message key into the four per-message keys."""
    k2 = kdf(mk, label=b"chacha", length=32)
    alpha = reduce_to_field(kdf(mk, label=b"alpha", length=48))
    beta = reduce_to_field(kdf(mk, label=b"beta", length=48))
    pad = kdf(mk, label=b"pad", length=pad_len)  # PRG-mode inner pad
    return k2, alpha, beta, pad


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _nonce(idx: int) -> bytes:
    return b"\x00\x00\x00\x00" + idx.to_bytes(8, "big")


def _mac_input(header: bytes, ad: bytes, ct: bytes) -> bytes:
    return header + len(ad).to_bytes(4, "big") + ad + ct


class _ReceiveChain:
    """Receive-side ratchet with out-of-order tolerance and replay protection."""

    def __init__(self, chain_key: bytes):
        self.ratchet = Ratchet(chain_key)
        self.skipped: dict[int, bytes] = {}

    def prepare(self, idx: int):
        """Return (message_key, commit_callable) for `idx` WITHOUT mutating
        state. The caller commits only after the tag verifies, so a forged
        message cannot desynchronize the chain."""
        if idx in self.skipped:
            mk = self.skipped[idx]
            return mk, (lambda: self.skipped.pop(idx, None))

        if idx < self.ratchet.index:
            raise ReplayError(f"message index {idx} already consumed (replay)")

        gap = idx - self.ratchet.index
        if gap > MAX_SKIP:
            raise SkipLimitError(f"would skip {gap} > {MAX_SKIP} messages")

        clone = Ratchet(self.ratchet._ck)
        clone.index = self.ratchet.index
        new_skips: dict[int, bytes] = {}
        while clone.index < idx:
            i, mk_i = clone.next_message_key()
            new_skips[i] = mk_i
        _, mk = clone.next_message_key()

        def commit():
            self.skipped.update(new_skips)
            self.ratchet = clone

        return mk, commit


class Session:
    """A bidirectional TESSERA channel between two peers."""

    def __init__(
        self,
        send_chain_key: bytes,
        recv_chain_key: bytes,
        send_pool: KeyPool | None = None,
        recv_pool: KeyPool | None = None,
    ):
        self._send = Ratchet(send_chain_key)
        self._recv = _ReceiveChain(recv_chain_key)
        self._send_pool = send_pool
        self._recv_pool = recv_pool

    # ---- construction ----------------------------------------------------
    @classmethod
    def _from_root(cls, root: bytes, initiator: bool, send_pool, recv_pool):
        a2b = kdf(root, label=_LABEL_A2B, length=32)
        b2a = kdf(root, label=_LABEL_B2A, length=32)
        if initiator:
            return cls(a2b, b2a, send_pool, recv_pool)
        return cls(b2a, a2b, send_pool, recv_pool)

    @classmethod
    def initiator(cls, root: bytes, send_pool=None, recv_pool=None) -> "Session":
        return cls._from_root(root, True, send_pool, recv_pool)

    @classmethod
    def responder(cls, root: bytes, send_pool=None, recv_pool=None) -> "Session":
        return cls._from_root(root, False, send_pool, recv_pool)

    # ---- healing ---------------------------------------------------------
    def inject_entropy(self, entropy: bytes) -> None:
        """Fold fresh shared entropy into BOTH directions (post-compromise
        security). Both peers must call this with the same entropy at a
        coordinated point in the conversation."""
        self._send.inject_entropy(entropy)
        self._recv.ratchet.inject_entropy(entropy)

    # ---- encryption ------------------------------------------------------
    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        idx, mk = self._send.next_message_key()
        L = len(plaintext)
        k2, alpha, beta, prg_pad = _derive_keys(mk, L)

        flags = 0
        if self._send_pool is not None and L <= OTP_SLOT:
            try:
                kappa = self._send_pool.take_at(idx * OTP_SLOT, L)
                flags |= FLAG_OTP
            except Exception:
                kappa = prg_pad  # graceful fallback when the pool is exhausted
        else:
            kappa = prg_pad

        c1 = _xor(plaintext, kappa)                    # inner lock
        c2 = chacha20.encrypt(k2, _nonce(idx), c1)     # outer lock

        header = (
            bytes([VERSION, flags])
            + idx.to_bytes(8, "big")
            + len(c2).to_bytes(4, "big")
        )
        tag = mac(alpha, beta, _mac_input(header, associated_data, c2))
        return header + c2 + tag

    # ---- decryption ------------------------------------------------------
    def decrypt(self, wire: bytes, associated_data: bytes = b"") -> bytes:
        if len(wire) < 1 + 1 + 8 + 4 + 32:
            raise AuthenticationError("message too short")
        version = wire[0]
        flags = wire[1]
        if version != VERSION:
            raise AuthenticationError(f"unsupported version {version}")
        idx = int.from_bytes(wire[2:10], "big")
        ct_len = int.from_bytes(wire[10:14], "big")
        header = wire[:14]
        c2 = wire[14:14 + ct_len]
        tag = wire[14 + ct_len:14 + ct_len + 32]
        if len(c2) != ct_len or len(tag) != 32:
            raise AuthenticationError("truncated message")

        mk, commit = self._recv.prepare(idx)
        k2, alpha, beta, prg_pad = _derive_keys(mk, ct_len)

        if not verify(alpha, beta, _mac_input(header, associated_data, c2), tag):
            # No commit: forged/tampered messages never advance state.
            raise AuthenticationError("authentication failed")

        c1 = chacha20.decrypt(k2, _nonce(idx), c2)     # peel outer lock
        if flags & FLAG_OTP:
            if self._recv_pool is None:
                raise AuthenticationError("OTP flagged but no pool available")
            kappa = self._recv_pool.take_at(idx * OTP_SLOT, ct_len)
        else:
            kappa = prg_pad
        plaintext = _xor(c1, kappa)                    # peel inner lock

        commit()  # only now is the receive chain advanced
        return plaintext
