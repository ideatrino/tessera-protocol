# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""OTP mode: when a shared entropy pool is present, the inner lock is a true
One-Time Pad, giving Shannon-perfect secrecy for that layer."""
from tessera import Session, derive_root, KeyPool
from tessera import chacha20
from tessera.session import _derive_keys, _nonce, FLAG_OTP, OTP_SLOT


def _pair_with_pool(pool_bytes: bytes):
    root = derive_root(pre_shared=b"otp-secret")
    pool_a = KeyPool(pool_bytes)
    pool_b = KeyPool(pool_bytes)
    a = Session.initiator(root, send_pool=pool_a)
    b = Session.responder(root, recv_pool=pool_b)
    return a, b


def test_otp_roundtrip_and_flag_set():
    a, b = _pair_with_pool(b"\x5a" * (OTP_SLOT * 4))
    wire = a.encrypt(b"top secret message")
    assert wire[1] & FLAG_OTP, "OTP flag should be set"
    assert b.decrypt(wire) == b"top secret message"


def test_inner_pad_actually_comes_from_the_pool():
    # White-box: confirm the inner lock used pool bytes (true OTP), not the PRG.
    pool_bytes = bytes((i * 7 + 3) & 0xFF for i in range(OTP_SLOT * 2))
    root = derive_root(pre_shared=b"otp-secret-2")
    pool = KeyPool(pool_bytes)
    a = Session.initiator(root, send_pool=pool)

    msg = b"verify the pad source"
    # Reproduce the message key the sender will use for index 0.
    from tessera.ratchet import Ratchet
    from tessera.kdf import kdf
    a2b = kdf(root, label=b"chain-A2B", length=32)
    rsim = Ratchet(a2b)
    idx, mk = rsim.next_message_key()
    k2, _, _, _ = _derive_keys(mk, len(msg))
    expected_pad = pool_bytes[idx * OTP_SLOT: idx * OTP_SLOT + len(msg)]
    expected_c1 = bytes(x ^ y for x, y in zip(msg, expected_pad))

    wire = a.encrypt(msg)
    ct_len = int.from_bytes(wire[10:14], "big")
    c2 = wire[14:14 + ct_len]
    c1 = chacha20.decrypt(k2, _nonce(idx), c2)  # peel the outer lock
    assert c1 == expected_c1, "inner pad did not come from the pre-shared pool"


def test_pool_exhaustion_falls_back_gracefully():
    # Pool smaller than the message -> cannot form an OTP -> PRG fallback.
    a, b = _pair_with_pool(b"\x01" * 8)
    wire = a.encrypt(b"no room for otp")        # 15 bytes > 8-byte pool
    assert not (wire[1] & FLAG_OTP)            # fell back to PRG
    assert b.decrypt(wire) == b"no room for otp"
