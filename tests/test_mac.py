# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""Properties of the Carter--Wegman one-time MAC."""
from tessera import mac
from tessera.field import P, reduce_to_field
from tessera.kdf import kdf


def _keys(seed: bytes):
    a = reduce_to_field(kdf(seed, label=b"a", length=48))
    b = reduce_to_field(kdf(seed, label=b"b", length=48))
    return a, b


def test_determinism():
    a, b = _keys(b"seed-1")
    m = b"the quick brown fox"
    assert mac.mac(a, b, m) == mac.mac(a, b, m)


def test_verify_accepts_and_rejects():
    a, b = _keys(b"seed-2")
    m = b"authenticated payload"
    t = mac.mac(a, b, m)
    assert mac.verify(a, b, m, t) is True
    assert mac.verify(a, b, m + b"x", t) is False           # changed message
    bad = bytes([t[0] ^ 1]) + t[1:]
    assert mac.verify(a, b, m, bad) is False                # changed tag


def test_tag_is_32_bytes_and_in_field():
    a, b = _keys(b"seed-3")
    t = mac.mac(a, b, b"x" * 1000)
    assert len(t) == 32
    assert int.from_bytes(t, "big") < P


def test_length_framing_distinguishes_truncation():
    # Two messages where one is a prefix of the other must (almost surely)
    # produce different tags thanks to the length-framing term.
    a, b = _keys(b"seed-4")
    assert mac.mac(a, b, b"AAAA") != mac.mac(a, b, b"AAAA\x00")


def test_different_keys_diverge():
    a1, b1 = _keys(b"k1")
    a2, b2 = _keys(b"k2")
    m = b"same message, different keys"
    assert mac.mac(a1, b1, m) != mac.mac(a2, b2, m)
