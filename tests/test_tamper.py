# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""Any modification to the wire message must be rejected."""
from tessera import Session, derive_root
from tessera.exceptions import AuthenticationError


def _pair():
    root = derive_root(pre_shared=b"tamper-test-secret")
    return Session.initiator(root), Session.responder(root)


def test_single_bit_flips_anywhere_are_rejected():
    a, b = _pair()
    wire = bytearray(a.encrypt(b"transfer 100 coins to alice"))
    rejected = 0
    for byte_i in range(len(wire)):
        for bit in range(8):
            mutated = bytearray(wire)
            mutated[byte_i] ^= (1 << bit)
            if bytes(mutated) == bytes(wire):
                continue
            fresh = Session.responder(derive_root(pre_shared=b"tamper-test-secret"))
            try:
                fresh.decrypt(bytes(mutated))
            except Exception:
                rejected += 1
            else:
                raise AssertionError(f"mutation at byte {byte_i} bit {bit} accepted")
    assert rejected > 0


def test_truncation_rejected():
    a, b = _pair()
    wire = a.encrypt(b"important")
    try:
        b.decrypt(wire[:-1])
        raise AssertionError("truncated message accepted")
    except Exception:
        pass


def test_corrupt_ciphertext_body():
    a, b = _pair()
    wire = bytearray(a.encrypt(b"x" * 64))
    wire[20] ^= 0xFF  # somewhere in the ciphertext body
    try:
        b.decrypt(bytes(wire))
        raise AssertionError("corrupted body accepted")
    except AuthenticationError:
        pass
