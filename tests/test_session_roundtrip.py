# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""End-to-end round-trip behaviour of a Session."""
from tessera import Session, derive_root


def _pair():
    root = derive_root(pre_shared=b"shared-out-of-band-secret")
    return Session.initiator(root), Session.responder(root)


def test_single_message_roundtrip():
    a, b = _pair()
    wire = a.encrypt(b"hello world")
    assert b.decrypt(wire) == b"hello world"


def test_empty_and_binary_payloads():
    a, b = _pair()
    for m in (b"", b"\x00" * 100, bytes(range(256)) * 4):
        assert b.decrypt(a.encrypt(m)) == m


def test_bidirectional_conversation():
    a, b = _pair()
    assert b.decrypt(a.encrypt(b"ping")) == b"ping"
    assert a.decrypt(b.encrypt(b"pong")) == b"pong"
    assert b.decrypt(a.encrypt(b"ping2")) == b"ping2"
    assert a.decrypt(b.encrypt(b"pong2")) == b"pong2"


def test_many_messages_in_order():
    a, b = _pair()
    for i in range(200):
        m = f"message number {i}".encode()
        assert b.decrypt(a.encrypt(m)) == m


def test_associated_data_must_match():
    a, b = _pair()
    wire = a.encrypt(b"payload", associated_data=b"to:bob;type:dm")
    assert b.decrypt(wire, associated_data=b"to:bob;type:dm") == b"payload"
    try:
        b2 = Session.responder(derive_root(pre_shared=b"shared-out-of-band-secret"))
        b2.decrypt(wire, associated_data=b"to:eve;type:dm")
        assert False, "should have raised on AD mismatch"
    except Exception:
        pass


def test_ciphertext_differs_for_identical_plaintext():
    a, _ = _pair()
    w1 = a.encrypt(b"same")
    w2 = a.encrypt(b"same")
    assert w1 != w2  # fresh per-message keys -> different ciphertext
