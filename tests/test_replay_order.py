# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""Replay protection and out-of-order delivery handling."""
from tessera import Session, derive_root
from tessera.exceptions import ReplayError, SkipLimitError


def _pair():
    root = derive_root(pre_shared=b"replay-secret")
    return Session.initiator(root), Session.responder(root)


def test_replay_is_rejected():
    a, b = _pair()
    wire = a.encrypt(b"once")
    assert b.decrypt(wire) == b"once"
    try:
        b.decrypt(wire)
        raise AssertionError("replay accepted")
    except ReplayError:
        pass


def test_out_of_order_delivery():
    a, b = _pair()
    w0 = a.encrypt(b"m0")
    w1 = a.encrypt(b"m1")
    w2 = a.encrypt(b"m2")
    # deliver 2, then 0, then 1
    assert b.decrypt(w2) == b"m2"
    assert b.decrypt(w0) == b"m0"
    assert b.decrypt(w1) == b"m1"
    # and none can be replayed afterwards
    for w in (w0, w1, w2):
        try:
            b.decrypt(w)
            raise AssertionError("replay accepted after reorder")
        except ReplayError:
            pass


def test_skip_limit_enforced():
    a, b = _pair()
    # advance the sender far beyond the receiver's skip window
    wires = [a.encrypt(b"x") for _ in range(2000)]
    try:
        b.decrypt(wires[-1])  # gap > MAX_SKIP
        raise AssertionError("excessive skip accepted")
    except SkipLimitError:
        pass


def test_dropped_message_does_not_block_channel():
    a, b = _pair()
    _dropped = a.encrypt(b"lost in transit")
    w1 = a.encrypt(b"arrived")
    assert b.decrypt(w1) == b"arrived"  # works despite the gap
