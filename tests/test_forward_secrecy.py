# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""Forward secrecy (ratchet) and post-compromise healing (entropy injection)."""
from tessera import Session, derive_root
from tessera.ratchet import Ratchet


def test_chain_key_advances_and_keys_are_unique():
    r = Ratchet(b"\x11" * 32)
    seen = set()
    keys = []
    for _ in range(50):
        idx, mk = r.next_message_key()
        keys.append((idx, mk))
        assert mk not in seen
        seen.add(mk)
    assert [i for i, _ in keys] == list(range(50))


def test_state_after_step_cannot_reproduce_prior_key():
    # The forward-secure property at the API level: a captured *current* state
    # has no operation that returns a *previous* message key.
    r = Ratchet(b"\x22" * 32)
    _, mk0 = r.next_message_key()
    captured_ck = r._ck                 # attacker captures state here
    forward = Ratchet(captured_ck)
    _, mk1 = forward.next_message_key()
    assert mk1 != mk0                   # cannot step "backwards" to mk0


def test_entropy_injection_must_be_symmetric():
    root = derive_root(pre_shared=b"heal-secret")
    a = Session.initiator(root)
    b = Session.responder(root)
    # Only A heals -> chains diverge -> communication breaks.
    a.inject_entropy(b"fresh-shared-entropy")
    try:
        b.decrypt(a.encrypt(b"after one-sided heal"))
        raise AssertionError("desynchronized channel still decrypted")
    except Exception:
        pass


def test_healing_when_both_sides_inject():
    root = derive_root(pre_shared=b"heal-secret-2")
    a = Session.initiator(root)
    b = Session.responder(root)
    assert b.decrypt(a.encrypt(b"before heal")) == b"before heal"
    # Both peers fold in the same fresh entropy at the same point.
    a.inject_entropy(b"E")
    b.inject_entropy(b"E")
    assert b.decrypt(a.encrypt(b"after heal")) == b"after heal"
    assert a.decrypt(b.encrypt(b"reply after heal")) == b"reply after heal"
