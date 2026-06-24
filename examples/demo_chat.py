#!/usr/bin/env python3
# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
demo_chat.py — a minimal two-party TESSERA conversation.

Run:  python examples/demo_chat.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tessera import Session, derive_root, KeyPool  # noqa: E402


def main() -> None:
    # 1) Establish a shared root. In production, combine a pre-shared secret with
    #    a vetted post-quantum KEM and X25519 (see keyagreement.derive_root).
    root = derive_root(pre_shared=os.urandom(32))

    # 2) Optional: a pre-shared true-entropy pool unlocks perfect-secrecy mode.
    pool_material = os.urandom(64 * 1024)
    alice = Session.initiator(root, send_pool=KeyPool(pool_material))
    bob = Session.responder(root, recv_pool=KeyPool(pool_material))

    print("=== TESSERA demo ===\n")

    # 3) Alice -> Bob, with associated (authenticated, not encrypted) metadata.
    w1 = alice.encrypt(b"Meet at the old bridge, midnight.", associated_data=b"hdr:dm")
    otp = "OTP/perfect-secrecy" if (w1[1] & 0x01) else "PRG"
    print(f"Alice sends {len(w1)} wire bytes  (inner lock: {otp})")
    print("Bob reads :", bob.decrypt(w1, associated_data=b"hdr:dm").decode(), "\n")

    # 4) Bob -> Alice.
    w2 = bob.encrypt(b"Understood. Bring the tessera.")
    print("Alice reads:", alice.decrypt(w2).decode(), "\n")

    # 5) Tampering is detected.
    tampered = bytearray(alice.encrypt(b"balance: 100"))
    tampered[18] ^= 0x01
    try:
        bob.decrypt(bytes(tampered))
    except Exception as e:
        print("Tamper attempt rejected:", type(e).__name__)

    # 6) Replay is rejected.
    w3 = alice.encrypt(b"one-time order")
    bob.decrypt(w3)
    try:
        bob.decrypt(w3)
    except Exception as e:
        print("Replay attempt rejected:", type(e).__name__)

    # 7) Post-compromise healing: both fold in fresh entropy.
    e = os.urandom(32)
    alice.inject_entropy(e)
    bob.inject_entropy(e)
    w4 = alice.encrypt(b"channel healed")
    print("\nAfter healing  :", bob.decrypt(w4).decode())


if __name__ == "__main__":
    main()
