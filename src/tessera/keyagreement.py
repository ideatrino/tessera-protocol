# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
keyagreement.py — Hybrid root-key derivation framework.

The root key r0 is derived by combining up to three INDEPENDENT shared secrets
so that the result is secure if ANY ONE of them is secure:

    r0 = KDF( pre_shared || kem_secret || ecdh_secret , label="root" )

  * pre_shared  : the literal "two halves of the tessera" (out-of-band secret).
                  Required for OTP-grade modes.
  * kem_secret  : output of a POST-QUANTUM key-encapsulation mechanism
                  (e.g. ML-KEM / Kyber). MUST be supplied by a vetted library.
  * ecdh_secret : classical elliptic-curve Diffie-Hellman (e.g. X25519).

This module deliberately does NOT implement a post-quantum KEM. Rolling your own
KEM is exactly the mistake this project warns against. Plug in a reviewed
implementation and pass its shared secret here.
"""
from __future__ import annotations

from .kdf import kdf


def derive_root(
    pre_shared: bytes = b"",
    kem_secret: bytes = b"",
    ecdh_secret: bytes = b"",
) -> bytes:
    """Combine the available shared secrets into a 32-byte root key."""
    if not (pre_shared or kem_secret or ecdh_secret):
        raise ValueError("at least one shared secret must be provided")
    return kdf(pre_shared, kem_secret, ecdh_secret, label=b"root", length=32)
