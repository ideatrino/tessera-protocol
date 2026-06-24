# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""
TESSERA — information-theoretic authentication meets post-quantum
defense-in-depth secure messaging.

EXPERIMENTAL. NOT AUDITED. NOT CONSTANT-TIME. See SECURITY.md before any use.

Public API
----------
    from tessera import Session, derive_root, KeyPool

    root = derive_root(pre_shared=shared_secret)
    alice = Session.initiator(root)
    bob   = Session.responder(root)

    wire = alice.encrypt(b"hello")
    assert bob.decrypt(wire) == b"hello"
"""
from __future__ import annotations

from .exceptions import (
    AuthenticationError,
    EntropyError,
    ReplayError,
    SkipLimitError,
    TesseraError,
)
from .keyagreement import derive_root
from .keypool import KeyPool
from .session import Session

__version__ = "0.1.0"
__author__ = "Ideatrino <ideatrino@proton.me>"

__all__ = [
    "Session",
    "derive_root",
    "KeyPool",
    "TesseraError",
    "AuthenticationError",
    "ReplayError",
    "SkipLimitError",
    "EntropyError",
    "__version__",
]
