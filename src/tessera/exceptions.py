# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""tessera.exceptions — error types raised by the protocol."""
from __future__ import annotations


class TesseraError(Exception):
    """Base class for all TESSERA errors."""


class AuthenticationError(TesseraError):
    """Raised when a message fails authentication (tampering / wrong key)."""


class ReplayError(TesseraError):
    """Raised when a message index has already been seen or is too old."""


class SkipLimitError(TesseraError):
    """Raised when too many messages would have to be skipped to advance."""


class EntropyError(TesseraError):
    """Raised when an OTP-mode keypool cannot satisfy a request."""
