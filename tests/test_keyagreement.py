# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""Hybrid root derivation from one or more shared secrets."""
from tessera import derive_root


def test_deterministic():
    r1 = derive_root(pre_shared=b"a", kem_secret=b"b", ecdh_secret=b"c")
    r2 = derive_root(pre_shared=b"a", kem_secret=b"b", ecdh_secret=b"c")
    assert r1 == r2 and len(r1) == 32


def test_requires_at_least_one_secret():
    try:
        derive_root()
        raise AssertionError("empty derivation accepted")
    except ValueError:
        pass


def test_distinct_inputs_distinct_roots():
    assert derive_root(pre_shared=b"x") != derive_root(pre_shared=b"y")
    # Each component independently changes the root.
    base = derive_root(pre_shared=b"p", kem_secret=b"k", ecdh_secret=b"e")
    assert base != derive_root(pre_shared=b"P", kem_secret=b"k", ecdh_secret=b"e")
    assert base != derive_root(pre_shared=b"p", kem_secret=b"K", ecdh_secret=b"e")
    assert base != derive_root(pre_shared=b"p", kem_secret=b"k", ecdh_secret=b"E")


def test_field_separation_no_concatenation_collision():
    # Length-prefixed absorption prevents ("ab","c") colliding with ("a","bc").
    assert derive_root(pre_shared=b"ab", kem_secret=b"c") != \
           derive_root(pre_shared=b"a", kem_secret=b"bc")
