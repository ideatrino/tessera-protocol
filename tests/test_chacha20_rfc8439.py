# Copyright (c) 2026 Ideatrino <ideatrino@proton.me>
# All Rights Reserved. See LICENSE.
"""Validate the ChaCha20 primitive against official RFC 8439 test vectors.

If these pass, the outer-lock cipher is implemented correctly to spec.
"""
from tessera import chacha20


def test_block_function_rfc8439_section_2_3_2():
    key = bytes(range(32))  # 00 01 ... 1f
    nonce = bytes.fromhex("000000090000004a00000000")
    counter = 1
    # 64-byte serialized keystream block from RFC 8439 section 2.3.2:
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    out = chacha20.block(key, counter, nonce)
    assert out == expected, out.hex()


def test_encrypt_rfc8439_section_2_4_2_sunscreen():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    out = chacha20.encrypt(key, nonce, plaintext, counter=1)
    assert out == expected, out.hex()
    assert chacha20.decrypt(key, nonce, out, counter=1) == plaintext
