"""Minimal Ed25519 signatures using only the Python 3.12 standard library.

This is the classic reference implementation of Ed25519 (RFC 8032) expressed
with big-int modular arithmetic over the twisted Edwards curve.  It is kept
deliberately small and dependency free so the drill runs on a stock Windows
Python 3.12 without ``cryptography`` or any third-party package.

Only a few hundred drill signatures are produced on the correctness path, so
the simple affine-coordinate reference formulas are fast enough.  The bulk
60k simulation uses HMAC tags instead (see :mod:`isolation.scale`).

Correctness is checked at runtime against the RFC 8032 section 7.1 test
vectors by :func:`selftest`.
"""

from __future__ import annotations

import hashlib
from typing import List

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


_d = -121665 * _inv(121666)
_I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B: List[int] = [_Bx % q, _By % q]


def _edwards(P: List[int], Q: List[int]) -> List[int]:
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P: List[int], e: int) -> List[int]:
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P: List[int]) -> bytes:
    x, y = P[0], P[1]
    out = bytearray(32)
    for i in range(32):
        byte = 0
        for j in range(8):
            bit_index = i * 8 + j
            if bit_index < b - 1:  # 0..254 are y bits
                bit = (y >> bit_index) & 1
            else:                  # bit 255 is the sign/x parity bit
                bit = x & 1
            byte |= bit << j
        out[i] = byte
    return bytes(out)


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    return int.from_bytes(_H(m), "little")


def derive_public(seed: bytes) -> bytes:
    """Return the 32-byte Ed25519 public key for a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def sign_message(seed: bytes, msg: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature for *msg* using *seed*."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    prefix = h[32:]
    r = _hint(prefix + msg)
    R = _scalarmult(_B, r)
    R_enc = _encodepoint(R)
    pk = derive_public(seed)
    k = _hint(R_enc + pk + msg)
    S = (r + k * a) % l
    return R_enc + _encodeint(S)


def _isoncurve(P: List[int]) -> bool:
    x, y = P[0], P[1]
    return (-x * x + y * y - 1 - _d * x * x * y * y) % q == 0


def _decodepoint(s: bytes) -> List[int]:
    y = int.from_bytes(s[:32], "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def verify_message(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an Ed25519 signature. Returns ``False`` for any malformed input."""
    try:
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            return False
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            return False
        R = _decodepoint(bytes(sig[:32]))
        A = _decodepoint(bytes(pub))
        S = int.from_bytes(bytes(sig[32:64]), "little")
        if S >= l:
            return False
        h = _hint(bytes(sig[:32]) + bytes(pub) + msg)
        left = _scalarmult(_B, S)
        right = _edwards(R, _scalarmult(A, h))
        return left[0] == right[0] and left[1] == right[1]
    except Exception:
        return False


# ---------------------------------------------------------------------------
# RFC 8032 section 7.1 test vectors
# ---------------------------------------------------------------------------

_RFC_VECTORS = [
    {
        "seed": "9d61b19defffd55a60ba844af492ec2cc44449c5697b326919703bac031cae7f",
        "pub": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "msg": "",
        "sig": (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pub": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "msg": "72",
        "sig": (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    },
]


def selftest() -> dict:
    """Check RFC vectors plus sign/verify round trips and tamper rejection."""
    results = []
    all_ok = True
    for i, vec in enumerate(_RFC_VECTORS, 1):
        seed = bytes.fromhex(vec["seed"])
        expect_pub = vec["pub"]
        expect_sig = vec["sig"]
        msg = bytes.fromhex(vec["msg"])
        pub = derive_public(seed).hex()
        sig = sign_message(seed, msg).hex()
        pub_ok = pub == expect_pub
        sig_ok = sig == expect_sig
        verifies = verify_message(bytes.fromhex(expect_pub), msg,
                                  bytes.fromhex(expect_sig))
        ok = pub_ok and sig_ok and verifies
        all_ok &= ok
        results.append({
            "vector": f"RFC8032-7.1 test {i}",
            "public_key_match": pub_ok,
            "signature_match": sig_ok,
            "verify": verifies,
            "ok": ok,
        })

    # Round trip + tamper + wrong-key checks on synthetic data.
    seed_a = hashlib.sha256(b"isolation-drill/selftest/a").digest()
    seed_b = hashlib.sha256(b"isolation-drill/selftest/b").digest()
    pub_a = derive_public(seed_a)
    msg = b"rule-gen=1\ndigest=abc\n"
    sig = sign_message(seed_a, msg)
    rt = verify_message(pub_a, msg, sig)
    tampered = verify_message(pub_a, msg + b"x", sig)
    wrong_key = verify_message(derive_public(seed_b), msg, sig)
    bad_sig = verify_message(pub_a, msg, sig[:-1] + bytes([sig[-1] ^ 1]))
    roundtrip_ok = rt and not tampered and not wrong_key and not bad_sig
    all_ok &= roundtrip_ok
    results.append({
        "vector": "round-trip/tamper/wrong-key",
        "roundtrip": rt,
        "tampered_rejected": not tampered,
        "wrong_key_rejected": not wrong_key,
        "corrupt_sig_rejected": not bad_sig,
        "ok": roundtrip_ok,
    })
    return {"ok": all_ok, "checks": results}
