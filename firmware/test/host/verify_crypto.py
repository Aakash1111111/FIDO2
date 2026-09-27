#!/usr/bin/env python3
"""Independent cross-verification of fido_crypto output.

Reads vectors written by test_crypto (public data only) and checks them with a
different implementation (pyca/cryptography, backed by OpenSSL):
  * every ES256 signature verifies over m1 || m2 with the given public key,
  * signatures are strict DER (re-encoding gives identical bytes),
  * the COSE_Key decodes to exactly {1:2, 3:-7, -1:1, -2:x, -3:y} matching the
    public key and uses canonical CTAP2 key order,
  * the RFC 6979 known-answer constants used by the firmware self-test are
    themselves consistent (public key derives from the private key and the
    expected signature verifies).

Usage: verify_crypto.py vectors.jsonl
"""
import json
import sys

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def check_vector(v: dict) -> None:
    pub = bytes.fromhex(v["pub"])
    msg = bytes.fromhex(v["m1"]) + bytes.fromhex(v["m2"])
    sig = bytes.fromhex(v["sig"])
    cose = bytes.fromhex(v["cose"])

    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
    key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))

    r, s = decode_dss_signature(sig)
    assert encode_dss_signature(r, s) == sig, "signature is not strict DER"
    assert 0 < r < P256_N and 0 < s < P256_N

    decoded = cbor2.loads(cose)
    assert decoded == {1: 2, 3: -7, -1: 1, -2: pub[1:33], -3: pub[33:65]}, decoded
    assert list(decoded.keys()) == [1, 3, -1, -2, -3], "COSE key not in canonical order"
    assert cbor2.dumps(decoded, canonical=True) == cose, "COSE key is not canonical CBOR"


def check_rfc6979_constants() -> None:
    d = int("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
    priv = ec.derive_private_key(d, ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    assert nums.x == int("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16)
    assert nums.y == int("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16)
    for msg, r, s in [
        (b"sample",
         "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
         "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        (b"test",
         "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
         "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
    ]:
        sig = encode_dss_signature(int(r, 16), int(s, 16))
        priv.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256()))


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "vectors.jsonl"
    check_rfc6979_constants()
    count = 0
    with open(path, encoding="ascii") as f:
        for line in f:
            try:
                check_vector(json.loads(line))
            except (InvalidSignature, AssertionError) as exc:
                print(f"FAIL vector {count}: {exc!r}")
                return 1
            count += 1
    if count == 0:
        print("FAIL: no vectors")
        return 1
    print(f"cross-verified {count} vectors + RFC 6979 constants with pyca/cryptography")
    return 0


if __name__ == "__main__":
    sys.exit(main())
