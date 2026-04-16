# crypto/signatures.py
# ECDSA signing and verification.
# NIST P-256 curve, SHA-256 hash, FIPS 186-4 compliant.

import ecdsa
import hashlib

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


CURVE = ecdsa.NIST256p


def generate_keypair():
    """
    Generate a new ECDSA key pair.
    Returns (signing_key, verifying_key).
    """
    sk = ecdsa.SigningKey.generate(curve=CURVE)
    vk = sk.get_verifying_key()
    return sk, vk


def sign_data(data: bytes, signing_key: ecdsa.SigningKey) -> bytes:
    """Sign bytes with ECDSA SHA-256. Returns 64-byte signature."""
    return signing_key.sign(data, hashfunc=hashlib.sha256)


def verify_signature(data: bytes,
                     signature: bytes,
                     verifying_key: ecdsa.VerifyingKey) -> bool:
    """Verify an ECDSA signature. Returns True if valid."""
    try:
        verifying_key.verify(signature, data, hashfunc=hashlib.sha256)
        return True
    except ecdsa.BadSignatureError:
        return False


def sk_to_hex(sk: ecdsa.SigningKey) -> str:
    """Serialize signing key to hex string for storage."""
    return sk.to_string().hex()


def vk_to_hex(vk: ecdsa.VerifyingKey) -> str:
    """Serialize verifying key to hex string for storage."""
    return vk.to_string().hex()


def sk_from_hex(hex_str: str) -> ecdsa.SigningKey:
    """Deserialize signing key from hex string."""
    return ecdsa.SigningKey.from_string(
        bytes.fromhex(hex_str), curve=CURVE
    )


def vk_from_hex(hex_str: str) -> ecdsa.VerifyingKey:
    """Deserialize verifying key from hex string."""
    return ecdsa.VerifyingKey.from_string(
        bytes.fromhex(hex_str), curve=CURVE
    )


if __name__ == "__main__":
    print("Testing ECDSA signatures...")
    sk, vk = generate_keypair()
    data = b"test payload"
    sig  = sign_data(data, sk)
    assert verify_signature(data, sig, vk), "Valid sig failed."

    tampered = b"tampered payload"
    assert not verify_signature(tampered, sig, vk), "Tamper not detected."
    print("  Signing and verification OK.")

    sk2, vk2 = generate_keypair()
    assert not verify_signature(data, sig, vk2), "Wrong key not detected."
    print("  Wrong key detection OK.")

    hex_sk = sk_to_hex(sk)
    hex_vk = vk_to_hex(vk)
    sk_r   = sk_from_hex(hex_sk)
    vk_r   = vk_from_hex(hex_vk)
    assert verify_signature(data, sign_data(data, sk_r), vk_r)
    print("  Serialization and deserialization OK.")
    print("  signatures.py OK.")