# crypto/he.py
# CKKS Homomorphic Encryption helpers.
# Context creation, encryption, decryption, and serialization.

import tenseal as ts
import numpy as np

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    CKKS_POLY_MOD_DEGREE,
    CKKS_COEFF_MOD_BITS,
    CKKS_SCALE
)




def create_context() -> ts.Context:
    """
    Create a fresh CKKS context with standard parameters.
    Includes Galois keys for rotation operations.
    """
    ctx = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=CKKS_POLY_MOD_DEGREE,
        coeff_mod_bit_sizes=CKKS_COEFF_MOD_BITS
    )
    ctx.generate_galois_keys()
    ctx.global_scale = CKKS_SCALE
    return ctx


def serialize_context(ctx: ts.Context,
                      save_secret_key: bool = False) -> bytes:
    """Serialize CKKS context to bytes."""
    return ctx.serialize(save_secret_key=save_secret_key)


def deserialize_context(data: bytes) -> ts.Context:
    """Deserialize CKKS context from bytes."""
    return ts.context_from(data)


def encrypt_vector(ctx: ts.Context,
                   vector: np.ndarray) -> ts.CKKSVector:
    """Encrypt a numpy vector under the given CKKS context."""
    return ts.ckks_vector(ctx, vector.tolist())


def serialize_ciphertext(ct: ts.CKKSVector) -> bytes:
    """Serialize a CKKS ciphertext to bytes for transmission."""
    return ct.serialize()


def deserialize_ciphertext(ctx: ts.Context,
                           data: bytes) -> ts.CKKSVector:
    """Deserialize a CKKS ciphertext from bytes."""
    return ts.ckks_vector_from(ctx, data)


def he_dot_product(ct: ts.CKKSVector,
                   weights: np.ndarray,
                   bias: float) -> ts.CKKSVector:
    """
    Perform homomorphic dot product between an encrypted vector
    and plaintext weights, then add plaintext bias.
    Returns an encrypted logit.
    """
    return ct.dot(weights.tolist()) + bias


def decrypt_vector(ct: ts.CKKSVector) -> list:
    """Decrypt a CKKS ciphertext. Returns plaintext list."""
    return ct.decrypt()


if __name__ == "__main__":
    print("Testing CKKS HE pipeline...")
    import numpy as np
    np.random.seed(42)

    ctx     = create_context()
    vector  = np.random.randn(768).astype(np.float64)
    weights = np.random.randn(768).astype(np.float64)
    bias    = float(np.random.randn(1)[0])

    plaintext_logit = np.dot(vector, weights) + bias

    ct            = encrypt_vector(ctx, vector)
    ct_bytes      = serialize_ciphertext(ct)
    ctx_bytes     = serialize_context(ctx, save_secret_key=True)
    ctx_reloaded  = deserialize_context(ctx_bytes)
    ct_reloaded   = deserialize_ciphertext(ctx_reloaded, ct_bytes)
    he_result     = he_dot_product(ct_reloaded, weights, bias)
    decrypted     = decrypt_vector(he_result)[0]

    error = abs(decrypted - plaintext_logit)
    assert error < 0.001, f"HE error too large: {error}"
    print(f"  HE error : {error:.10f}")
    print(f"  he.py OK.")