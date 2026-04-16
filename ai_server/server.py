# ai_server/server.py
# AI Compute Server — untrusted cloud component.
# Receives encrypted patient vectors, performs HE dot product,
# signs the response, forwards to Key Authority.
# Never sees plaintext patient data at any point.

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import hashlib
import datetime
import base64
import numpy as np
import requests
from flask import Flask, request, jsonify

from config import (
    AI_SERVER_PORT,
    AUTHORITY_SERVER_URL,
    MODEL_WEIGHTS_FILE,
    MODEL_INTERCEPT_FILE,
    PATIENT_ID
)
from crypto.he import (
    deserialize_context,
    deserialize_ciphertext,
    he_dot_product,
    serialize_ciphertext
)
from crypto.signatures import (
    generate_keypair,
    sign_data,
    verify_signature,
    vk_from_hex,
    vk_to_hex,
    sk_to_hex
)

app = Flask(__name__)

# --- Load model weights at startup ---
print("Loading model weights...")
try:
    MODEL_WEIGHTS   = np.load(MODEL_WEIGHTS_FILE)
    MODEL_INTERCEPT = float(np.load(MODEL_INTERCEPT_FILE)[0])
    print(f"  Weights loaded : {MODEL_WEIGHTS.shape}")
    print(f"  Intercept      : {MODEL_INTERCEPT:.6f}")
except FileNotFoundError:
    print("  ERROR: Model weights not found.")
    print(f"  Expected at    : {MODEL_WEIGHTS_FILE}")
    print("  Copy coef.npy and intercept.npy into resilience/models/")
    sys.exit(1)

# --- Generate AI server ECDSA key pair ---
AI_SK, AI_VK = generate_keypair()
print(f"  AI server public key : {vk_to_hex(AI_VK)[:32]}...")

# --- Store registered patient public keys ---
# In a real system this would be a database.
# Here it is an in-memory dict populated at registration.
registered_patients = {}


def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status"    : "online",
        "service"   : "AI Compute Server",
        "model"     : "LR-MentalBERT-v1.0",
        "timestamp" : datetime.datetime.now().isoformat()
    })


@app.route("/register", methods=["POST"])
def register():
    """
    Register a patient's public key and CKKS public context.
    Called once during patient registration.
    """
    data = request.get_json()

    patient_id = data.get("patient_id")
    patient_vk_hex = data.get("patient_vk")
    ctx_b64    = data.get("public_context")

    if not all([patient_id, patient_vk_hex, ctx_b64]):
        return jsonify({"error": "Missing fields."}), 400

    # Store patient public key and context
    registered_patients[patient_id] = {
        "vk_hex"        : patient_vk_hex,
        "public_context": ctx_b64
    }

    print(f"\n[REGISTER] Patient registered: {patient_id}")
    print(f"           Public key : {patient_vk_hex[:32]}...")

    return jsonify({
        "status"    : "registered",
        "patient_id": patient_id,
        "ai_vk"     : vk_to_hex(AI_VK)
    })


@app.route("/infer", methods=["POST"])
def infer():
    """
    Main inference endpoint.
    Receives encrypted vector + patient signature.
    Performs HE dot product.
    Signs response and forwards to Key Authority.
    Returns countersigned result to caller.
    """
    data = request.get_json()

    patient_id   = data.get("patient_id")
    ct_b64       = data.get("ciphertext")
    manifest_b64 = data.get("manifest")
    patient_sig_hex = data.get("patient_signature")
    ctx_b64      = data.get("public_context")

    if not all([patient_id, ct_b64, manifest_b64,
                patient_sig_hex, ctx_b64]):
        return jsonify({"error": "Missing fields."}), 400

    # --- Step 1: Verify patient is registered ---
    if patient_id not in registered_patients:
        return jsonify({"error": "Patient not registered."}), 403

    # --- Step 2: Verify patient ECDSA signature ---
    patient_vk  = vk_from_hex(registered_patients[patient_id]["vk_hex"])
    manifest_bytes = base64.b64decode(manifest_b64)
    patient_sig    = bytes.fromhex(patient_sig_hex)

    if not verify_signature(manifest_bytes, patient_sig, patient_vk):
        print(f"[INFER] Signature verification FAILED for {patient_id}")
        return jsonify({"error": "Invalid patient signature."}), 401

    print(f"\n[INFER] Patient signature verified for {patient_id}")

    # --- Step 3: Deserialize context and ciphertext ---
    ctx_bytes = base64.b64decode(ctx_b64)
    ct_bytes  = base64.b64decode(ct_b64)

    ctx = deserialize_context(ctx_bytes)
    ct  = deserialize_ciphertext(ctx, ct_bytes)

    ct_hash = hash_data(ct_bytes)
    print(f"[INFER] Ciphertext received : {ct_hash[:32]}...")
    print(f"[INFER] Performing HE inference — server sees no plaintext.")

    # --- Step 4: HE dot product ---
    encrypted_logit    = he_dot_product(ct, MODEL_WEIGHTS, MODEL_INTERCEPT)
    encrypted_logit_bytes = serialize_ciphertext(encrypted_logit)
    logit_hash         = hash_data(encrypted_logit_bytes)

    print(f"[INFER] Encrypted logit produced : {logit_hash[:32]}...")

    # --- Step 5: AI server signs its response ---
    ai_response_manifest = {
        "patient_id"      : patient_id,
        "input_hash"      : ct_hash,
        "output_hash"     : logit_hash,
        "model_version"   : "LR-MentalBERT-v1.0",
        "timestamp"       : datetime.datetime.now().isoformat()
    }
    ai_manifest_bytes = json.dumps(
        ai_response_manifest, sort_keys=True
    ).encode()
    ai_signature = sign_data(ai_manifest_bytes, AI_SK)

    print(f"[INFER] AI server signed response.")

    # --- Step 6: Forward to Key Authority ---
    print(f"[INFER] Forwarding to Key Authority...")

    authority_payload = {
        "patient_id"         : patient_id,
        "ciphertext_hash"    : ct_hash,
        "encrypted_logit"    : base64.b64encode(
            encrypted_logit_bytes
        ).decode(),
        "logit_hash"         : logit_hash,
        "ai_manifest"        : base64.b64encode(
            ai_manifest_bytes
        ).decode(),
        "ai_signature"       : ai_signature.hex(),
        "ai_vk"              : vk_to_hex(AI_VK),
        "patient_manifest"   : manifest_b64,
        "patient_signature"  : patient_sig_hex,
        "patient_vk"         : registered_patients[patient_id]["vk_hex"],
        "public_context"     : ctx_b64
    }

    try:
        auth_response = requests.post(
            f"{AUTHORITY_SERVER_URL}/log_and_sign",
            json=authority_payload,
            timeout=30
        )
        auth_data = auth_response.json()
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": "Key Authority unreachable."
        }), 503

    if auth_response.status_code != 200:
        return jsonify({
            "error"  : "Key Authority rejected the request.",
            "details": auth_data
        }), 502

    print(f"[INFER] Key Authority countersigned. Returning to client.")

    return jsonify({
        "status"              : "success",
        "encrypted_logit"     : base64.b64encode(
            encrypted_logit_bytes
        ).decode(),
        "logit_hash"          : logit_hash,
        "ai_manifest"         : base64.b64encode(
            ai_manifest_bytes
        ).decode(),
        "ai_signature"        : ai_signature.hex(),
        "authority_manifest"  : auth_data.get("authority_manifest"),
        "authority_signature" : auth_data.get("authority_signature"),
        "authority_vk"        : auth_data.get("authority_vk"),
        "merkle_root"         : auth_data.get("merkle_root")
    })


if __name__ == "__main__":
    print(f"\nStarting AI Compute Server on port {AI_SERVER_PORT}...")
    print(f"  Model       : LR-MentalBERT-v1.0")
    print(f"  Weights dim : {MODEL_WEIGHTS.shape}")
    print(f"  Trust level : UNTRUSTED — never sees plaintext\n")
    app.run(host="0.0.0.0", port=AI_SERVER_PORT, debug=False)