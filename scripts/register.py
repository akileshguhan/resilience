# scripts/register.py
# One-time patient registration script.
# Generates CKKS keys, splits the secret via Shamir,
# registers with both the AI server and Key Authority.
# Saves patient state to client/state.json.

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import hashlib
import base64
import requests

from config import (
    AI_SERVER_URL,
    AUTHORITY_SERVER_URL,
    CLIENT_STATE_FILE,
    CLIENT_DIR,
    PATIENT_ID
)
from crypto.he import (
    create_context,
    serialize_context
)
from crypto.shamir import (
    split_secret,
    shares_to_json
)
from crypto.signatures import (
    generate_keypair,
    sign_data,
    sk_to_hex,
    vk_to_hex
)


def register():
    print("=" * 60)
    print("RESILIENCE — PATIENT REGISTRATION")
    print("=" * 60)
    print()

    # --- Step 1: Check servers are online ---
    print("Step 1 — Checking servers are online...")
    for name, url in [
        ("AI Server",      AI_SERVER_URL),
        ("Key Authority",  AUTHORITY_SERVER_URL)
    ]:
        try:
            r = requests.get(f"{url}/health", timeout=5)
            status = r.json().get("status", "unknown")
            print(f"  {name:<20} : {status}")
        except requests.exceptions.ConnectionError:
            print(f"  {name:<20} : OFFLINE")
            print(f"\n  ERROR: {name} is not running.")
            print(f"  Start it with: python ai_server/server.py")
            sys.exit(1)
    print()

    # --- Step 2: Generate CKKS key pair ---
    print("Step 2 — Generating CKKS key pair on device...")
    ctx = create_context()

    # Serialize full context (with secret key) for local storage
    full_ctx_bytes   = serialize_context(ctx, save_secret_key=True)

    # Serialize public context (without secret key) for servers
    public_ctx_bytes = serialize_context(ctx, save_secret_key=False)
    public_ctx_b64   = base64.b64encode(public_ctx_bytes).decode()

    print(f"  Full context size   : {len(full_ctx_bytes) / 1024:.2f} KB")
    print(f"  Public context size : {len(public_ctx_bytes) / 1024:.2f} KB")
    print()

    # --- Step 3: Derive shareable secret and split ---
    print("Step 3 — Splitting private key via Shamir (2-of-3)...")
    ctx_hash    = hashlib.sha256(full_ctx_bytes).digest()

    from config import SHAMIR_PRIME
    ckks_secret = int.from_bytes(ctx_hash, byteorder='big') % SHAMIR_PRIME

    shares      = split_secret(ckks_secret, n=3, k=2)
    share_1     = shares[0]   # Patient device
    share_2     = shares[1]   # Key Authority
    share_3     = shares[2]   # Third-party escrow

    print(f"  Share 1 (device)    : x={share_1[0]}, y={hex(share_1[1])[:12]}...")
    print(f"  Share 2 (authority) : x={share_2[0]}, y={hex(share_2[1])[:12]}...")
    print(f"  Share 3 (escrow)    : x={share_3[0]}, y={hex(share_3[1])[:12]}...")
    print()

    # --- Step 4: Generate ECDSA key pair ---
    print("Step 4 — Generating ECDSA signing key pair...")
    patient_sk, patient_vk = generate_keypair()
    print(f"  Public key          : {vk_to_hex(patient_vk)[:32]}...")
    print()

    # --- Step 5: Register with AI server ---
    print("Step 5 — Registering with AI server...")
    ai_payload = {
        "patient_id"     : PATIENT_ID,
        "patient_vk"     : vk_to_hex(patient_vk),
        "public_context" : public_ctx_b64
    }
    ai_response = requests.post(
        f"{AI_SERVER_URL}/register",
        json=ai_payload,
        timeout=30
    )
    if ai_response.status_code != 200:
        print(f"  ERROR: AI server registration failed.")
        print(f"  {ai_response.json()}")
        sys.exit(1)

    ai_data  = ai_response.json()
    ai_vk_hex = ai_data.get("ai_vk")
    print(f"  AI server status    : {ai_data.get('status')}")
    print(f"  AI server pubkey    : {ai_vk_hex[:32]}...")
    print()

    # --- Step 6: Register with Key Authority ---
    print("Step 6 — Registering with Key Authority...")

    # Patient signs registration manifest
    reg_manifest = {
        "patient_id" : PATIENT_ID,
        "patient_vk" : vk_to_hex(patient_vk),
        "action"     : "REGISTER"
    }
    reg_manifest_bytes = json.dumps(
        reg_manifest, sort_keys=True
    ).encode()
    reg_sig = sign_data(reg_manifest_bytes, patient_sk)

    authority_payload = {
        "patient_id"             : PATIENT_ID,
        "patient_vk"             : vk_to_hex(patient_vk),
        "share_2"                : shares_to_json([share_2])[0],
        "share_3"                : shares_to_json([share_3])[0],
        "registration_manifest"  : base64.b64encode(
            reg_manifest_bytes
        ).decode(),
        "registration_signature" : reg_sig.hex()
    }
    auth_response = requests.post(
        f"{AUTHORITY_SERVER_URL}/register",
        json=authority_payload,
        timeout=30
    )
    if auth_response.status_code != 200:
        print(f"  ERROR: Key Authority registration failed.")
        print(f"  {auth_response.json()}")
        sys.exit(1)

    auth_data     = auth_response.json()
    authority_vk_hex = auth_data.get("authority_vk")
    genesis_root  = auth_data.get("merkle_root")

    print(f"  Authority status    : {auth_data.get('status')}")
    print(f"  Authority pubkey    : {authority_vk_hex[:32]}...")
    print(f"  Genesis Merkle root : {genesis_root[:32]}...")
    print()

    # --- Step 7: Save patient state to disk ---
    print("Step 7 — Saving patient state to disk...")

    os.makedirs(CLIENT_DIR, exist_ok=True)

    state = {
        "patient_id"       : PATIENT_ID,
        "full_context_b64" : base64.b64encode(full_ctx_bytes).decode(),
        "public_context_b64": public_ctx_b64,
        "patient_sk_hex"   : sk_to_hex(patient_sk),
        "patient_vk_hex"   : vk_to_hex(patient_vk),
        "ai_vk_hex"        : ai_vk_hex,
        "authority_vk_hex" : authority_vk_hex,
        "share_1"          : shares_to_json([share_1])[0],
        "ckks_secret"      : str(ckks_secret),
        "score_history"    : [],
        "day_counter"      : 0,
        "genesis_root"     : genesis_root
    }

    with open(CLIENT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

    print(f"  State saved to      : {CLIENT_STATE_FILE}")
    print()
    print("=" * 60)
    print("REGISTRATION COMPLETE")
    print("=" * 60)
    print()
    print(f"  Patient ID          : {PATIENT_ID}")
    print(f"  CKKS keys           : Generated and split")
    print(f"  Shares distributed  : Device / Authority / Escrow")
    print(f"  Genesis Merkle root : {genesis_root[:32]}...")
    print()
    print("  You can now run the patient client:")
    print("  python client/client.py")


if __name__ == "__main__":
    register()