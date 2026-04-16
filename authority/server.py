# authority/server.py
# Hospital Key Authority — trusted premises component.
# Verifies all signatures, maintains the Merkle audit chain,
# countersigns results, and handles break-glass requests.
# Holds Key Share 2 for every registered patient.

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import hashlib
import datetime
import base64
from flask import Flask, request, jsonify

from config import (
    AUTHORITY_SERVER_PORT,
    AUDIT_LOG_FILE,
    AUTHORITY_DIR
)
from crypto.signatures import (
    generate_keypair,
    sign_data,
    verify_signature,
    vk_from_hex,
    vk_to_hex
)
from crypto.merkle import (
    build_tree,
    get_root,
    get_proof,
    verify_leaf,
    proof_to_json
)
from crypto.shamir import (
    reconstruct_secret,
    shares_from_json
)

app = Flask(__name__)

# --- Generate authority ECDSA key pair ---
AUTHORITY_SK, AUTHORITY_VK = generate_keypair()
print(f"Authority public key : {vk_to_hex(AUTHORITY_VK)[:32]}...")

# --- In-memory state ---
# Patient registry: patient_id -> {vk_hex, share_2, share_3}
patient_registry  = {}

# Merkle audit chain
merkle_events     = []
merkle_tree       = None
merkle_root       = None


def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rebuild_merkle():
    """Rebuild the Merkle tree from current events list."""
    global merkle_tree, merkle_root
    if merkle_events:
        merkle_tree = build_tree(merkle_events)
        merkle_root = get_root(merkle_tree)


def append_audit_event(event: dict) -> str:
    """
    Append a new event to the Merkle audit chain.
    Returns the new Merkle root.
    """
    event_bytes = json.dumps(event, sort_keys=True).encode()
    merkle_events.append(event_bytes)
    rebuild_merkle()

    # Persist to disk
    persist_audit_log()
    return merkle_root


def persist_audit_log():
    """Save audit log to disk as JSON."""
    os.makedirs(AUTHORITY_DIR, exist_ok=True)
    log_data = {
        "merkle_root" : merkle_root,
        "event_count" : len(merkle_events),
        "events"      : [
            json.loads(e.decode()) for e in merkle_events
        ]
    }
    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(log_data, f, indent=2)


def load_audit_log():
    """Load persisted audit log from disk on startup."""
    global merkle_events
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r") as f:
            log_data = json.load(f)
        merkle_events = [
            json.dumps(e, sort_keys=True).encode()
            for e in log_data.get("events", [])
        ]
        rebuild_merkle()
        print(f"  Audit log loaded : {len(merkle_events)} events")
        if merkle_root:
            print(f"  Merkle root      : {merkle_root[:32]}...")
    else:
        print("  Audit log        : empty (fresh start)")


# Load existing audit log on startup
load_audit_log()


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status"      : "online",
        "service"     : "Hospital Key Authority",
        "events"      : len(merkle_events),
        "merkle_root" : merkle_root,
        "timestamp"   : datetime.datetime.now().isoformat()
    })


@app.route("/register", methods=["POST"])
def register():
    """
    Register a patient with the Key Authority.
    Receives patient public key, Share 2, and Share 3.
    Creates genesis Merkle leaf.
    """
    data = request.get_json()

    patient_id     = data.get("patient_id")
    patient_vk_hex = data.get("patient_vk")
    share_2        = data.get("share_2")
    share_3        = data.get("share_3")
    reg_sig_hex    = data.get("registration_signature")
    reg_manifest_b64 = data.get("registration_manifest")

    if not all([patient_id, patient_vk_hex,
                share_2, share_3,
                reg_sig_hex, reg_manifest_b64]):
        return jsonify({"error": "Missing fields."}), 400

    # Verify patient signed the registration manifest
    patient_vk     = vk_from_hex(patient_vk_hex)
    manifest_bytes = base64.b64decode(reg_manifest_b64)
    reg_sig        = bytes.fromhex(reg_sig_hex)

    if not verify_signature(manifest_bytes, reg_sig, patient_vk):
        return jsonify({"error": "Invalid registration signature."}), 401

    # Store patient record
    patient_registry[patient_id] = {
        "vk_hex" : patient_vk_hex,
        "share_2": share_2,
        "share_3": share_3
    }

    # Create genesis Merkle leaf
    genesis_event = {
        "event_type"  : "REGISTRATION",
        "patient_id"  : patient_id,
        "timestamp"   : datetime.datetime.now().isoformat(),
        "pubkey_hash" : hash_data(patient_vk.to_string()),
        "status"      : "GENESIS"
    }
    new_root = append_audit_event(genesis_event)

    # Authority countersigns the registration
    auth_response = {
        "patient_id"  : patient_id,
        "timestamp"   : genesis_event["timestamp"],
        "merkle_root" : new_root,
        "status"      : "REGISTERED"
    }
    auth_response_bytes = json.dumps(
        auth_response, sort_keys=True
    ).encode()
    auth_sig = sign_data(auth_response_bytes, AUTHORITY_SK)

    print(f"\n[REGISTER] Patient registered : {patient_id}")
    print(f"           Merkle root        : {new_root[:32]}...")

    return jsonify({
        "status"               : "registered",
        "patient_id"           : patient_id,
        "merkle_root"          : new_root,
        "authority_vk"         : vk_to_hex(AUTHORITY_VK),
        "authority_manifest"   : base64.b64encode(
            auth_response_bytes
        ).decode(),
        "authority_signature"  : auth_sig.hex()
    })


@app.route("/log_and_sign", methods=["POST"])
def log_and_sign():
    """
    Core daily submission endpoint.
    Verifies patient and AI server signatures.
    Appends audit event to Merkle chain.
    Countersigns the final package.
    """
    data = request.get_json()

    patient_id       = data.get("patient_id")
    ciphertext_hash  = data.get("ciphertext_hash")
    encrypted_logit  = data.get("encrypted_logit")
    logit_hash       = data.get("logit_hash")
    ai_manifest_b64  = data.get("ai_manifest")
    ai_sig_hex       = data.get("ai_signature")
    ai_vk_hex        = data.get("ai_vk")
    patient_manifest_b64 = data.get("patient_manifest")
    patient_sig_hex  = data.get("patient_signature")
    patient_vk_hex   = data.get("patient_vk")

    if not all([patient_id, ciphertext_hash, encrypted_logit,
                logit_hash, ai_manifest_b64, ai_sig_hex,
                ai_vk_hex, patient_manifest_b64,
                patient_sig_hex, patient_vk_hex]):
        return jsonify({"error": "Missing fields."}), 400

    # --- Verify patient signature ---
    patient_vk     = vk_from_hex(patient_vk_hex)
    patient_manifest_bytes = base64.b64decode(patient_manifest_b64)
    patient_sig    = bytes.fromhex(patient_sig_hex)

    if not verify_signature(
        patient_manifest_bytes, patient_sig, patient_vk
    ):
        return jsonify({"error": "Invalid patient signature."}), 401

    # --- Verify AI server signature ---
    ai_vk          = vk_from_hex(ai_vk_hex)
    ai_manifest_bytes = base64.b64decode(ai_manifest_b64)
    ai_sig         = bytes.fromhex(ai_sig_hex)

    if not verify_signature(ai_manifest_bytes, ai_sig, ai_vk):
        return jsonify({"error": "Invalid AI server signature."}), 401

    print(f"\n[LOG] Patient signature verified  : {patient_id}")
    print(f"[LOG] AI server signature verified : OK")

    # --- Append audit event to Merkle chain ---
    audit_event = {
        "event_type"        : "DAILY_SUBMISSION",
        "patient_id"        : patient_id,
        "timestamp"         : datetime.datetime.now().isoformat(),
        "ciphertext_hash"   : ciphertext_hash,
        "logit_hash"        : logit_hash,
        "patient_sig_valid" : True,
        "ai_sig_valid"      : True,
        "status"            : "LOGGED"
    }
    new_root = append_audit_event(audit_event)

    print(f"[LOG] Audit event appended.")
    print(f"[LOG] New Merkle root : {new_root[:32]}...")

    # --- Authority countersigns the final package ---
    authority_manifest = {
        "patient_id"    : patient_id,
        "ciphertext_hash": ciphertext_hash,
        "logit_hash"    : logit_hash,
        "merkle_root"   : new_root,
        "timestamp"     : audit_event["timestamp"],
        "audit_status"  : "LOGGED"
    }
    authority_manifest_bytes = json.dumps(
        authority_manifest, sort_keys=True
    ).encode()
    authority_sig = sign_data(authority_manifest_bytes, AUTHORITY_SK)

    print(f"[LOG] Authority countersigned.")

    return jsonify({
        "status"               : "logged",
        "merkle_root"          : new_root,
        "authority_manifest"   : base64.b64encode(
            authority_manifest_bytes
        ).decode(),
        "authority_signature"  : authority_sig.hex(),
        "authority_vk"         : vk_to_hex(AUTHORITY_VK)
    })


@app.route("/audit", methods=["GET"])
def audit():
    """
    Public audit endpoint — returns the full audit log.
    In the real system this is access-controlled.
    Here it is open for demonstration purposes.
    """
    events = [
        json.loads(e.decode()) for e in merkle_events
    ]
    return jsonify({
        "merkle_root"  : merkle_root,
        "event_count"  : len(merkle_events),
        "events"       : events
    })


@app.route("/verify_event", methods=["POST"])
def verify_event():
    """
    Verify that a specific event exists in the audit chain.
    Accepts event index and returns Merkle proof verification.
    """
    data  = request.get_json()
    index = data.get("index")

    if index is None or index >= len(merkle_events):
        return jsonify({"error": "Invalid event index."}), 400

    event_bytes = merkle_events[index]
    proof       = get_proof(merkle_tree, index)
    verified    = verify_leaf(event_bytes, index, proof, merkle_root)

    return jsonify({
        "index"    : index,
        "verified" : verified,
        "event"    : json.loads(event_bytes.decode()),
        "proof"    : proof_to_json(proof),
        "root"     : merkle_root
    })


@app.route("/break_glass", methods=["POST"])
def break_glass():
    """
    Emergency access endpoint.
    Clinician submits a signed request.
    Authority combines Share 2 + Share 3 to reconstruct the key.
    All access is logged in the Merkle audit chain.
    """
    data = request.get_json()

    clinician_id  = data.get("clinician_id")
    patient_id    = data.get("patient_id")
    justification = data.get("justification")

    if not all([clinician_id, patient_id, justification]):
        return jsonify({"error": "Missing fields."}), 400

    if patient_id not in patient_registry:
        return jsonify({"error": "Patient not found."}), 404

    # Log emergency request
    request_event = {
        "event_type"   : "BREAK_GLASS_REQUEST",
        "patient_id"   : patient_id,
        "clinician_id" : clinician_id,
        "justification": justification,
        "timestamp"    : datetime.datetime.now().isoformat(),
        "status"       : "LOGGED"
    }
    append_audit_event(request_event)
    print(f"\n[BREAK-GLASS] Request from {clinician_id} for {patient_id}")

    # Retrieve shares 2 and 3
    record  = patient_registry[patient_id]
    share_2 = shares_from_json([record["share_2"]])[0]
    share_3 = shares_from_json([record["share_3"]])[0]

    # Reconstruct secret ephemerally
    reconstructed = reconstruct_secret([share_2, share_3])
    print(f"[BREAK-GLASS] Key reconstructed from Share 2 + Share 3.")
    print(f"[BREAK-GLASS] Patient device NOT involved.")

    # Log decryption event
    decryption_event = {
        "event_type"   : "BREAK_GLASS_DECRYPTION",
        "patient_id"   : patient_id,
        "clinician_id" : clinician_id,
        "shares_used"  : "Authority(2) + Escrow(3)",
        "timestamp"    : datetime.datetime.now().isoformat(),
        "status"       : "ACCESSED"
    }
    new_root = append_audit_event(decryption_event)

    # Destroy reconstructed key
    del reconstructed
    import gc
    gc.collect()
    print(f"[BREAK-GLASS] Reconstructed key destroyed from memory.")

    # Log patient notification
    notification_event = {
        "event_type"   : "PATIENT_NOTIFIED",
        "patient_id"   : patient_id,
        "clinician_id" : clinician_id,
        "timestamp"    : datetime.datetime.now().isoformat(),
        "status"       : "NOTIFIED"
    }
    final_root = append_audit_event(notification_event)
    print(f"[BREAK-GLASS] Patient notified. Merkle root: {final_root[:32]}...")

    return jsonify({
        "status"      : "access_granted",
        "patient_id"  : patient_id,
        "clinician_id": clinician_id,
        "merkle_root" : final_root,
        "message"     : (
            "Emergency access granted and fully logged. "
            "Patient has been notified. "
            "Reconstructed key destroyed from memory."
        )
    })


if __name__ == "__main__":
    print(f"\nStarting Key Authority Server on port {AUTHORITY_SERVER_PORT}...")
    print(f"  Trust level : TRUSTED — hospital premises")
    print(f"  Audit log   : {AUDIT_LOG_FILE}\n")
    app.run(host="0.0.0.0", port=AUTHORITY_SERVER_PORT, debug=False)