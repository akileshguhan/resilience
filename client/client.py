# client/client.py
# Patient-facing terminal CLI.
# Handles journal entry, local embedding, encryption,
# signing, submission, decryption, and risk display.

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import hashlib
import base64
import datetime
import numpy as np
import requests
from transformers import AutoTokenizer, AutoModel
import torch

from config import (
    AI_SERVER_URL,
    AUTHORITY_SERVER_URL,
    CLIENT_STATE_FILE,
    PATIENT_ID,
    DISTILBERT_MODEL,
    RISK_LOW_THRESHOLD,
    RISK_ELEVATED_THRESHOLD,
    ROLLING_WINDOW_DAYS
)
from crypto.he import (
    deserialize_context,
    encrypt_vector,
    serialize_ciphertext,
    deserialize_ciphertext,
    decrypt_vector
)
from crypto.signatures import (
    sign_data,
    verify_signature,
    sk_from_hex,
    vk_from_hex
)


# --- Globals ---
tokenizer   = None
bert_model  = None
device      = torch.device("cpu")


def sigmoid(x):
    return 1 / (1 + np.exp(-x))


def load_state() -> dict:
    """Load patient state from disk."""
    if not os.path.exists(CLIENT_STATE_FILE):
        print("ERROR: No patient state found.")
        print("Run registration first: python scripts/register.py")
        sys.exit(1)
    with open(CLIENT_STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state: dict):
    """Save patient state to disk."""
    with open(CLIENT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def load_embedding_model():
    """Load DistilBERT tokenizer and model."""
    global tokenizer, bert_model
    if tokenizer is not None:
        return
    print("Loading DistilBERT embedding model...")
    print("(This takes a moment on first run.)")
    tokenizer  = AutoTokenizer.from_pretrained(DISTILBERT_MODEL)
    bert_model = AutoModel.from_pretrained(DISTILBERT_MODEL)
    bert_model.eval()
    print("Model loaded.\n")


def embed_text(text: str) -> np.ndarray:
    """
    Convert journal text to a 768-dim embedding
    using DistilBERT CLS token extraction.
    Runs entirely on the patient device.
    """
    load_embedding_model()
    encoded = tokenizer(
        text,
        padding=True,
        truncation=True,
        max_length=512,
        return_tensors="pt"
    )
    with torch.no_grad():
        output = bert_model(**encoded)
    embedding = output.last_hidden_state[:, 0, :].squeeze().numpy()
    return embedding.astype(np.float64)


def check_servers():
    """Verify both servers are online before submission."""
    all_online = True
    for name, url in [
        ("AI Server",     AI_SERVER_URL),
        ("Key Authority", AUTHORITY_SERVER_URL)
    ]:
        try:
            r = requests.get(f"{url}/health", timeout=5)
            status = r.json().get("status", "unknown")
            if status != "online":
                print(f"  {name} : DEGRADED")
                all_online = False
            else:
                print(f"  {name} : online")
        except requests.exceptions.ConnectionError:
            print(f"  {name} : OFFLINE")
            all_online = False
    return all_online


def display_risk_score(score: float, history: list):
    """Display the risk score and rolling average."""
    def bar(s, width=30):
        filled = int(s * width)
        return "[" + "█" * filled + "░" * (width - filled) + "]"

    def label(s):
        if s >= RISK_ELEVATED_THRESHOLD:
            return "ELEVATED  ⚠"
        elif s >= RISK_LOW_THRESHOLD:
            return "MODERATE  ~"
        else:
            return "LOW       ✓"

    rolling = np.mean(history[-ROLLING_WINDOW_DAYS:]) if history else score

    print()
    print("  ┌─────────────────────────────────────┐")
    print("  │         RESILIENCE RISK REPORT      │")
    print("  ├─────────────────────────────────────┤")
    print(f"  │  Today's score  : {score:.4f}              │")
    print(f"  │  {bar(score)}  │")
    print(f"  │  Status         : {label(score):<18}│")
    print(f"  ├─────────────────────────────────────┤")
    print(f"  │  {ROLLING_WINDOW_DAYS}-day average  : {rolling:.4f}              │")
    print(f"  │  {bar(rolling)}  │")
    print(f"  │  Trend          : {label(rolling):<18}│")
    print(f"  ├─────────────────────────────────────┤")
    print(f"  │  History ({len(history)} day{'s' if len(history) != 1 else ' '}):                   │")
    for i, s in enumerate(history[-7:], 1):
        day_label = f"Day {len(history) - len(history[-7:]) + i}"
        print(f"  │    {day_label:<8} {bar(s, width=18)} {s:.3f}  │")
    print("  └─────────────────────────────────────┘")
    print()

    if rolling >= RISK_ELEVATED_THRESHOLD:
        print("  ⚠  ELEVATED RISK DETECTED")
        print("     Please contact your care team or call a helpline.")
        print("     Your clinician has been notified via audit log.")
    elif rolling >= RISK_LOW_THRESHOLD:
        print("  ~  MODERATE RISK — Continue monitoring.")
        print("     Consider reaching out to your support network.")
    else:
        print("  ✓  Risk within acceptable range.")
        print("     Keep journaling. You are doing well.")
    print()


def submit_journal_entry(state: dict) -> dict:
    """
    Full daily submission pipeline:
    journal text → embedding → encryption → signing
    → AI server → Key Authority → decryption → display
    """
    print()
    print("─" * 50)
    print("  DAILY JOURNAL SUBMISSION")
    print("─" * 50)
    print()
    print("  Write your journal entry below.")
    print("  Your text never leaves this device.")
    print("  Press Enter twice when done.")
    print()

    lines = []
    while True:
        line = input()
        if line == "" and lines and lines[-1] == "":
            break
        lines.append(line)
    journal_text = "\n".join(lines).strip()

    if not journal_text:
        print("  No text entered. Submission cancelled.")
        return state

    print()
    print("  Processing...")

    # --- Step 1: Embed on device ---
    print("  [1/6] Generating embedding on device...")
    embedding = embed_text(journal_text)
    print(f"        Embedding shape : {embedding.shape}")

    # --- Step 2: Load CKKS context and encrypt ---
    print("  [2/6] Encrypting vector...")
    ctx_bytes = base64.b64decode(state["full_context_b64"])
    ctx       = deserialize_context(ctx_bytes)
    ct        = encrypt_vector(ctx, embedding)
    ct_bytes  = serialize_ciphertext(ct)
    ct_hash   = hashlib.sha256(ct_bytes).hexdigest()
    print(f"        Ciphertext size : {len(ct_bytes) / 1024:.1f} KB")
    print(f"        Ciphertext hash : {ct_hash[:32]}...")

    # --- Step 3: Sign submission manifest ---
    print("  [3/6] Signing submission...")
    state["day_counter"] += 1
    manifest = {
        "patient_id"     : state["patient_id"],
        "day"            : state["day_counter"],
        "timestamp"      : datetime.datetime.now().isoformat(),
        "ciphertext_hash": ct_hash
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    patient_sk     = sk_from_hex(state["patient_sk_hex"])
    patient_sig    = sign_data(manifest_bytes, patient_sk)
    print(f"        Signature       : {patient_sig.hex()[:32]}...")

    # --- Step 4: Submit to AI server ---
    print("  [4/6] Submitting to AI server...")
    public_ctx_b64 = state["public_context_b64"]

    payload = {
        "patient_id"       : state["patient_id"],
        "ciphertext"       : base64.b64encode(ct_bytes).decode(),
        "manifest"         : base64.b64encode(manifest_bytes).decode(),
        "patient_signature": patient_sig.hex(),
        "public_context"   : public_ctx_b64
    }

    try:
        response = requests.post(
            f"{AI_SERVER_URL}/infer",
            json=payload,
            timeout=60
        )
    except requests.exceptions.ConnectionError:
        print("  ERROR: AI server unreachable.")
        return state

    if response.status_code != 200:
        print(f"  ERROR: Inference failed.")
        print(f"  {response.json()}")
        return state

    result = response.json()
    print(f"        AI server       : inference complete")
    print(f"        Merkle root     : {result.get('merkle_root', '')[:32]}...")

    # --- Step 5: Verify authority countersignature ---
    print("  [5/6] Verifying Key Authority countersignature...")
    authority_vk      = vk_from_hex(state["authority_vk_hex"])
    auth_manifest_b64 = result.get("authority_manifest")
    auth_sig_hex      = result.get("authority_signature")

    if not auth_manifest_b64 or not auth_sig_hex:
        print("  ERROR: Missing authority countersignature.")
        return state

    auth_manifest_bytes = base64.b64decode(auth_manifest_b64)
    auth_sig            = bytes.fromhex(auth_sig_hex)

    if not verify_signature(auth_manifest_bytes, auth_sig, authority_vk):
        print("  ERROR: Authority countersignature invalid. Aborting.")
        return state

    print("        Countersignature : VERIFIED")

    # --- Step 6: Decrypt and display ---
    print("  [6/6] Decrypting result on device...")
    encrypted_logit_bytes = base64.b64decode(result["encrypted_logit"])
    encrypted_logit       = deserialize_ciphertext(
        ctx, encrypted_logit_bytes
    )
    decrypted_logit = decrypt_vector(encrypted_logit)[0]
    risk_score      = sigmoid(decrypted_logit)

    print(f"        Decrypted logit : {decrypted_logit:.6f}")
    print(f"        Risk score      : {risk_score:.6f}")

    # Store score and save state
    state["score_history"].append(risk_score)
    save_state(state)

    # Display report
    display_risk_score(risk_score, state["score_history"])

    return state


def view_audit_log():
    """Fetch and display the audit log from the Key Authority."""
    print()
    print("─" * 50)
    print("  AUDIT LOG")
    print("─" * 50)
    try:
        r = requests.get(
            f"{AUTHORITY_SERVER_URL}/audit", timeout=10
        )
        data   = r.json()
        events = data.get("events", [])
        print(f"\n  Merkle root  : {data.get('merkle_root', 'N/A')[:32]}...")
        print(f"  Total events : {data.get('event_count', 0)}")
        print()
        for i, event in enumerate(events):
            print(f"  [{i+1:02d}] {event.get('event_type', 'UNKNOWN'):<25} "
                  f"| {event.get('timestamp', '')[:19]}")
        print()
    except requests.exceptions.ConnectionError:
        print("  Key Authority offline — cannot retrieve audit log.")


def main():
    """Main patient CLI loop."""
    print()
    print("=" * 50)
    print("  RESILIENCE — Mental Health Monitor")
    print("  Privacy-Preserving Psychiatric Care")
    print("=" * 50)
    print()

    # Load patient state
    state = load_state()
    print(f"  Welcome, {state['patient_id']}")
    print(f"  Submissions logged : {state['day_counter']}")
    if state["score_history"]:
        last = state["score_history"][-1]
        print(f"  Last risk score    : {last:.4f}")
    print()

    while True:
        print("  What would you like to do?")
        print("  [1] Submit today's journal entry")
        print("  [2] View risk history")
        print("  [3] View audit log")
        print("  [4] Check server status")
        print("  [5] Exit")
        print()

        choice = input("  Enter choice: ").strip()
        print()

        if choice == "1":
            # Check servers first
            print("  Checking servers...")
            if not check_servers():
                print()
                print("  One or more servers are offline.")
                print("  Please start all servers before submitting.")
            else:
                state = submit_journal_entry(state)

        elif choice == "2":
            if not state["score_history"]:
                print("  No submissions yet.")
            else:
                display_risk_score(
                    state["score_history"][-1],
                    state["score_history"]
                )

        elif choice == "3":
            view_audit_log()

        elif choice == "4":
            print("  Server Status:")
            check_servers()
            print()

        elif choice == "5":
            print("  Goodbye. Stay well.")
            print()
            sys.exit(0)

        else:
            print("  Invalid choice. Please enter 1-5.")
            print()


if __name__ == "__main__":
    main()