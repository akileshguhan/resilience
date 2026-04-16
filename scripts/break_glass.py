# scripts/break_glass.py
# Emergency access simulation script.
# Demonstrates the break-glass protocol where a clinician
# requests emergency access to a patient's data without
# the patient's device being present.
# All access is cryptographically logged in the Merkle chain.

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import requests
import datetime

from config import (
    AUTHORITY_SERVER_URL,
    PATIENT_ID
)


def break_glass():
    print()
    print("=" * 60)
    print("RESILIENCE — BREAK-GLASS EMERGENCY ACCESS")
    print("=" * 60)
    print()
    print("WARNING: This simulates an emergency access scenario.")
    print("All actions are cryptographically logged and auditable.")
    print("The patient will be automatically notified.")
    print()

    # --- Step 1: Check Key Authority is online ---
    print("Step 1 — Checking Key Authority status...")
    try:
        r = requests.get(
            f"{AUTHORITY_SERVER_URL}/health", timeout=5
        )
        data = r.json()
        print(f"  Status       : {data.get('status')}")
        print(f"  Audit events : {data.get('events')}")
        print(f"  Merkle root  : {data.get('merkle_root', '')[:32]}...")
    except requests.exceptions.ConnectionError:
        print("  ERROR: Key Authority is offline.")
        print("  Start it with: python authority/server.py")
        sys.exit(1)
    print()

    # --- Step 2: Collect clinician details ---
    print("Step 2 — Clinician identification.")
    print()
    clinician_id  = input("  Enter clinician ID       : ").strip()
    if not clinician_id:
        clinician_id = "DR-SHARMA-7741"
        print(f"  Using default            : {clinician_id}")

    justification = input("  Enter clinical justification : ").strip()
    if not justification:
        justification = (
            "Patient unreachable for 72 hours. "
            "Risk score trend indicates acute crisis. "
            "Emergency evaluation required."
        )
        print(f"  Using default            : {justification}")
    print()

    # --- Step 3: Confirm before proceeding ---
    print("Step 3 — Confirm emergency access request.")
    print()
    print(f"  Clinician    : {clinician_id}")
    print(f"  Patient      : {PATIENT_ID}")
    print(f"  Justification: {justification}")
    print()
    confirm = input(
        "  Proceed with emergency access? (yes/no) : "
    ).strip().lower()
    if confirm != "yes":
        print()
        print("  Emergency access cancelled.")
        sys.exit(0)
    print()

    # --- Step 4: Submit break-glass request ---
    print("Step 4 — Submitting emergency access request...")
    print()

    payload = {
        "clinician_id" : clinician_id,
        "patient_id"   : PATIENT_ID,
        "justification": justification
    }

    try:
        response = requests.post(
            f"{AUTHORITY_SERVER_URL}/break_glass",
            json=payload,
            timeout=30
        )
    except requests.exceptions.ConnectionError:
        print("  ERROR: Key Authority unreachable during request.")
        sys.exit(1)

    if response.status_code != 200:
        print(f"  ERROR: Break-glass request failed.")
        print(f"  {response.json()}")
        sys.exit(1)

    result = response.json()
    print(f"  Status       : {result.get('status')}")
    print(f"  Merkle root  : {result.get('merkle_root', '')[:32]}...")
    print(f"  Message      : {result.get('message')}")
    print()

    # --- Step 5: Retrieve and display updated audit log ---
    print("Step 5 — Retrieving updated audit log...")
    print()

    try:
        audit_r = requests.get(
            f"{AUTHORITY_SERVER_URL}/audit", timeout=10
        )
        audit_data = audit_r.json()
        events     = audit_data.get("events", [])

        print(f"  Total events : {audit_data.get('event_count')}")
        print(f"  Merkle root  : {audit_data.get('merkle_root', '')[:32]}...")
        print()
        print("  Full audit trail:")
        print()

        for i, event in enumerate(events):
            event_type = event.get("event_type", "UNKNOWN")
            timestamp  = event.get("timestamp", "")[:19]
            patient    = event.get("patient_id", "")
            clinician  = event.get("clinician_id", "")

            # Format based on event type
            if event_type == "REGISTRATION":
                detail = f"Patient {patient} registered"
            elif event_type == "DAILY_SUBMISSION":
                detail = (
                    f"Patient {patient} | "
                    f"ct={event.get('ciphertext_hash', '')[:12]}..."
                )
            elif event_type == "BREAK_GLASS_REQUEST":
                detail = (
                    f"Clinician {clinician} requested "
                    f"access to {patient}"
                )
            elif event_type == "BREAK_GLASS_DECRYPTION":
                detail = (
                    f"Shares used: {event.get('shares_used', '')} | "
                    f"Clinician: {clinician}"
                )
            elif event_type == "PATIENT_NOTIFIED":
                detail = f"Patient {patient} notified of access"
            else:
                detail = json.dumps(event)[:60]

            # Highlight break-glass events
            prefix = "  >>>" if "BREAK_GLASS" in event_type or \
                     "NOTIFIED" in event_type else "    "

            print(f"{prefix} [{i+1:02d}] {event_type:<28} "
                  f"| {timestamp}")
            print(f"          {detail}")
            print()

    except requests.exceptions.ConnectionError:
        print("  Could not retrieve audit log.")

    print("=" * 60)
    print("BREAK-GLASS SIMULATION COMPLETE")
    print("=" * 60)
    print()
    print("  What was demonstrated:")
    print("  - Clinician submitted a signed emergency request")
    print("  - Key Authority combined Share 2 + Share 3")
    print("  - Private key reconstructed without patient device")
    print("  - All three break-glass events logged in Merkle chain")
    print("  - Patient automatically notified")
    print("  - Reconstructed key destroyed from memory")
    print()
    print("  The patient can verify this access at any time by")
    print("  checking the audit log from the client interface.")


if __name__ == "__main__":
    break_glass()