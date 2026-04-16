# config.py
# Shared configuration for all three processes.
# Every server and client imports from here.
# Change ports here if you have conflicts.

import os

# --- Directory paths ---
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
CRYPTO_DIR     = os.path.join(BASE_DIR, "crypto")
CLIENT_DIR     = os.path.join(BASE_DIR, "client")
AUTHORITY_DIR  = os.path.join(BASE_DIR, "authority")
MODEL_DIR      = os.path.join(BASE_DIR, "models")

# --- File paths ---
CLIENT_STATE_FILE   = os.path.join(CLIENT_DIR,    "state.json")
AUDIT_LOG_FILE      = os.path.join(AUTHORITY_DIR, "audit_log.json")
MODEL_WEIGHTS_FILE  = os.path.join(MODEL_DIR,     "coef.npy")
MODEL_INTERCEPT_FILE= os.path.join(MODEL_DIR,     "intercept.npy")

# --- Server ports ---
AI_SERVER_PORT        = 5001
AUTHORITY_SERVER_PORT = 5002

AI_SERVER_URL        = f"http://localhost:{AI_SERVER_PORT}"
AUTHORITY_SERVER_URL = f"http://localhost:{AUTHORITY_SERVER_PORT}"

# --- CKKS parameters ---
CKKS_POLY_MOD_DEGREE   = 8192
CKKS_COEFF_MOD_BITS    = [60, 40, 40, 60]
CKKS_SCALE             = 2 ** 40

# --- Shamir parameters ---
# secp256k1 prime — same as notebook
SHAMIR_PRIME = (
    2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
)
SHAMIR_TOTAL_SHARES     = 3
SHAMIR_THRESHOLD        = 2

# --- ECDSA ---
ECDSA_CURVE = "NIST256p"

# --- Clinical thresholds ---
RISK_LOW_THRESHOLD      = 0.3
RISK_ELEVATED_THRESHOLD = 0.6
ROLLING_WINDOW_DAYS     = 7

# --- Embedding ---
DISTILBERT_MODEL   = "distilbert-base-uncased"
EMBEDDING_DIM      = 768

# --- Patient config ---
PATIENT_ID = "PATIENT-4821"

print("Config loaded.")