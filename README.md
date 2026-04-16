# Resilience
### Privacy-Preserving Mental Health Monitoring via Homomorphic Encryption and Threshold Key Management

> **Institution:** Vellore Institute of Technology, Chennai — SCOPE School, Dept. of CSE (AI & Robotics)  
> **Authors:** Akileshguhan A (23BRS1070) · Karthik J (23BRS1191)

---

## What This Project Is

Resilience is a privacy-preserving mental health monitoring system for high-risk psychiatric patients. The system tracks a 7-day rolling depressive symptom risk score derived from daily journal entries — without any server ever observing plaintext patient data.

The core guarantee: **no single party, if compromised, can expose a patient's diagnostic data.**

Every HIPAA Technical Safeguard requirement is enforced through a cryptographic mechanism rather than a policy document:

| HIPAA Safeguard | Cryptographic Enforcement |
|---|---|
| Access Control | Shamir 2-of-3 Secret Sharing |
| Audit Controls | SHA-256 Merkle Tree |
| Integrity | ECDSA Signatures (NIST P-256) |
| Transmission Security | CKKS Homomorphic Encryption |
| Emergency Access | Threshold Key Reconstruction |
| Person Authentication | ECDSA Patient Signing Key |

---

## Architecture Overview

The system has four participants with strictly defined trust boundaries:

```
┌─────────────────────────────────────────────────────────────────┐
│                        PATIENT DEVICE                           │
│  DistilBERT (local) · CKKS Encryption · Key Share 1 · ECDSA     │
└──────────────────────────┬──────────────────────────────────────┘
                           │  Encrypted vector + ECDSA signature
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                 AI COMPUTE SERVER (Untrusted)                   │
│  LR Model Weights (plaintext) · HE Dot Product · ECDSA Sign     │
│  ── Never sees plaintext data ────────────────────────────────   │
└──────────────────────────┬──────────────────────────────────────┘
                           │  Encrypted logit + AI signature
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              HOSPITAL KEY AUTHORITY (Trusted Premises)          │
│  Key Share 2 · Merkle Audit Chain · ECDSA Verify + Countersign  │
└──────────────────────────┬──────────────────────────────────────┘
                           │  Countersigned package + Merkle root
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        PATIENT DEVICE                           │
│  Verify countersig · Decrypt logit · Sigmoid · Display score    │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│              THIRD-PARTY ESCROW (Break-Glass Only)              │
│  Key Share 3 · Independent verification · Emergency release     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Cryptographic Stack

### CKKS Homomorphic Encryption (TenSEAL)

The AI server computes a dot product on the patient's encrypted 768-dim embedding without ever decrypting it. The encrypted result is returned to the patient's device for decryption.

- Polynomial modulus degree: **8192**
- Global scale: **2⁴⁰**
- Approximation error: **0.00007687%**
- Ciphertext size: **~326 KB**

### Shamir's Secret Sharing (2-of-3)

- Share 1 → Patient device  
- Share 2 → Hospital Key Authority  
- Share 3 → Third-party escrow  

### ECDSA Signatures (NIST P-256)

All payloads are signed and verified across a countersignature chain.

### SHA-256 Merkle Tree

Append-only audit log with tamper detection.

---

## Machine Learning Model

| Property | Value |
|---|---|
| Embedding Model | DistilBERT |
| Classifier | Logistic Regression |
| Dataset | Dreaddit |
| Accuracy | 77.48% |
| AUC-ROC | 0.8497 |
| Dimension | 768 |

---

## Project Structure

```
resilience/
├── config.py
├── crypto/
├── ai_server/
├── authority/
├── client/
├── models/
└── scripts/
```

---

## Setup

### Install dependencies

```
pip install tenseal ecdsa flask numpy requests transformers torch sympy timm==0.9.16
```

### Disable XET (Windows)

```
set HF_HUB_DISABLE_XET=1
set HF_HUB_DOWNLOAD_TIMEOUT=300
```

### Disable XET (Mac/Linux)

```
export HF_HUB_DISABLE_XET=1
export HF_HUB_DOWNLOAD_TIMEOUT=300
```

### Download model

```
python -c "from transformers import AutoTokenizer, AutoModel; AutoTokenizer.from_pretrained('distilbert-base-uncased'); AutoModel.from_pretrained('distilbert-base-uncased')"
```

---

## Run

Terminal 1:
```
python authority/server.py
```

Terminal 2:
```
python ai_server/server.py
```

Terminal 3:
```
python scripts/register.py
python client/client.py
```

---

## Results

- Accuracy: 77.48%  
- AUC: 0.8497  
- Ciphertext size: ~326 KB  
- Expansion: 54.4×  

---

## Limitations

- Uses DistilBERT (not MentalBERT)  
- No clinician authentication  
- Prototype only  
- Dataset not clinical  

---

## Future Work

- MentalBERT  
- Authentication  
- Mobile deployment  
- Federated learning  

---

