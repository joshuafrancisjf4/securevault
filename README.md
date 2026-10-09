# 🛡️ SecureVault 2.0

A next-generation Flask-based cybersecurity digital vault engineered to store and protect sensitive files with authenticated **AES-256-GCM** encryption, scrypt key derivation, Smart Inactivity Vault Locking, Master Password Isolation, Two-Factor Authentication (TOTP), and synchronized futuristic HUD lock/unlock animations.

Built upon core cybersecurity tenets — **Confidentiality, Integrity, and Availability (CIA Triad)** — with zero-plaintext storage on disk.

---

## ⚡ SecureVault 2.0 Major Enhancements

1. **Genuine AES-256-GCM File Encryption**:
   - Files are encrypted in-memory before storage using authenticated encryption mode `AES-256-GCM`.
   - Keys are derived from the vault master password using **scrypt KDF** ($N=16384$, $r=8$, $p=1$, 32-byte key) with unique cryptographic salts.
   - 128-bit authentication tags verify integrity and immediately detect file corruption or tampering.
   - Decryption occurs entirely in-memory for download/preview streaming — decrypted files are **never** written to disk.
   - Backward-compatible handling for legacy unencrypted assets.

2. **Smart Vault Lock & Inactivity Defense**:
   - Automated inactivity detection with user-configurable timeouts (30 seconds, 1 minute, 5 minutes, 10 minutes).
   - Page Visibility API integration: automatically engages lockdown when browser tabs switch or become hidden.
   - Instant manual **"Lock Now"** trigger that purges derived encryption keys from session memory.
   - Defense-in-depth: backend session timestamp enforcement validates all file view/download/upload operations.

3. **Master Password Protection**:
   - Master password setup and verification are strictly separated from encryption key derivation.
   - Password authentication hashes use `scrypt` via Werkzeug. Legacy plaintext passwords from version 1.0 are automatically and transparently upgraded to secure hashes on first login.
   - Real-time password strength meter and entropy evaluator with actionable guidance.
   - Rate limiting on authentication routes (maximum 5 attempts with 30-second exponential cooldown).
   - Zero-Knowledge Architecture documentation explaining mathematical recovery realities.

4. **Two-Factor Authentication (2FA)**:
   - RFC 6238 Time-based One-Time Password (TOTP) authenticator app support (Google Authenticator, Microsoft Authenticator, Authy).
   - Offline, pure-Python SVG QR code rendering and manual secret setup key.
   - Verification required prior to activation.
   - 8 single-use emergency backup recovery codes, hashed with SHA-256 in the database and invalidated after one-time use.

5. **Smart Password Generator**:
   - Cryptographically secure random generation using hardware-entropy RNG (`window.crypto.getRandomValues` and Python `secrets`).
   - Configurable character length (8–64 characters) and symbol filters.
   - Live strength evaluation and entropy bits calculation.
   - One-click regenerate, masked/unmasked toggle, and clipboard copy.
   - Seamless "Use in Form" action on vault creation and signup screens.

6. **Futuristic Vault Lock & Unlock Animations**:
   - Cyber HUD with concentric rotating security rings, central digital vault iris, and radar laser sweep.
   - Synchronized state transitions: *"Verifying credentials"*, *"Deriving AES-256 keys via scrypt"*, *"Validating auth tag"*, and *"Vault Unlocked"*.
   - Accessibility-ready with `@media (prefers-reduced-motion: reduce)` support.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.11+, Flask 3.1+
- **Database**: MongoDB (via `pymongo`)
- **Cryptography**: `cryptography` (AES-256-GCM), `hashlib` (scrypt KDF), `werkzeug.security`
- **2FA**: `pyotp` (RFC 6238 TOTP), `qrcode` (SVG renderer)
- **Frontend**: HTML5, Modern CSS3 (Glassmorphism, Cyber HUD), Vanilla JavaScript (Web Crypto API)

---

## 🚀 Setup & Local Execution (Windows)

### 1. Prerequisites
- Python 3.10+ installed
- MongoDB Community Server running locally on `localhost:27017`

### 2. Activate Virtual Environment & Install Dependencies
```powershell
# Navigate to project directory
cd c:\Users\Administrator\Desktop\projects\securevault

# Activate existing virtual environment
.\venv\Scripts\Activate.ps1

# Install / update dependencies
pip install -r requirements.txt
```

### 3. Environment Variables (Optional)
You can configure custom secrets via environment variables:
```powershell
$env:SECRET_KEY = "your-custom-session-secret"
$env:MONGO_URI = "mongodb://localhost:27017/"
```

### 4. Run the Application
```powershell
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Running Automated Tests

Run the complete test suite including crypto tests and end-to-end integration tests:
```powershell
python -m unittest discover
```
Or run individually:
```powershell
python test_crypto.py
python test_app.py
```

---

## 📖 Manual Testing Guide

1. **User Registration & Login**:
   - Visit `http://127.0.0.1:5000/signup`.
   - Create an account with a strong password (observe the live strength meter).
   - Log in at `/login`.
2. **Two-Factor Authentication**:
   - Navigate to **Settings** (`/settings`).
   - Click **Enroll in Two-Factor Authentication**.
   - Scan the QR code with an authenticator app (e.g., Google Authenticator) and enter the 6-digit code.
   - Save the 8 backup recovery codes.
   - Log out and log in again: observe the 2FA challenge. Test logging in with either the TOTP code or an 8-character backup code.
3. **Vault Creation & Master Password**:
   - Go to **Create Vault** (`/create_vault`).
   - Click **⚡ Generate Strong** to populate an entropy-verified master password.
   - Submit to initialize the encrypted vault partition.
4. **Futuristic Unlock Animation & File Encryption**:
   - Open your vault list (`/open_vault`) and click your vault.
   - Enter your master password.
   - Observe the concentric rotating rings and synchronized verification stages before the vault unlocks.
   - Upload any file (PDF, image, text).
   - Check the physical file in `uploads/<vault_id>/<filename>` with a hex editor: note the `SV20` header and encrypted ciphertext.
   - Click **View** or **Download**: observe the file is decrypted on-the-fly.
5. **Smart Vault Lock**:
   - While viewing an unlocked vault, note the countdown timer.
   - Switch browser tabs or minimize the browser: observe that the vault immediately engages lockdown to protect sensitive data.
   - Re-enter master password to resume access.

---

## 👤 Author

**Joshua Francis**
*SecureVault 2.0 — Cryptographic File Protection & Cyber Defense*
