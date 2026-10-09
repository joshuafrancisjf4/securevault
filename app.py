"""
SecureVault 2.0 - Core Application Server
=========================================
Enhanced with authenticated AES-256-GCM file encryption, Argon2id/scrypt KDF,
Smart Inactivity Vault Lock, Master Password Protection, 2FA (TOTP + Backup Codes),
Cryptographically Secure Password Generator, and Futuristic HUD Animations.
"""

import os
import io
import time
import mimetypes
from bson.objectid import ObjectId
from flask import (
    Flask, render_template, request, redirect, session,
    send_file, jsonify, flash, url_for
)
from pymongo import MongoClient
from werkzeug.utils import secure_filename
import pyotp
import qrcode
import qrcode.image.svg

import crypto_utils

app = Flask(__name__)
# Secret key for sessions (can be overridden by environment variable)
app.secret_key = os.environ.get("SECRET_KEY", "securevault-2.0-supersecret-production-key-2026")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max upload

# ---------------- CONFIG & STORAGE ----------------
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- MONGODB ----------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["securevault"]

users_collection = db["users"]
vaults_collection = db["vaults"]

# Rate limiting dictionary in memory: {ip_or_user: [timestamps]}
LOGIN_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 30  # seconds


# ---------------- SECURITY HELPERS ----------------

def is_rate_limited(key: str) -> bool:
    """Checks if IP/user is rate-limited after multiple failed attempts."""
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(key, [])
    # Filter attempts within lockout duration
    attempts = [t for t in attempts if now - t < LOCKOUT_DURATION]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= MAX_FAILED_ATTEMPTS


def record_failed_attempt(key: str):
    """Records a failed attempt timestamp for rate limiting."""
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(key, [])
    attempts.append(now)
    LOGIN_ATTEMPTS[key] = attempts


def reset_failed_attempts(key: str):
    """Clears failed attempts after successful authentication."""
    LOGIN_ATTEMPTS.pop(key, None)


def get_current_user():
    """Retrieves current authenticated user document from session."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    try:
        return users_collection.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


def get_user_lock_timeout(user=None) -> int:
    """Returns user's inactivity timeout preference in seconds (default 300 / 5 min)."""
    if user is None:
        user = get_current_user()
    if user and "lock_timeout" in user:
        try:
            return int(user["lock_timeout"])
        except (ValueError, TypeError):
            pass
    return 300


def check_and_touch_vault_unlock(vault_id: str, user=None) -> bool:
    """
    Validates if vault is currently unlocked in session and within the inactivity timeout.
    If valid, touches last_activity timestamp. If expired, automatically locks it.
    """
    unlocked_vaults = session.get("unlocked_vaults", {})
    vault_info = unlocked_vaults.get(vault_id)
    if not vault_info:
        return False

    now = time.time()
    last_act = vault_info.get("last_activity", 0)
    timeout = get_user_lock_timeout(user)

    if now - last_act > timeout:
        # Expired! Remove from session
        unlocked_vaults.pop(vault_id, None)
        session["unlocked_vaults"] = unlocked_vaults
        return False

    # Within timeout, touch activity
    vault_info["last_activity"] = now
    unlocked_vaults[vault_id] = vault_info
    session["unlocked_vaults"] = unlocked_vaults
    return True


def get_vault_master_password(vault_id: str) -> str:
    """Returns the unlocked master password from session if valid."""
    if not check_and_touch_vault_unlock(vault_id):
        return None
    return session.get("unlocked_vaults", {}).get(vault_id, {}).get("master_password")


def is_safe_path(base_dir: str, path: str) -> bool:
    """Prevents directory traversal attacks."""
    matchpath = os.path.abspath(path)
    base = os.path.abspath(base_dir)
    return matchpath.startswith(base)


# ---------------- SECURITY HEADERS ----------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ---------------- ROUTES ----------------

@app.route('/')
def home():
    """Welcome Landing Page (Feature showcase)."""
    return render_template("welcome.html")


# ---------------- SIGNUP ----------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User Registration with Password Hashing & Strength Validation."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("signup.html")

        # Check existing user
        if users_collection.find_one({"username": username}):
            flash("Username is already taken. Please choose another.", "error")
            return render_template("signup.html")

        # Password strength validation
        strength = crypto_utils.calculate_password_strength(password)
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("signup.html")

        # Hash password securely using scrypt
        hashed_password = crypto_utils.hash_vault_or_user_password(password)

        users_collection.insert_one({
            "username": username,
            "password": hashed_password,
            "two_factor_enabled": False,
            "lock_timeout": 300,
            "created_at": time.time()
        })

        flash("Account created successfully! Please login.", "success")
        return redirect('/login')

    return render_template("signup.html")


# ---------------- LOGIN & 2FA ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User Authentication with 2FA Challenge & Rate Limiting."""
    if request.method == 'POST':
        client_ip = request.remote_addr or "unknown"
        if is_rate_limited(client_ip):
            flash(f"Too many failed login attempts. Please wait {LOCKOUT_DURATION} seconds.", "error")
            return render_template("login.html"), 429

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = users_collection.find_one({"username": username})

        if user:
            stored_pass = user.get('password', '')
            is_valid, needs_rehash = crypto_utils.verify_stored_password(password, stored_pass)

            if is_valid:
                reset_failed_attempts(client_ip)

                # Transparent upgrade of legacy plaintext passwords to scrypt hashes
                if needs_rehash:
                    new_hash = crypto_utils.hash_vault_or_user_password(password)
                    users_collection.update_one({"_id": user["_id"]}, {"$set": {"password": new_hash}})

                # Check if Two-Factor Authentication is enabled
                if user.get("two_factor_enabled"):
                    session["2fa_pending_user_id"] = str(user["_id"])
                    return redirect('/verify-2fa')

                # Direct login if 2FA is not enabled
                session['user_id'] = str(user['_id'])
                session['unlocked_vaults'] = {}
                flash("Authenticated successfully. Welcome to SecureVault!", "success")
                return redirect('/dashboard')

        record_failed_attempt(client_ip)
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Second-Factor Authentication Challenge (TOTP or Backup Code)."""
    pending_id = session.get("2fa_pending_user_id")
    if not pending_id:
        return redirect('/login')

    user = users_collection.find_one({"_id": ObjectId(pending_id)})
    if not user:
        session.pop("2fa_pending_user_id", None)
        return redirect('/login')

    if request.method == 'POST':
        code = request.form.get("two_factor_code", "").strip()
        secret = user.get("two_factor_secret")

        # 1. Verify TOTP code (6-digit)
        totp_valid = False
        if secret and len(code.replace(" ", "")) == 6 and code.replace(" ", "").isdigit():
            totp = pyotp.TOTP(secret)
            totp_valid = totp.verify(code.replace(" ", ""), valid_window=1)

        if totp_valid:
            session.pop("2fa_pending_user_id", None)
            session["user_id"] = str(user["_id"])
            session["unlocked_vaults"] = {}
            flash("Two-Factor verification successful!", "success")
            return redirect('/dashboard')

        # 2. Check single-use backup recovery codes
        stored_backup_hashes = user.get("two_factor_backup_codes", [])
        code_matched, updated_hashes = crypto_utils.verify_and_consume_backup_code(code, stored_backup_hashes)

        if code_matched:
            # Update user record with consumed backup code removed
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"two_factor_backup_codes": updated_hashes}}
            )
            session.pop("2fa_pending_user_id", None)
            session["user_id"] = str(user["_id"])
            session["unlocked_vaults"] = {}
            flash("Backup recovery code accepted! (Code has now been consumed)", "warning")
            return redirect('/dashboard')

        flash("Invalid authentication code or expired backup code.", "error")
        return render_template("verify_2fa.html"), 401

    return render_template("verify_2fa.html")


# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    """Cybersecurity Command Dashboard."""
    if 'user_id' not in session:
        return redirect('/login')

    user = get_current_user()
    if not user:
        session.clear()
        return redirect('/login')

    return render_template("dashboard.html", user=user)


# ---------------- CREATE VAULT ----------------
@app.route('/create_vault', methods=['GET', 'POST'])
def create_vault():
    """Initializes new vault with Master Password & isolated cryptographic directory."""
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        name = request.form.get('vault_name', '').strip()
        password = request.form.get('vault_password', '')
        confirm = request.form.get('confirm_password', '')

        if not name or not password:
            flash("Vault name and master password are required.", "error")
            return render_template("create_vault.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("create_vault.html")

        if len(password) < 6:
            flash("Master password must be at least 6 characters long.", "error")
            return render_template("create_vault.html")

        # Hash master password for authentication verification (separate from KDF)
        hashed_password = crypto_utils.hash_vault_or_user_password(password)

        vault = vaults_collection.insert_one({
            "user_id": session['user_id'],
            "vault_name": name,
            "vault_password": hashed_password,
            "created_at": time.time()
        })

        vault_id = str(vault.inserted_id)

        # Create physical directory in uploads
        vault_path = os.path.join(app.config["UPLOAD_FOLDER"], vault_id)
        os.makedirs(vault_path, exist_ok=True)

        flash(f"Vault '{name}' created with AES-256-GCM protection!", "success")
        return redirect('/open_vault')

    return render_template("create_vault.html")


# ---------------- OPEN VAULT LIST ----------------
@app.route('/open_vault')
def open_vault():
    """Lists user's encrypted vaults with lock status indicators."""
    if 'user_id' not in session:
        return redirect('/login')

    vaults = list(vaults_collection.find({"user_id": session['user_id']}))

    # Get set of currently unlocked vault IDs that haven't timed out
    unlocked_ids = set()
    unlocked_vaults = session.get("unlocked_vaults", {})
    user = get_current_user()

    for vid in list(unlocked_vaults.keys()):
        if check_and_touch_vault_unlock(vid, user):
            unlocked_ids.add(vid)

    return render_template("open_vault.html", vaults=vaults, unlocked_ids=unlocked_ids)


# ---------------- ACCESS / UNLOCK VAULT ----------------
@app.route('/open_vault/<vault_id>', methods=['GET', 'POST'])
def access_vault(vault_id):
    """
    Vault Access Controller:
    - If vault is currently unlocked: renders vault.html with decrypted inventory.
    - If vault is locked: renders enter_password.html with futuristic unlock animation HUD.
    """
    if 'user_id' not in session:
        return redirect('/login')

    user = get_current_user()
    try:
        vault = vaults_collection.find_one({
            "_id": ObjectId(vault_id),
            "user_id": session['user_id']
        })
    except Exception:
        vault = None

    if not vault:
        flash("Vault not found or unauthorized access attempt.", "error")
        return redirect('/open_vault')

    # Handle Master Password Submission (Form POST)
    if request.method == 'POST':
        password = request.form.get('vault_password', '')
        stored_pass = vault.get('vault_password', '')

        is_valid, needs_rehash = crypto_utils.verify_stored_password(password, stored_pass)

        if is_valid:
            # Upgrade legacy plaintext vault password in database if needed
            if needs_rehash:
                new_hash = crypto_utils.hash_vault_or_user_password(password)
                vaults_collection.update_one({"_id": vault["_id"]}, {"$set": {"vault_password": new_hash}})

            # Store unlocked session state
            unlocked = session.get("unlocked_vaults", {})
            unlocked[vault_id] = {
                "master_password": password,
                "unlocked_at": time.time(),
                "last_activity": time.time()
            }
            session["unlocked_vaults"] = unlocked

            flash("Vault successfully authenticated and unlocked!", "success")
            return redirect(f"/open_vault/{vault_id}")
        else:
            flash("Invalid Master Password. Decryption key verification failed.", "error")
            return render_template("enter_password.html", vault_id=vault_id, vault=vault), 401

    # GET Request: Check if already unlocked and within timeout
    if check_and_touch_vault_unlock(vault_id, user):
        vault_path = os.path.join(app.config["UPLOAD_FOLDER"], vault_id)
        os.makedirs(vault_path, exist_ok=True)

        raw_files = os.listdir(vault_path)
        files_info = []

        for f in raw_files:
            fpath = os.path.join(vault_path, f)
            size_str = ""
            is_enc = True
            try:
                sz = os.path.getsize(fpath)
                if sz < 1024:
                    size_str = f"{sz} B"
                elif sz < 1024 * 1024:
                    size_str = f"{sz / 1024:.1f} KB"
                else:
                    size_str = f"{sz / (1024 * 1024):.1f} MB"

                with open(fpath, "rb") as test_f:
                    head = test_f.read(8)
                    is_enc = crypto_utils.is_encrypted_file(head)
            except Exception:
                pass

            files_info.append({
                "name": f,
                "size": size_str,
                "is_encrypted": is_enc
            })

        timeout_sec = get_user_lock_timeout(user)
        return render_template(
            "vault.html",
            vault=vault,
            files=files_info,
            vault_id=vault_id,
            lock_timeout=timeout_sec
        )

    # Vault is currently locked: render futuristic unlock interface
    return render_template("enter_password.html", vault_id=vault_id, vault=vault)


# ---------------- API: ANIMATED VAULT UNLOCK ----------------
@app.route('/api/vault_unlock/<vault_id>', methods=['POST'])
def api_vault_unlock(vault_id):
    """
    JSON API for synchronized frontend futuristic unlock animation.
    Verifies credentials and derives session encryption keys.
    """
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    try:
        vault = vaults_collection.find_one({
            "_id": ObjectId(vault_id),
            "user_id": session['user_id']
        })
    except Exception:
        vault = None

    if not vault:
        return jsonify({"success": False, "error": "Vault not found"}), 404

    data = request.get_json() or {}
    password = data.get("vault_password", "")

    stored_pass = vault.get("vault_password", "")
    is_valid, needs_rehash = crypto_utils.verify_stored_password(password, stored_pass)

    if not is_valid:
        return jsonify({"success": False, "error": "Invalid Master Password"}), 401

    if needs_rehash:
        new_hash = crypto_utils.hash_vault_or_user_password(password)
        vaults_collection.update_one({"_id": vault["_id"]}, {"$set": {"vault_password": new_hash}})

    unlocked = session.get("unlocked_vaults", {})
    unlocked[vault_id] = {
        "master_password": password,
        "unlocked_at": time.time(),
        "last_activity": time.time()
    }
    session["unlocked_vaults"] = unlocked

    return jsonify({"success": True, "message": "Authentication verified & keys derived"})


# ---------------- LOCK VAULT (Feature 2) ----------------
@app.route('/lock_vault/<vault_id>', methods=['GET', 'POST'])
def lock_vault(vault_id):
    """Explicitly locks a vault and wipes decrypted master keys from session."""
    unlocked = session.get("unlocked_vaults", {})
    if vault_id in unlocked:
        unlocked.pop(vault_id, None)
        session["unlocked_vaults"] = unlocked
        flash("Vault secured. Encryption keys purged from session.", "info")

    return redirect(f"/open_vault/{vault_id}")


@app.route('/api/lock_vault/<vault_id>', methods=['POST'])
def api_lock_vault(vault_id):
    """API endpoint for Smart Lock background lock on inactivity/visibility change."""
    unlocked = session.get("unlocked_vaults", {})
    unlocked.pop(vault_id, None)
    session["unlocked_vaults"] = unlocked
    return jsonify({"success": True, "status": "locked", "vault_id": vault_id})


@app.route('/lock_all', methods=['GET', 'POST'])
def lock_all():
    """Locks all open vaults across the session."""
    session["unlocked_vaults"] = {}
    flash("All vaults secured and locked.", "info")
    return redirect('/open_vault')


# ---------------- UPLOAD FILE (Feature 1: AES-256-GCM Encryption) ----------------
@app.route('/upload/<vault_id>', methods=['POST'])
def upload_file(vault_id):
    """
    Encrypts uploaded file with genuine AES-256-GCM using scrypt key derivation
    before persisting to storage.
    """
    if 'user_id' not in session:
        return redirect('/login')

    master_password = get_vault_master_password(vault_id)
    if not master_password:
        flash("Vault is locked. Please enter master password before uploading.", "error")
        return redirect(f"/open_vault/{vault_id}")

    if 'file' not in request.files:
        flash("No file provided in upload request.", "error")
        return redirect(f"/open_vault/{vault_id}")

    file = request.files['file']
    if not file or not file.filename:
        flash("No file selected.", "error")
        return redirect(f"/open_vault/{vault_id}")

    filename = secure_filename(file.filename)
    if not filename:
        flash("Invalid filename provided.", "error")
        return redirect(f"/open_vault/{vault_id}")

    vault_path = os.path.join(app.config["UPLOAD_FOLDER"], vault_id)
    os.makedirs(vault_path, exist_ok=True)
    target_path = os.path.join(vault_path, filename)

    if not is_safe_path(vault_path, target_path):
        flash("Illegal filename path detected.", "error")
        return redirect(f"/open_vault/{vault_id}")

    # Read plaintext file bytes into memory
    plaintext_bytes = file.read()

    try:
        # Encrypt with authenticated AES-256-GCM
        encrypted_bytes = crypto_utils.encrypt_file_bytes(plaintext_bytes, master_password, filename)

        with open(target_path, "wb") as f_out:
            f_out.write(encrypted_bytes)

        flash(f"File '{filename}' securely encrypted with AES-256-GCM and stored.", "success")
    except Exception as e:
        flash(f"Encryption failed: {str(e)}", "error")

    return redirect(f"/open_vault/{vault_id}")


# ---------------- VIEW FILE (On-The-Fly AES Decryption) ----------------
@app.route('/view/<vault_id>/<filename>')
def view_file(vault_id, filename):
    """
    Decrypts AES-256-GCM file in memory and streams inline preview.
    Plaintext is NEVER written to disk!
    """
    if 'user_id' not in session:
        return redirect('/login')

    master_password = get_vault_master_password(vault_id)
    if not master_password:
        flash("Vault is locked. Master password required to decrypt files.", "error")
        return redirect(f"/open_vault/{vault_id}")

    vault_path = os.path.join(app.config["UPLOAD_FOLDER"], vault_id)
    safe_name = secure_filename(filename)
    file_path = os.path.join(vault_path, safe_name)

    if not os.path.exists(file_path) or not is_safe_path(vault_path, file_path):
        flash("Requested file not found in vault.", "error")
        return redirect(f"/open_vault/{vault_id}")

    with open(file_path, "rb") as f_in:
        raw_bytes = f_in.read()

    # If file was encrypted with SecureVault 2.0 AES-256-GCM format
    if crypto_utils.is_encrypted_file(raw_bytes):
        try:
            decrypted_bytes = crypto_utils.decrypt_file_bytes(raw_bytes, master_password)
        except Exception:
            flash("Decryption failed: Authentication tag mismatch or corrupt file.", "error")
            return redirect(f"/open_vault/{vault_id}")
    else:
        # Legacy backward-compatibility for unencrypted files
        decrypted_bytes = raw_bytes

    mimetype, _ = mimetypes.guess_type(safe_name)
    mimetype = mimetype or "application/octet-stream"

    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=mimetype,
        as_attachment=False,
        download_name=safe_name
    )


# ---------------- DOWNLOAD FILE ----------------
@app.route('/download/<vault_id>/<filename>')
def download_file(vault_id, filename):
    """
    Decrypts AES-256-GCM file in memory and streams as downloaded attachment.
    """
    if 'user_id' not in session:
        return redirect('/login')

    master_password = get_vault_master_password(vault_id)
    if not master_password:
        flash("Vault is locked. Master password required to download files.", "error")
        return redirect(f"/open_vault/{vault_id}")

    vault_path = os.path.join(app.config["UPLOAD_FOLDER"], vault_id)
    safe_name = secure_filename(filename)
    file_path = os.path.join(vault_path, safe_name)

    if not os.path.exists(file_path) or not is_safe_path(vault_path, file_path):
        flash("Requested file not found in vault.", "error")
        return redirect(f"/open_vault/{vault_id}")

    with open(file_path, "rb") as f_in:
        raw_bytes = f_in.read()

    if crypto_utils.is_encrypted_file(raw_bytes):
        try:
            decrypted_bytes = crypto_utils.decrypt_file_bytes(raw_bytes, master_password)
        except Exception:
            flash("Decryption failed: Authentication tag verification failed.", "error")
            return redirect(f"/open_vault/{vault_id}")
    else:
        decrypted_bytes = raw_bytes

    mimetype, _ = mimetypes.guess_type(safe_name)
    mimetype = mimetype or "application/octet-stream"

    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=mimetype,
        as_attachment=True,
        download_name=safe_name
    )


# ---------------- DELETE FILE ----------------
@app.route('/delete/<vault_id>/<filename>')
def delete_file(vault_id, filename):
    """Securely deletes file from the encrypted vault."""
    if 'user_id' not in session:
        return redirect('/login')

    if not check_and_touch_vault_unlock(vault_id):
        flash("Vault is locked. Master password required to delete assets.", "error")
        return redirect(f"/open_vault/{vault_id}")

    vault_path = os.path.join(app.config["UPLOAD_FOLDER"], vault_id)
    safe_name = secure_filename(filename)
    file_path = os.path.join(vault_path, safe_name)

    if os.path.exists(file_path) and is_safe_path(vault_path, file_path):
        os.remove(file_path)
        flash(f"Asset '{safe_name}' permanently deleted.", "info")

    return redirect(f"/open_vault/{vault_id}")


# ---------------- SETTINGS & 2FA MANAGEMENT ----------------

@app.route('/settings')
def settings():
    """Security Settings Panel (2FA, Smart Lock timeout)."""
    if 'user_id' not in session:
        return redirect('/login')
    user = get_current_user()
    return render_template("settings.html", user=user)


@app.route('/api/update_timeout', methods=['POST'])
def update_timeout():
    """Updates user inactivity timeout preference (Feature 2)."""
    if 'user_id' not in session:
        return redirect('/login')

    try:
        new_timeout = int(request.form.get("timeout", 300))
        if new_timeout in (30, 60, 300, 600):
            users_collection.update_one(
                {"_id": ObjectId(session['user_id'])},
                {"$set": {"lock_timeout": new_timeout}}
            )
            flash(f"Inactivity timeout preference updated to {new_timeout} seconds.", "success")
    except Exception:
        pass

    return redirect('/settings')


@app.route('/settings/2fa/setup')
def setup_2fa():
    """Initiates 2FA TOTP Enrollment with SVG QR Code generation."""
    if 'user_id' not in session:
        return redirect('/login')

    user = get_current_user()
    secret = pyotp.random_base32()
    session["temp_totp_secret"] = secret

    # Generate standard otpauth URI
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.get("username", "User"),
        issuer_name="SecureVault 2.0"
    )

    # Render offline, pure-Python SVG QR code
    qr_img = qrcode.make(provisioning_uri, image_factory=qrcode.image.svg.SvgPathImage)
    svg_buf = io.BytesIO()
    qr_img.save(svg_buf)
    qr_svg = svg_buf.getvalue().decode('utf-8')

    return render_template("setup_2fa.html", secret=secret, qr_svg=qr_svg)


@app.route('/settings/2fa/verify', methods=['POST'])
def verify_setup_2fa():
    """Verifies initial 6-digit TOTP code and generates single-use backup recovery codes."""
    if 'user_id' not in session:
        return redirect('/login')

    secret = session.get("temp_totp_secret")
    code = request.form.get("code", "").strip()

    if not secret:
        flash("2FA session expired. Please try again.", "error")
        return redirect('/settings/2fa/setup')

    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=1):
        # Generate 8 single-use backup recovery codes
        plain_codes, hashed_codes = crypto_utils.generate_2fa_backup_codes(8)

        users_collection.update_one(
            {"_id": ObjectId(session['user_id'])},
            {"$set": {
                "two_factor_enabled": True,
                "two_factor_secret": secret,
                "two_factor_backup_codes": hashed_codes
            }}
        )
        session.pop("temp_totp_secret", None)
        return render_template("backup_codes.html", backup_codes=plain_codes)
    else:
        flash("Invalid 6-digit verification code. Please try again.", "error")
        return redirect('/settings/2fa/setup')


@app.route('/settings/2fa/disable', methods=['POST'])
def disable_2fa():
    """Disables Two-Factor Authentication."""
    if 'user_id' not in session:
        return redirect('/login')

    users_collection.update_one(
        {"_id": ObjectId(session['user_id'])},
        {"$set": {
            "two_factor_enabled": False,
            "two_factor_secret": None,
            "two_factor_backup_codes": []
        }}
    )
    flash("Two-Factor Authentication disabled.", "info")
    return redirect('/settings')


# ---------------- API: PASSWORD GENERATOR (Feature 5) ----------------
@app.route('/api/generate_password')
def api_generate_password():
    """Cryptographically secure password generation API."""
    length = int(request.args.get("length", 16))
    use_upper = request.args.get("upper", "true").lower() == "true"
    use_lower = request.args.get("lower", "true").lower() == "true"
    use_digits = request.args.get("digits", "true").lower() == "true"
    use_special = request.args.get("symbols", "true").lower() == "true"

    password = crypto_utils.generate_strong_password(
        length=length,
        include_upper=use_upper,
        include_lower=use_lower,
        include_digits=use_digits,
        include_special=use_special
    )
    strength = crypto_utils.calculate_password_strength(password)

    return jsonify({
        "password": password,
        "strength": strength
    })


# ---------------- RECOVERY INFO (Zero-Knowledge Guide) ----------------
@app.route('/recovery-info')
def recovery_info():
    """Educational page on Zero-Knowledge architecture and recovery limitations."""
    return render_template("recovery_info.html")


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    """Terminates session and purges all decrypted keys from memory."""
    session.clear()
    flash("Session terminated securely.", "info")
    return redirect('/')


# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)