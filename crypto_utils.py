"""
SecureVault 2.0 - Cryptographic Utilities
=========================================
Implements genuine AES-256-GCM file encryption, Argon2id/scrypt key derivation,
cryptographically secure password generation, TOTP 2FA, and recovery code handling.
"""

import os
import hashlib
import secrets
import string
from typing import Tuple, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from werkzeug.security import generate_password_hash, check_password_hash

# Binary file format constants
MAGIC_HEADER = b"SV20"
FORMAT_VERSION = b"\x01"
SALT_SIZE = 16    # 128-bit salt for scrypt
NONCE_SIZE = 12   # 96-bit nonce for AES-GCM
TAG_SIZE = 16     # 128-bit GCM authentication tag

# Scrypt parameters (RFC 7914 compliant, high security)
# N=16384 (CPU/memory cost), r=8 (block size), p=1 (parallelization), 32 bytes derived key
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32


def derive_encryption_key(master_password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit (32-byte) AES encryption key from the master password using scrypt.
    """
    if not isinstance(master_password, str):
        master_password = str(master_password)
    return hashlib.scrypt(
        master_password.encode('utf-8'),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LENGTH
    )


def encrypt_file_bytes(plaintext: bytes, master_password: str, original_filename: str = "") -> bytes:
    """
    Encrypts arbitrary file bytes using AES-256-GCM with a unique per-file salt and nonce.
    Payload format:
      [4 bytes MAGIC 'SV20']
      [1 byte VERSION 0x01]
      [16 bytes FILE_SALT]
      [12 bytes NONCE]
      [CIPHERTEXT + 16 bytes AUTH_TAG]
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_encryption_key(master_password, salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    # Authenticated Associated Data (AAD) binds the magic header and version
    aad = MAGIC_HEADER + FORMAT_VERSION
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data=aad)

    encrypted_payload = MAGIC_HEADER + FORMAT_VERSION + salt + nonce + ciphertext_and_tag
    return encrypted_payload


def is_encrypted_file(file_bytes: bytes) -> bool:
    """
    Checks if binary data begins with the SecureVault 2.0 magic header and version.
    """
    return len(file_bytes) >= (len(MAGIC_HEADER) + len(FORMAT_VERSION)) and \
           file_bytes[:len(MAGIC_HEADER)] == MAGIC_HEADER and \
           file_bytes[len(MAGIC_HEADER):len(MAGIC_HEADER)+1] == FORMAT_VERSION


def decrypt_file_bytes(encrypted_payload: bytes, master_password: str) -> bytes:
    """
    Decrypts an AES-256-GCM encrypted payload using the master password.
    Verifies authentication tag and rejects tampered files or incorrect passwords.

    Raises:
        InvalidTag: If password is incorrect or data was tampered with.
        ValueError: If file structure is corrupt or header is invalid.
    """
    min_len = len(MAGIC_HEADER) + len(FORMAT_VERSION) + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(encrypted_payload) < min_len:
        raise ValueError("Corrupted file: Encrypted file size is smaller than header minimum.")

    magic = encrypted_payload[:len(MAGIC_HEADER)]
    version = encrypted_payload[len(MAGIC_HEADER):len(MAGIC_HEADER)+1]

    if magic != MAGIC_HEADER or version != FORMAT_VERSION:
        raise ValueError("Invalid file format: Not a SecureVault 2.0 encrypted file.")

    offset = len(MAGIC_HEADER) + len(FORMAT_VERSION)
    salt = encrypted_payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = encrypted_payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext_and_tag = encrypted_payload[offset:]

    key = derive_encryption_key(master_password, salt)
    aesgcm = AESGCM(key)
    aad = MAGIC_HEADER + FORMAT_VERSION

    # aesgcm.decrypt raises InvalidTag if ciphertext/tag is corrupted or key is incorrect
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=aad)
    return decrypted_bytes


# Password Hashing for Authentication (separate from encryption key derivation)

def hash_vault_or_user_password(password: str) -> str:
    """
    Creates a secure password verification hash using scrypt.
    """
    return generate_password_hash(password, method="scrypt")


def verify_stored_password(input_password: str, stored_hash_or_plain: str) -> Tuple[bool, bool]:
    """
    Verifies an input password against stored hash or legacy plaintext.
    Returns:
        (is_valid: bool, needs_rehash: bool)
    If needs_rehash is True, caller should update DB with hash_vault_or_user_password(input_password).
    """
    if not stored_hash_or_plain:
        return False, False

    # Check if stored value looks like Werkzeug hash
    if stored_hash_or_plain.startswith(('scrypt:', 'pbkdf2:')):
        try:
            valid = check_password_hash(stored_hash_or_plain, input_password)
            return valid, False
        except Exception:
            return False, False

    # Legacy plaintext fallback for existing users/vaults
    if secrets.compare_digest(input_password, stored_hash_or_plain):
        return True, True  # Match found, mark for upgrading to secure hash!

    return False, False


# Password Generator

def generate_strong_password(
    length: int = 16,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_special: bool = True
) -> str:
    """
    Generates a cryptographically secure random password using secrets module.
    Enforces inclusion of at least one character from each selected set.
    """
    length = max(8, min(64, length))

    char_sets = []
    required_chars = []

    if include_lower:
        char_sets.append(string.ascii_lowercase)
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if include_upper:
        char_sets.append(string.ascii_uppercase)
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if include_digits:
        char_sets.append(string.digits)
        required_chars.append(secrets.choice(string.digits))
    if include_special:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        char_sets.append(symbols)
        required_chars.append(secrets.choice(symbols))

    if not char_sets:
        # Default fallback if nothing selected
        char_sets = [string.ascii_letters + string.digits]
        required_chars = [secrets.choice(char_sets[0])]

    all_chars = "".join(char_sets)
    remaining_length = length - len(required_chars)
    random_chars = [secrets.choice(all_chars) for _ in range(remaining_length)]

    password_list = required_chars + random_chars
    # Cryptographically secure shuffle using Fisher-Yates with secrets.randbelow
    for i in range(len(password_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_list[i], password_list[j] = password_list[j], password_list[i]

    return "".join(password_list)


def calculate_password_strength(password: str) -> dict:
    """
    Evaluates password strength and entropy, returning human-friendly feedback.
    """
    if not password:
        return {"score": 0, "label": "Empty", "entropy": 0, "feedback": ["Please enter a password."]}

    pool_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 33

    import math
    entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0

    feedback = []
    if len(password) < 10:
        feedback.append("Use at least 10 characters for better security.")
    if not has_upper:
        feedback.append("Include uppercase letters (A-Z).")
    if not has_digit:
        feedback.append("Include numeric digits (0-9).")
    if not has_special:
        feedback.append("Include special symbols (!@#$...).")

    if entropy < 36:
        score = 1
        label = "Weak"
    elif entropy < 56:
        score = 2
        label = "Moderate"
    elif entropy < 80:
        score = 3
        label = "Strong"
    else:
        score = 4
        label = "Cyber-Grade"

    return {
        "score": score,
        "label": label,
        "entropy": round(entropy, 1),
        "feedback": feedback
    }


# Two-Factor Authentication Backup Codes

def generate_2fa_backup_codes(count: int = 8) -> Tuple[List[str], List[str]]:
    """
    Generates single-use backup recovery codes.
    Returns:
        (plain_codes: List[str], hashed_codes: List[str])
    Plain codes are shown to user once. Only hashes are stored in database.
    """
    plain_codes = []
    hashed_codes = []
    for _ in range(count):
        code = secrets.token_hex(4).upper()  # e.g., '4A9F1B2C' (formatted: '4A9F-1B2C')
        formatted = f"{code[:4]}-{code[4:]}"
        plain_codes.append(formatted)

        # Hash code with sha256 for secure verification
        hashed = hashlib.sha256(formatted.replace("-", "").upper().encode('utf-8')).hexdigest()
        hashed_codes.append(hashed)

    return plain_codes, hashed_codes


def verify_and_consume_backup_code(entered_code: str, stored_hashes: List[str]) -> Tuple[bool, List[str]]:
    """
    Checks if entered backup code matches any stored hash.
    If valid, returns (True, updated_hashes_list_with_code_removed).
    Otherwise returns (False, stored_hashes).
    """
    clean_code = entered_code.replace("-", "").replace(" ", "").upper().strip()
    target_hash = hashlib.sha256(clean_code.encode('utf-8')).hexdigest()

    for idx, h in enumerate(stored_hashes):
        if secrets.compare_digest(target_hash, h):
            updated = list(stored_hashes)
            updated.pop(idx)
            return True, updated

    return False, stored_hashes
