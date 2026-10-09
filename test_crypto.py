import unittest
import os
from cryptography.exceptions import InvalidTag
from crypto_utils import (
    encrypt_file_bytes,
    decrypt_file_bytes,
    is_encrypted_file,
    hash_vault_or_user_password,
    verify_stored_password,
    generate_strong_password,
    calculate_password_strength,
    generate_2fa_backup_codes,
    verify_and_consume_backup_code
)

class TestCryptoUtils(unittest.TestCase):

    def test_encryption_and_decryption(self):
        pwd = "MasterPasswordSecure2026!#"
        data = b"CLASSIFIED SECURITY ASSET - CONFIDENTIAL"

        enc = encrypt_file_bytes(data, pwd)
        self.assertTrue(is_encrypted_file(enc))
        self.assertNotEqual(enc, data)

        dec = decrypt_file_bytes(enc, pwd)
        self.assertEqual(dec, data)

    def test_tamper_detection(self):
        pwd = "MasterPasswordSecure2026!#"
        data = b"CLASSIFIED SECURITY ASSET"
        enc = bytearray(encrypt_file_bytes(data, pwd))

        # Tamper with the last byte (auth tag)
        enc[-1] ^= 0x55

        with self.assertRaises(InvalidTag):
            decrypt_file_bytes(bytes(enc), pwd)

    def test_wrong_password_rejection(self):
        pwd = "CorrectPassword123!"
        wrong_pwd = "WrongPassword456!"
        data = b"Secret vault content"
        enc = encrypt_file_bytes(data, pwd)

        with self.assertRaises(InvalidTag):
            decrypt_file_bytes(enc, wrong_pwd)

    def test_password_hashing_and_legacy_compatibility(self):
        plain = "dmk"
        # Legacy check
        valid, needs_rehash = verify_stored_password(plain, "dmk")
        self.assertTrue(valid)
        self.assertTrue(needs_rehash)

        # New scrypt hash check
        hashed = hash_vault_or_user_password(plain)
        valid2, needs_rehash2 = verify_stored_password(plain, hashed)
        self.assertTrue(valid2)
        self.assertFalse(needs_rehash2)

        # Wrong password
        valid3, _ = verify_stored_password("wrong", hashed)
        self.assertFalse(valid3)

    def test_password_generator(self):
        pwd = generate_strong_password(length=24, include_upper=True, include_lower=True, include_digits=True, include_special=True)
        self.assertEqual(len(pwd), 24)
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(not c.isalnum() for c in pwd))

        strength = calculate_password_strength(pwd)
        self.assertGreaterEqual(strength["score"], 3)

    def test_backup_codes(self):
        plain_codes, hashed_codes = generate_2fa_backup_codes(8)
        self.assertEqual(len(plain_codes), 8)
        self.assertEqual(len(hashed_codes), 8)

        first_code = plain_codes[0]
        # Verify valid code
        success, remaining = verify_and_consume_backup_code(first_code, hashed_codes)
        self.assertTrue(success)
        self.assertEqual(len(remaining), 7)

        # Trying to reuse same code should fail
        success2, remaining2 = verify_and_consume_backup_code(first_code, remaining)
        self.assertFalse(success2)
        self.assertEqual(len(remaining2), 7)

if __name__ == '__main__':
    unittest.main()
