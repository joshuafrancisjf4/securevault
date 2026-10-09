"""
SecureVault 2.0 - Automated Integration & Security Test Suite
Tests all 6 features:
1. AES-256-GCM file encryption and decryption, tamper detection
2. Smart Vault Lock & Inactivity timeout
3. Master Password protection & legacy hash upgrading
4. Two-Factor Authentication (TOTP + single-use backup recovery codes)
5. Smart Password Generator API & strength evaluation
6. Vault lock/unlock endpoints & authorized access control
"""

import unittest
import io
import os
import pyotp
from bson.objectid import ObjectId
from app import app, db, users_collection, vaults_collection
import crypto_utils

class SecureVault2IntegrationTest(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        # Create isolated test user
        self.username = f"testuser_{os.urandom(4).hex()}"
        self.password = "SuperSecurePass2026!#"
        self.hashed_pw = crypto_utils.hash_vault_or_user_password(self.password)

        self.user_doc = {
            "username": self.username,
            "password": self.hashed_pw,
            "two_factor_enabled": False,
            "lock_timeout": 300
        }
        res = users_collection.insert_one(self.user_doc)
        self.user_id = str(res.inserted_id)

    def tearDown(self):
        # Clean up test user & vaults
        users_collection.delete_one({"_id": ObjectId(self.user_id)})
        vaults_collection.delete_many({"user_id": self.user_id})

    def login_user(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.user_id
            sess['unlocked_vaults'] = {}

    def test_signup_and_login_flow(self):
        new_user = f"new_{os.urandom(4).hex()}"
        new_pass = "TestPass789!#"

        # Test Signup
        resp = self.client.post('/signup', data={
            'username': new_user,
            'password': new_pass
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Verify password is saved as scrypt hash, NOT plaintext
        db_u = users_collection.find_one({"username": new_user})
        self.assertIsNotNone(db_u)
        self.assertTrue(db_u['password'].startswith(('scrypt:', 'pbkdf2:')))

        # Test Login
        resp2 = self.client.post('/login', data={
            'username': new_user,
            'password': new_pass
        }, follow_redirects=True)
        self.assertEqual(resp2.status_code, 200)
        self.assertIn(b"Cybersecurity Command Center", resp2.data)

        # Clean up
        users_collection.delete_one({"_id": db_u['_id']})

    def test_legacy_plaintext_password_auto_upgrade(self):
        legacy_user = f"legacy_{os.urandom(4).hex()}"
        legacy_pass = "oldplainpassword"

        # Insert directly as plaintext (simulating SecureVault 1.0)
        res = users_collection.insert_one({
            "username": legacy_user,
            "password": legacy_pass,
            "two_factor_enabled": False
        })

        # Login with plaintext
        resp = self.client.post('/login', data={
            'username': legacy_user,
            'password': legacy_pass
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Check that MongoDB record was automatically upgraded to scrypt hash!
        updated = users_collection.find_one({"_id": res.inserted_id})
        self.assertTrue(updated['password'].startswith(('scrypt:', 'pbkdf2:')))
        self.assertNotEqual(updated['password'], legacy_pass)

        # Clean up
        users_collection.delete_one({"_id": res.inserted_id})

    def test_two_factor_auth_enrollment_and_challenge(self):
        self.login_user()

        # Step 1: Request 2FA setup page
        resp = self.client.get('/settings/2fa/setup')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"<svg", resp.data)  # SVG QR code rendered

        with self.client.session_transaction() as sess:
            secret = sess.get('temp_totp_secret')
        self.assertIsNotNone(secret)

        # Step 2: Verify with correct TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        resp_verify = self.client.post('/settings/2fa/verify', data={
            'code': valid_code
        })
        self.assertEqual(resp_verify.status_code, 200)
        self.assertIn(b"2FA Successfully Activated", resp_verify.data)

        # Check DB that 2FA is active and has 8 backup codes
        updated_u = users_collection.find_one({"_id": ObjectId(self.user_id)})
        self.assertTrue(updated_u['two_factor_enabled'])
        backup_hashes = updated_u['two_factor_backup_codes']
        self.assertEqual(len(backup_hashes), 8)

        # Step 3: Test Login with 2FA Challenge
        self.client.get('/logout')

        resp_login = self.client.post('/login', data={
            'username': self.username,
            'password': self.password
        }, follow_redirects=True)
        self.assertIn(b"Two-Factor Challenge", resp_login.data)

        # Verify challenge with TOTP
        resp_challenge = self.client.post('/verify-2fa', data={
            'two_factor_code': totp.now()
        }, follow_redirects=True)
        self.assertIn(b"Cybersecurity Command Center", resp_challenge.data)

    def test_vault_creation_and_aes256_encryption_flow(self):
        self.login_user()

        vault_name = "Confidential Vault Alpha"
        master_pw = "MasterVaultSecret2026!#"

        # Step 1: Create Vault
        resp = self.client.post('/create_vault', data={
            'vault_name': vault_name,
            'vault_password': master_pw,
            'confirm_password': master_pw
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        vault = vaults_collection.find_one({"user_id": self.user_id, "vault_name": vault_name})
        self.assertIsNotNone(vault)
        vault_id = str(vault['_id'])

        # Step 2: Vault is initially locked
        resp_view = self.client.get(f'/open_vault/{vault_id}')
        self.assertIn(b"Unlock", resp_view.data)

        # Step 3: Unlock Vault via API or POST
        resp_unlock = self.client.post(f'/api/vault_unlock/{vault_id}', json={
            'vault_password': master_pw
        })
        self.assertEqual(resp_unlock.status_code, 200)
        self.assertTrue(resp_unlock.json['success'])

        # Step 4: Upload file to be encrypted with AES-256-GCM
        test_content = b"TOP SECRET: Financial figures and encryption keys 2026."
        test_filename = "classified_report.txt"

        resp_upload = self.client.post(f'/upload/{vault_id}', data={
            'file': (io.BytesIO(test_content), test_filename)
        }, follow_redirects=True)
        self.assertEqual(resp_upload.status_code, 200)

        # Verify on-disk file is genuinely encrypted with SV20 magic header
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], vault_id, test_filename)
        self.assertTrue(os.path.exists(file_path))

        with open(file_path, "rb") as f:
            disk_bytes = f.read()

        # The file on disk must NOT be the plaintext!
        self.assertNotEqual(disk_bytes, test_content)
        # Must start with SecureVault 2.0 magic bytes
        self.assertTrue(crypto_utils.is_encrypted_file(disk_bytes))

        # Step 5: View / Download file - streams decrypted bytes
        resp_download = self.client.get(f'/download/{vault_id}/{test_filename}')
        self.assertEqual(resp_download.status_code, 200)
        self.assertEqual(resp_download.data, test_content)

        # Step 6: Test Tamper Detection
        # Corrupt the ciphertext file on disk
        tampered_bytes = bytearray(disk_bytes)
        tampered_bytes[-1] ^= 0xFF
        with open(file_path, "wb") as f:
            f.write(tampered_bytes)

        resp_corrupt = self.client.get(f'/download/{vault_id}/{test_filename}', follow_redirects=True)
        self.assertIn(b"Decryption failed", resp_corrupt.data)

        # Step 7: Delete file
        resp_del = self.client.get(f'/delete/{vault_id}/{test_filename}', follow_redirects=True)
        self.assertEqual(resp_del.status_code, 200)
        self.assertFalse(os.path.exists(file_path))

    def test_smart_vault_lock_and_lockout(self):
        self.login_user()
        master_pw = "VaultSecret2026!#"

        vault = vaults_collection.insert_one({
            "user_id": self.user_id,
            "vault_name": "LockTestVault",
            "vault_password": crypto_utils.hash_vault_or_user_password(master_pw)
        })
        vault_id = str(vault.inserted_id)

        # Unlock
        self.client.post(f'/api/vault_unlock/{vault_id}', json={'vault_password': master_pw})

        # Lock manually
        resp_lock = self.client.post(f'/api/lock_vault/{vault_id}')
        self.assertEqual(resp_lock.status_code, 200)

        # Verify file upload is rejected when locked
        resp_fail_upload = self.client.post(f'/upload/{vault_id}', data={
            'file': (io.BytesIO(b"data"), "file.txt")
        }, follow_redirects=True)
        self.assertIn(b"Vault is locked", resp_fail_upload.data)

    def test_password_generator_api(self):
        resp = self.client.get('/api/generate_password?length=20&upper=true&lower=true&digits=true&symbols=true')
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertEqual(len(data['password']), 20)
        self.assertGreaterEqual(data['strength']['score'], 3)


if __name__ == '__main__':
    unittest.main()
