"""
Phase 2 Automated Test Suite for Hybrid Cryptography and Network Security.

Covers:
1. AES-256-GCM encryption, decryption, nonce uniqueness, and tampering detection
2. RSA-OAEP (3072-bit, SHA-256) key wrapping, unwrapping, and error rejection
3. RSA-PSS (3072-bit, SHA-256) valid signature and altered package/signature rejection
4. PBKDF2-HMAC-SHA256 password derivation and verification
5. HMAC-SHA256 integrity verification for logs and transaction records
6. Replay protection: duplicate nonce rejection, duplicate transaction ID rejection, and expired timestamp rejection
7. End-to-end 11-step client / 12-step server secure transaction flow & server-side price recomputation
8. TLS 1.3 valid connection negotiation and invalid/untrusted certificate rejection
"""
import base64
import datetime
from datetime import timezone
import json
import socket
import ssl
import sys
import os
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from database.database import db
from models.user import User
from models.product import Product
from models.order import Order
from models.transaction import Transaction, ConsumedNonce, SecurityLog
from services.crypto.aes_encryption import (
    AESEncryptionError,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_gcm_nonce,
)
from services.crypto.rsa_key_management import (
    RSAKeyManagementError,
    generate_rsa_keypair,
    get_or_create_server_keypair,
    get_server_private_key_pem,
    get_server_public_key_pem,
    provision_client_keypair,
)
from services.crypto.rsa_encryption import (
    RSAEncryptionError,
    unwrap_aes_key,
    wrap_aes_key,
)
from services.crypto.digital_signature import (
    sign_transaction_package,
    verify_transaction_signature,
)
from services.crypto.integrity import (
    compute_hmac_sha256,
    hash_password_pbkdf2,
    verify_hmac_sha256,
    verify_password_pbkdf2,
)
from services.crypto.transaction_security import (
    build_client_transaction_package,
    create_tls_client_context,
    create_tls_server_context,
    ensure_local_tls_certificates,
    generate_replay_nonce,
    generate_timestamp,
    generate_transaction_id,
    generate_untrusted_self_signed_cert,
    perform_tls_handshake_and_exchange,
    validate_timestamp,
    validate_transaction_id,
    verify_and_process_transaction_package,
)


# Pre-generate a secondary RSA-3072 keypair once for wrong-key negative tests
_ALT_PRIVATE_PEM, _ALT_PUBLIC_PEM = generate_rsa_keypair(3072)


class TestAES256GCM(unittest.TestCase):
    """Test AES-256-GCM authenticated encryption and tampering detection."""

    def test_aes_key_and_nonce_lengths(self):
        key = generate_aes_key()
        nonce = generate_gcm_nonce(key)
        self.assertEqual(len(key), 32)    # 256 bits
        self.assertEqual(len(nonce), 12)  # 96 bits

    def test_aes_encryption_and_decryption(self):
        key = generate_aes_key()
        nonce = generate_gcm_nonce(key)
        payload = '{"item":"Headphones","qty":2,"amount":5998.00}'
        aad = b"tx-123:user-1"

        enc = encrypt_aes_gcm(payload, key=key, nonce=nonce, associated_data=aad)
        self.assertEqual(len(enc['auth_tag']), 16)  # 128-bit GCM tag

        decrypted = decrypt_aes_gcm(
            ciphertext=enc['ciphertext_b64'],
            key=key,
            nonce=enc['nonce_b64'],
            auth_tag=enc['auth_tag_b64'],
            associated_data=aad,
        )
        self.assertEqual(decrypted.decode('utf-8'), payload)

    def test_aes_tampering_detection_ciphertext(self):
        enc = encrypt_aes_gcm("Sensitive transaction payload")
        tampered_ct = bytearray(enc['ciphertext'])
        tampered_ct[0] ^= 0x01

        with self.assertRaises(AESEncryptionError):
            decrypt_aes_gcm(
                ciphertext=bytes(tampered_ct),
                key=enc['key'],
                nonce=enc['nonce'],
                auth_tag=enc['auth_tag'],
            )

    def test_aes_tampering_detection_auth_tag(self):
        enc = encrypt_aes_gcm("Sensitive transaction payload")
        tampered_tag = bytearray(enc['auth_tag'])
        tampered_tag[-1] ^= 0x01

        with self.assertRaises(AESEncryptionError):
            decrypt_aes_gcm(
                ciphertext=enc['ciphertext'],
                key=enc['key'],
                nonce=enc['nonce'],
                auth_tag=bytes(tampered_tag),
            )

    def test_aes_wrong_key_rejection(self):
        enc = encrypt_aes_gcm("Sensitive transaction payload")
        wrong_key = generate_aes_key()

        with self.assertRaises(AESEncryptionError):
            decrypt_aes_gcm(
                ciphertext=enc['ciphertext'],
                key=wrong_key,
                nonce=enc['nonce'],
                auth_tag=enc['auth_tag'],
            )

    def test_aes_nonce_reuse_rejected(self):
        key = generate_aes_key()
        nonce = generate_gcm_nonce(key)
        encrypt_aes_gcm("First message", key=key, nonce=nonce)

        with self.assertRaises(AESEncryptionError):
            encrypt_aes_gcm("Second message with same key and nonce", key=key, nonce=nonce)


class TestRSAOAEP(unittest.TestCase):
    """Test RSA-3072 key management and RSA-OAEP key wrapping."""

    def test_rsa_key_size_validation(self):
        with self.assertRaises(RSAKeyManagementError):
            generate_rsa_keypair(2048)

    def test_rsa_oaep_encryption_and_decryption(self):
        aes_key = generate_aes_key()
        pub_pem = get_server_public_key_pem()
        priv_pem = get_server_private_key_pem()

        wrapped = wrap_aes_key(aes_key, public_key_pem=pub_pem)
        self.assertEqual(len(wrapped['wrapped_key']), 384)  # 3072-bit RSA modulus = 384 bytes

        unwrapped = unwrap_aes_key(wrapped['wrapped_key_b64'], private_key_pem=priv_pem)
        self.assertEqual(unwrapped, aes_key)

    def test_rsa_oaep_wrong_private_key_rejected(self):
        aes_key = generate_aes_key()
        wrapped = wrap_aes_key(aes_key, public_key_pem=get_server_public_key_pem())

        with self.assertRaises(RSAEncryptionError):
            unwrap_aes_key(wrapped['wrapped_key_b64'], private_key_pem=_ALT_PRIVATE_PEM)

    def test_rsa_oaep_corrupted_ciphertext_rejected(self):
        aes_key = generate_aes_key()
        wrapped = wrap_aes_key(aes_key, public_key_pem=get_server_public_key_pem())
        corrupted = bytearray(wrapped['wrapped_key'])
        corrupted[10] ^= 0xFF

        with self.assertRaises(RSAEncryptionError):
            unwrap_aes_key(bytes(corrupted), private_key_pem=get_server_private_key_pem())


class TestRSAPSSSignatures(unittest.TestCase):
    """Test RSA-PSS digital signature generation and verification."""

    def setUp(self):
        self.priv_pem, self.pub_pem = get_or_create_server_keypair()
        self.sample_package = {
            'transaction_id': generate_transaction_id(),
            'user_id': 2,
            'timestamp': generate_timestamp(),
            'nonce': generate_replay_nonce(),
            'ciphertext_b64': base64.b64encode(b'encrypted_data').decode('ascii'),
            'gcm_nonce_b64': base64.b64encode(b'12byte_nonce').decode('ascii'),
            'auth_tag_b64': base64.b64encode(b'16byte_auth_tag!').decode('ascii'),
            'wrapped_key_b64': base64.b64encode(b'wrapped_key_bytes').decode('ascii'),
        }

    def test_rsa_pss_valid_signature(self):
        sig = sign_transaction_package(self.sample_package, self.priv_pem)
        self.assertTrue(
            verify_transaction_signature(self.sample_package, sig['signature_b64'], self.pub_pem)
        )

    def test_rsa_pss_altered_package_rejection(self):
        sig = sign_transaction_package(self.sample_package, self.priv_pem)
        altered_package = dict(self.sample_package)
        altered_package['nonce'] = generate_replay_nonce()

        self.assertFalse(
            verify_transaction_signature(altered_package, sig['signature_b64'], self.pub_pem)
        )

    def test_rsa_pss_altered_signature_rejection(self):
        sig = sign_transaction_package(self.sample_package, self.priv_pem)
        tampered_sig = bytearray(sig['signature'])
        tampered_sig[0] ^= 0xFF

        self.assertFalse(
            verify_transaction_signature(self.sample_package, bytes(tampered_sig), self.pub_pem)
        )

    def test_rsa_pss_wrong_public_key_rejection(self):
        sig = sign_transaction_package(self.sample_package, self.priv_pem)
        self.assertFalse(
            verify_transaction_signature(self.sample_package, sig['signature_b64'], _ALT_PUBLIC_PEM)
        )


class TestPBKDF2AndHMAC(unittest.TestCase):
    """Test PBKDF2-HMAC-SHA256 password hashing and HMAC-SHA256 integrity."""

    def test_pbkdf2_password_verification(self):
        pw_hash_1 = hash_password_pbkdf2('SecurePass@2026', iterations=260000)
        pw_hash_2 = hash_password_pbkdf2('SecurePass@2026', iterations=260000)

        self.assertTrue(pw_hash_1.startswith('pbkdf2:sha256:260000$'))
        self.assertNotEqual(pw_hash_1, pw_hash_2)  # Unique random salts
        self.assertTrue(verify_password_pbkdf2(pw_hash_1, 'SecurePass@2026'))
        self.assertFalse(verify_password_pbkdf2(pw_hash_1, 'WrongPass@2026'))

    def test_hmac_integrity_verification(self):
        record = {'event': 'ORDER_PLACED', 'amount': 1499.00, 'user_id': 5}
        tag = compute_hmac_sha256(record)

        self.assertTrue(verify_hmac_sha256(record, tag))

        # Modify record
        tampered_record = {'event': 'ORDER_PLACED', 'amount': 1.00, 'user_id': 5}
        self.assertFalse(verify_hmac_sha256(tampered_record, tag))
        self.assertFalse(verify_hmac_sha256(record, '00' * 32))


class TestReplayAndSecureTransactionFlow(unittest.TestCase):
    """Test replay protection, timestamp validation, and end-to-end hybrid cryptographic checkout."""

    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.admin = User(name='Admin User', email='admin@test.com', role='admin')
        self.admin.set_password('Admin@12345')
        self.admin.ensure_client_public_key()

        self.customer = User(name='Customer User', email='customer@test.com', role='customer')
        self.customer.set_password('Customer@123')
        self.customer.ensure_client_public_key()

        self.product = Product(
            name='Secure Hardware Token',
            description='FIDO2 / PKCS#11 hardware security key.',
            price=2500.00,
            category='Electronics',
            stock=20
        )
        db.session.add_all([self.admin, self.customer, self.product])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_duplicate_nonce_rejection(self):
        nonce = generate_replay_nonce()
        items = [{'product_id': self.product.id, 'name': self.product.name, 'price': 2500.00, 'quantity': 1}]

        pkg1 = build_client_transaction_package(
            user_id=self.customer.id,
            items=items,
            shipping_address='100 Cyber Park, Bengaluru, KA 560001',
            nonce=nonce,
        )
        ok1, msg1, order1, tx1 = verify_and_process_transaction_package(pkg1, self.customer)
        self.assertTrue(ok1, msg1)
        self.assertIsNotNone(order1)
        self.assertIsNotNone(tx1)

        # Replay second package reusing the exact same nonce (even with a new transaction_id)
        pkg2 = build_client_transaction_package(
            user_id=self.customer.id,
            items=items,
            shipping_address='100 Cyber Park, Bengaluru, KA 560001',
            nonce=nonce,
        )
        ok2, msg2, order2, tx2 = verify_and_process_transaction_package(pkg2, self.customer)
        self.assertFalse(ok2)
        self.assertIn('Replay', msg2)
        self.assertIsNone(order2)

    def test_expired_timestamp_rejection(self):
        expired_dt = datetime.datetime.now(timezone.utc) - datetime.timedelta(minutes=15)
        expired_iso = expired_dt.isoformat()

        is_valid, err_msg = validate_timestamp(expired_iso, tolerance_seconds=300)
        self.assertFalse(is_valid)
        self.assertIn('expired', err_msg.lower())

        items = [{'product_id': self.product.id, 'name': self.product.name, 'price': 2500.00, 'quantity': 1}]
        pkg = build_client_transaction_package(
            user_id=self.customer.id,
            items=items,
            shipping_address='100 Cyber Park, Bengaluru, KA 560001',
            timestamp=expired_iso,
        )
        ok, msg, order, _ = verify_and_process_transaction_package(pkg, self.customer)
        self.assertFalse(ok)
        self.assertIn('expired', msg.lower())
        self.assertIsNone(order)

    def test_server_recomputes_price_and_ignores_tampered_client_price(self):
        # Client claims the ₹2,500 product costs ₹1.00
        tampered_items = [{'product_id': self.product.id, 'name': self.product.name, 'price': 1.00, 'quantity': 2}]
        pkg = build_client_transaction_package(
            user_id=self.customer.id,
            items=tampered_items,
            shipping_address='100 Cyber Park, Bengaluru, KA 560001',
            client_reported_total=2.00,
        )
        ok, msg, order, tx = verify_and_process_transaction_package(pkg, self.customer)
        self.assertTrue(ok, msg)
        # Server must compute 2 * 2500.00 = 5000.00 from database Product.price
        self.assertEqual(order.total_amount, 5000.00)
        self.assertEqual(tx.amount, 5000.00)
        self.assertTrue(tx.verify_integrity())

    def test_transaction_details_and_admin_crypto_demo_pages(self):
        # Login as customer, place order, and view transaction detail page
        self.client.post('/login', data={'email': 'customer@test.com', 'password': 'Customer@123'}, follow_redirects=True)
        self.client.post(f'/cart/add/{self.product.id}', data={'quantity': 1}, follow_redirects=True)
        self.client.post('/checkout', data={'shipping_address': '100 Cyber Park, Bengaluru, KA 560001'}, follow_redirects=True)

        tx = Transaction.query.first()
        self.assertIsNotNone(tx)
        self.assertTrue(tx.is_encrypted)
        self.assertEqual(tx.verification_status, 'VERIFIED')

        resp = self.client.get(f'/transaction/{tx.transaction_id}')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'AES-256-GCM Encrypted', resp.data)
        self.assertIn(b'VERIFIED (RSA-PSS)', resp.data)

        # Customer cannot access /admin/crypto-demo
        resp_forbidden = self.client.get('/admin/crypto-demo')
        self.assertEqual(resp_forbidden.status_code, 403)

        # Admin can access /admin/crypto-demo
        self.client.get('/logout', follow_redirects=True)
        self.client.post('/login', data={'email': 'admin@test.com', 'password': 'Admin@12345'}, follow_redirects=True)
        resp_demo = self.client.get('/admin/crypto-demo')
        self.assertEqual(resp_demo.status_code, 200)
        self.assertIn(b'Hybrid Cryptography &amp; Security Demonstration Lab', resp_demo.data)


class TestTLS13Security(unittest.TestCase):
    """Test real TLS 1.3 handshake and invalid/untrusted certificate rejection."""

    def test_valid_tls13_connection(self):
        ensure_local_tls_certificates()
        server_ctx = create_tls_server_context(require_tls13=True)
        client_ctx = create_tls_client_context(require_tls13=True)

        result = perform_tls_handshake_and_exchange(
            server_ctx=server_ctx,
            client_ctx=client_ctx,
            message=b"SECURE_TX_PING",
            server_hostname="localhost",
        )
        self.assertEqual(result['protocol_version'], 'TLSv1.3')
        self.assertEqual(result['response'], b"ACK:SECURE_TX_PING")
        self.assertIsNotNone(result['cipher'])

    def test_invalid_certificate_rejection(self):
        ensure_local_tls_certificates()
        untrusted_cert, untrusted_key = generate_untrusted_self_signed_cert()
        rogue_server_ctx = create_tls_server_context(
            cert_path=untrusted_cert,
            key_path=untrusted_key,
            require_tls13=True,
        )
        # Client context only trusts the official Local Development Root CA
        strict_client_ctx = create_tls_client_context(require_tls13=True)

        with self.assertRaises(ssl.SSLCertVerificationError):
            perform_tls_handshake_and_exchange(
                server_ctx=rogue_server_ctx,
                client_ctx=strict_client_ctx,
                message=b"HELLO",
                server_hostname="localhost",
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)
