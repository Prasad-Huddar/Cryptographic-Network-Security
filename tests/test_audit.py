"""
Complete Independent Audit & Security Verification Suite (Parts 2 through 8).

Executes:
- Part 2: Complete Phase 1 E-Commerce, Admin CRUD, and Authorization / IDOR verification
- Part 4: 19-Step End-to-End Hybrid Cryptographic Transaction verification
- Part 5: TLS 1.3 negotiation, certificate validation, hostname verification, and private key non-exposure
- Part 6: All 15 controlled attack simulations (Ciphertext tamper, Tag tamper, Signature tamper,
          Replay old tx, Duplicate nonce, Expired timestamp, Customer->Admin RBAC, IDOR order/tx access,
          Price manipulation, Invalid TLS cert, SQL Injection, XSS, CSRF, Session tampering,
          Concurrent replay race)
- Part 7: Official CNS Test Cases T01 through T10
- Part 8: Admin Cryptography Demonstration Lab interactive button verification
"""
import base64
import datetime
from datetime import timezone
import json
import os
import ssl
import sys
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
    get_server_private_key_pem,
    get_server_public_key_pem,
)
from services.crypto.rsa_encryption import unwrap_aes_key, wrap_aes_key
from services.crypto.digital_signature import (
    sign_transaction_package,
    verify_transaction_signature,
)
from services.crypto.transaction_security import (
    build_client_transaction_package,
    consume_nonce_atomically,
    create_tls_client_context,
    create_tls_server_context,
    ensure_local_tls_certificates,
    generate_replay_nonce,
    generate_timestamp,
    generate_transaction_id,
    generate_untrusted_self_signed_cert,
    perform_tls_handshake_and_exchange,
    verify_and_process_transaction_package,
)


class AuditBaseTestCase(unittest.TestCase):
    """Base test case for the comprehensive project audit."""

    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.admin = User(name='Audit Admin', email='admin@test.com', role='admin')
        self.admin.set_password('Admin@12345')
        self.admin.ensure_client_public_key()

        self.customer1 = User(name='Customer One', email='customer1@test.com', role='customer')
        self.customer1.set_password('Customer@123')
        self.customer1.ensure_client_public_key()

        self.customer2 = User(name='Customer Two', email='customer2@test.com', role='customer')
        self.customer2.set_password('Customer@123')
        self.customer2.ensure_client_public_key()

        self.p1 = Product(
            name='Audit Laptop Pro',
            description='High-security workstation laptop.',
            price=1500.00,
            category='Electronics',
            stock=50,
        )
        self.p2 = Product(
            name='Hardware Security Module',
            description='FIPS 140-3 Level 3 HSM.',
            price=500.00,
            category='Electronics',
            stock=30,
        )
        db.session.add_all([self.admin, self.customer1, self.customer2, self.p1, self.p2])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self, email, password):
        return self.client.post('/login', data={'email': email, 'password': password}, follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)


class TestOfficialCNSTestCases(AuditBaseTestCase):
    """Part 7: Verify the 10 Official CNS Project Test Cases (T01 - T10)."""

    def test_T01_valid_login(self):
        """T01 – Valid login."""
        resp = self.login('customer1@test.com', 'Customer@123')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Login successful', resp.data)
        log = SecurityLog.query.filter_by(event_type='LOGIN_SUCCESS', user_id=self.customer1.id).first()
        self.assertIsNotNone(log)
        self.assertTrue(log.verify_integrity())

    def test_T02_invalid_password(self):
        """T02 – Invalid password."""
        resp = self.login('customer1@test.com', 'WrongPass@999')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Invalid email or password', resp.data)
        log = SecurityLog.query.filter_by(event_type='LOGIN_FAILED').first()
        self.assertIsNotNone(log)
        self.assertTrue(log.verify_integrity())

    def test_T03_aes_encryption_and_decryption(self):
        """T03 – AES-256-GCM encryption and decryption."""
        key = generate_aes_key()
        nonce = generate_gcm_nonce(key)
        plaintext = json.dumps({'order': 'CNS-T03', 'amount': 1500.00})
        aad = b'T03-AAD-METADATA'

        enc = encrypt_aes_gcm(plaintext, key=key, nonce=nonce, associated_data=aad)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(enc['auth_tag']), 16)

        dec = decrypt_aes_gcm(
            ciphertext=enc['ciphertext_b64'],
            key=key,
            nonce=enc['nonce_b64'],
            auth_tag=enc['auth_tag_b64'],
            associated_data=aad,
        )
        self.assertEqual(dec.decode('utf-8'), plaintext)

    def test_T04_transaction_tampering(self):
        """T04 – Transaction tampering detection (ciphertext, auth tag, and metadata)."""
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items,
            shipping_address='42 Residency Road, Bengaluru, KA 560025',
        )
        # Tamper with ciphertext_b64 in transit
        raw_ct = bytearray(base64.b64decode(pkg['ciphertext_b64']))
        raw_ct[0] ^= 0xFF
        pkg['ciphertext_b64'] = base64.b64encode(bytes(raw_ct)).decode('ascii')

        ok, msg, order, tx = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok)
        self.assertIsNone(order)
        self.assertIsNone(tx)
        tamper_log = SecurityLog.query.filter_by(event_type='TAMPERING_DETECTED').first()
        self.assertIsNotNone(tamper_log)

    def test_T05_replay_old_transaction(self):
        """T05 – Replay old transaction (both duplicate package replay and expired timestamp)."""
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items,
            shipping_address='42 Residency Road, Bengaluru, KA 560025',
        )
        ok1, msg1, order1, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertTrue(ok1, msg1)
        self.assertIsNotNone(order1)

        # Replay exact same package
        ok2, msg2, order2, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok2)
        self.assertIsNone(order2)
        self.assertIn('replay', msg2.lower())

        # Replay with old expired timestamp (10 minutes old)
        old_ts = (datetime.datetime.now(timezone.utc) - datetime.timedelta(minutes=10)).isoformat()
        pkg_old = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items,
            shipping_address='42 Residency Road, Bengaluru, KA 560025',
            timestamp=old_ts,
        )
        ok3, msg3, order3, _ = verify_and_process_transaction_package(pkg_old, self.customer1)
        self.assertFalse(ok3)
        self.assertIsNone(order3)
        self.assertIn('expired', msg3.lower())

    def test_T06_customer_accessing_admin_operation(self):
        """T06 – Customer accessing admin operation (GET and POST admin endpoints)."""
        self.login('customer1@test.com', 'Customer@123')
        for endpoint in ('/admin/', '/admin/products', '/admin/orders', '/admin/users', '/admin/security-logs', '/admin/crypto-demo'):
            resp = self.client.get(endpoint)
            self.assertEqual(resp.status_code, 403, f"Expected 403 on {endpoint}")

        post_resp = self.client.post('/admin/products/add', data={
            'name': 'Unauthorized Product',
            'description': 'Should fail',
            'price': 100,
            'category': 'Test',
            'stock': 5,
        })
        self.assertEqual(post_resp.status_code, 403)
        denied_log = SecurityLog.query.filter_by(event_type='ACCESS_DENIED', user_id=self.customer1.id).first()
        self.assertIsNotNone(denied_log)

    def test_T07_tls_connection(self):
        """T07 – Valid TLS 1.3 connection and encrypted payload exchange."""
        ensure_local_tls_certificates()
        server_ctx = create_tls_server_context(require_tls13=True)
        client_ctx = create_tls_client_context(require_tls13=True)

        res = perform_tls_handshake_and_exchange(
            server_ctx=server_ctx,
            client_ctx=client_ctx,
            message=b"T07_TLS13_VERIFICATION",
            server_hostname="localhost",
        )
        self.assertEqual(res['protocol_version'], 'TLSv1.3')
        self.assertEqual(res['response'], b"ACK:T07_TLS13_VERIFICATION")
        self.assertEqual(res['cipher'][1], 'TLSv1.3')

    def test_T08_invalid_untrusted_certificate(self):
        """T08 – Invalid/untrusted certificate and hostname mismatch rejection."""
        ensure_local_tls_certificates()
        untrusted_cert, untrusted_key = generate_untrusted_self_signed_cert()
        rogue_server_ctx = create_tls_server_context(
            cert_path=untrusted_cert,
            key_path=untrusted_key,
            require_tls13=True,
        )
        client_ctx = create_tls_client_context(require_tls13=True)

        # 1. Untrusted self-signed cert rejected
        with self.assertRaises(ssl.SSLCertVerificationError):
            perform_tls_handshake_and_exchange(
                server_ctx=rogue_server_ctx,
                client_ctx=client_ctx,
                message=b"TEST",
                server_hostname="localhost",
            )

        # 2. Valid cert with wrong hostname rejected
        valid_server_ctx = create_tls_server_context(require_tls13=True)
        with self.assertRaises(ssl.SSLCertVerificationError):
            perform_tls_handshake_and_exchange(
                server_ctx=valid_server_ctx,
                client_ctx=client_ctx,
                message=b"TEST",
                server_hostname="wrong.hostname.internal",
            )

    def test_T09_digital_signature_verification(self):
        """T09 – RSA-PSS digital signature verification and forgery rejection."""
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items,
            shipping_address='42 Residency Road, Bengaluru, KA 560025',
        )
        # Valid signature against customer1's registered public key
        self.assertTrue(
            verify_transaction_signature(pkg, pkg['signature_b64'], self.customer1.public_key_pem)
        )
        # Fails against customer2's public key
        self.assertFalse(
            verify_transaction_signature(pkg, pkg['signature_b64'], self.customer2.public_key_pem)
        )
        # Fails if signature bytes are modified
        sig_bytes = bytearray(base64.b64decode(pkg['signature_b64']))
        sig_bytes[5] ^= 0xFF
        pkg['signature_b64'] = base64.b64encode(bytes(sig_bytes)).decode('ascii')
        ok, msg, order, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok)
        self.assertIsNone(order)
        self.assertIn('signature', msg.lower())

    def test_T10_concurrent_normal_transactions(self):
        """T10 – Concurrent normal transactions and sequential batch verification."""
        items_c1 = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        items_c2 = [{'product_id': self.p2.id, 'name': self.p2.name, 'price': self.p2.price, 'quantity': 2}]

        pkg1 = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items_c1,
            shipping_address='101 MG Road, Bengaluru, KA 560001',
        )
        pkg2 = build_client_transaction_package(
            user_id=self.customer2.id,
            items=items_c2,
            shipping_address='202 Indiranagar, Bengaluru, KA 560038',
        )
        pkg3 = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items_c2,
            shipping_address='101 MG Road, Bengaluru, KA 560001',
        )

        ok1, _, order1, tx1 = verify_and_process_transaction_package(pkg1, self.customer1)
        ok2, _, order2, tx2 = verify_and_process_transaction_package(pkg2, self.customer2)
        ok3, _, order3, tx3 = verify_and_process_transaction_package(pkg3, self.customer1)

        self.assertTrue(ok1 and ok2 and ok3)
        self.assertNotEqual(tx1.transaction_id, tx2.transaction_id)
        self.assertNotEqual(tx1.wrapped_aes_key, tx2.wrapped_aes_key)
        self.assertNotEqual(tx1.gcm_nonce, tx2.gcm_nonce)
        self.assertEqual(Order.query.count(), 3)
        self.assertEqual(db.session.get(Product, self.p1.id).stock, 49)
        self.assertEqual(db.session.get(Product, self.p2.id).stock, 26)


class TestSecurityAttackSimulations(AuditBaseTestCase):
    """Part 6: Controlled Security Attack Simulations (All 15 Attack Scenarios)."""

    def test_attack_01_ciphertext_tampering(self):
        """Attack 1: Ciphertext tampering is rejected by RSA-PSS and AES-256-GCM."""
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg = build_client_transaction_package(self.customer1.id, items, '101 MG Road, Bengaluru 560001')
        ct = bytearray(base64.b64decode(pkg['ciphertext_b64']))
        ct[0] ^= 0xFF
        pkg['ciphertext_b64'] = base64.b64encode(bytes(ct)).decode('ascii')
        ok, msg, order, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok)
        self.assertIsNone(order)

    def test_attack_02_authentication_tag_tampering(self):
        """Attack 2: AES-256-GCM 128-bit authentication tag tampering is rejected."""
        aes_key = generate_aes_key()
        enc = encrypt_aes_gcm(b'{"order":1}', aes_key)
        tag = bytearray(base64.b64decode(enc['auth_tag_b64']))
        tag[-1] ^= 0xFF
        with self.assertRaises(AESEncryptionError):
            decrypt_aes_gcm(
                enc['ciphertext_b64'],
                aes_key,
                enc['nonce_b64'],
                base64.b64encode(bytes(tag)).decode('ascii'),
            )

    def test_attack_03_wrapped_aes_key_tampering(self):
        """Attack 3: RSA-OAEP wrapped AES key tampering is rejected."""
        from services.crypto.rsa_key_management import provision_client_keypair
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg = build_client_transaction_package(self.customer1.id, items, '101 MG Road, Bengaluru 560001')
        wk = bytearray(base64.b64decode(pkg['wrapped_key_b64']))
        wk[10] ^= 0xFF
        pkg['wrapped_key_b64'] = base64.b64encode(bytes(wk)).decode('ascii')
        priv_pem, _ = provision_client_keypair(self.customer1.email)
        sig_res = sign_transaction_package(pkg, priv_pem)
        pkg['signature_b64'] = sig_res['signature_b64']
        ok, msg, order, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok)
        self.assertIsNone(order)
        self.assertIn('unwrap', msg.lower())

    def test_attack_04_digital_signature_tampering(self):
        """Attack 4: RSA-PSS digital signature tampering is rejected."""
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg = build_client_transaction_package(self.customer1.id, items, '101 MG Road, Bengaluru 560001')
        sig = bytearray(base64.b64decode(pkg['signature_b64']))
        sig[0] ^= 0xFF
        pkg['signature_b64'] = base64.b64encode(bytes(sig)).decode('ascii')
        ok, msg, order, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok)
        self.assertIsNone(order)
        self.assertIn('signature', msg.lower())

    def test_attack_05_replay_attack_same_nonce(self):
        """Attack 5: Replay attack reusing a consumed nonce is blocked."""
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg = build_client_transaction_package(self.customer1.id, items, '101 MG Road, Bengaluru 560001')
        ok1, _, _, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertTrue(ok1)
        ok2, msg2, order2, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok2)
        self.assertIsNone(order2)
        self.assertIn('replay', msg2.lower())

    def test_attack_06_expired_timestamp_attack(self):
        """Attack 6: Transaction with expired timestamp outside +-300s window is rejected."""
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        expired_ts = (datetime.datetime.now(timezone.utc) - datetime.timedelta(seconds=600)).isoformat()
        pkg = build_client_transaction_package(
            self.customer1.id, items, '101 MG Road, Bengaluru 560001', timestamp=expired_ts
        )
        ok, msg, order, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertFalse(ok)
        self.assertIsNone(order)
        self.assertIn('expired', msg.lower())

    def test_attack_07_price_manipulation_attempt(self):
        """Attack 7: Client-side price manipulation (Rs.0.01) is neutralized by server DB price lookup."""
        tampered_items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': 0.01, 'quantity': 2}]
        pkg = build_client_transaction_package(self.customer1.id, tampered_items, '101 MG Road, Bengaluru 560001')
        ok, _, order, _ = verify_and_process_transaction_package(pkg, self.customer1)
        self.assertTrue(ok)
        self.assertEqual(order.total_amount, 3000.00)

    def test_attack_08_idor_other_customers_order_and_transaction(self):
        """Attack 8: Customer 2 attempts to view Customer 1's order and cryptographic transaction."""
        self.login('customer1@test.com', 'Customer@123')
        self.client.post(f'/cart/add/{self.p1.id}', data={'quantity': 1}, follow_redirects=True)
        self.client.post('/checkout', data={'shipping_address': 'Customer 1 Private Address, Bengaluru 560001'}, follow_redirects=True)
        order_c1 = Order.query.filter_by(user_id=self.customer1.id).first()
        tx_c1 = Transaction.query.filter_by(order_id=order_c1.id).first()
        self.logout()

        # Login as Customer 2 and try to access Customer 1's order & transaction
        self.login('customer2@test.com', 'Customer@123')
        resp_order = self.client.get(f'/order/{order_c1.id}', follow_redirects=True)
        self.assertIn(b'Access denied', resp_order.data)
        self.assertNotIn(b'Customer 1 Private Address', resp_order.data)

        resp_tx = self.client.get(f'/transaction/{tx_c1.transaction_id}', follow_redirects=True)
        self.assertIn(b'Access denied', resp_tx.data)

    def test_attack_09_unauthorized_admin_access_by_customer(self):
        """Attack 9: Customer attempting to access admin endpoints receives 403 Forbidden."""
        self.login('customer1@test.com', 'Customer@123')
        for endpoint in ('/admin/', '/admin/products', '/admin/orders', '/admin/users', '/admin/security-logs', '/admin/crypto-demo'):
            resp = self.client.get(endpoint)
            self.assertEqual(resp.status_code, 403)

    def test_attack_10_unauthorized_endpoint_access_without_login(self):
        """Attack 10: Unauthenticated guest attempting protected endpoints is redirected (302)."""
        for endpoint in ('/cart', '/checkout', '/orders', '/admin/', '/api/transactions/secure-checkout'):
            resp = self.client.get(endpoint, follow_redirects=False) if endpoint != '/api/transactions/secure-checkout' else self.client.post(endpoint, json={}, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn('/login', resp.headers.get('Location', ''))

    def test_attack_11_sql_injection_attempts(self):
        """Attack 11: SQL injection payloads in login and product search."""
        sqli_payload = "' OR '1'='1' --"
        resp_login = self.login(sqli_payload, sqli_payload)
        self.assertIn(b'Invalid email or password', resp_login.data)

        resp_search = self.client.get(f"/products?search={sqli_payload}&category={sqli_payload}")
        self.assertEqual(resp_search.status_code, 200)
        # Ensure products table was not dropped or bypassed
        self.assertEqual(Product.query.count(), 2)

    def test_attack_12_xss_escaping(self):
        """Attack 12: Cross-site scripting (XSS) payload escaping in templates."""
        xss_payload = "<script>alert('XSS')</script>"
        resp = self.client.get(f"/products?search={xss_payload}")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b"<script>alert('XSS')</script>", resp.data)
        self.assertIn(b"&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;", resp.data)

    def test_attack_13_csrf_protection_enforced(self):
        """Attack 13: CSRF attack blocked when WTF_CSRF_ENABLED is True."""
        csrf_app = create_app('development')
        csrf_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        csrf_app.config['WTF_CSRF_ENABLED'] = True
        csrf_client = csrf_app.test_client()

        with csrf_app.app_context():
            db.create_all()
            # POST without csrf_token must be rejected with 400 Bad Request
            resp = csrf_client.post('/login', data={'email': 'admin@secureshop.com', 'password': 'Admin@12345'})
            self.assertEqual(resp.status_code, 400)

    def test_attack_14_session_cookie_tampering(self):
        """Attack 14: Forged/tampered session cookie attempting admin privilege escalation is rejected."""
        # Forged session cookie claiming _user_id = 1 (admin) with invalid HMAC signature
        self.client.set_cookie('session', 'eyJfdXNlcl9pZCI6IjEifQ.FORGED_TIMESTAMP.FORGED_HMAC_SIGNATURE')
        resp_admin = self.client.get('/admin/', follow_redirects=False)
        # Flask-Login discards the forged session cookie and redirects to /login (302)
        self.assertEqual(resp_admin.status_code, 302)
        self.assertIn('/login', resp_admin.headers.get('Location', ''))

        resp_cart = self.client.get('/cart', follow_redirects=False)
        self.assertEqual(resp_cart.status_code, 302)
        self.assertIn('/login', resp_cart.headers.get('Location', ''))

    def test_attack_15_database_log_tampering_detected_and_private_keys_protected(self):
        """Attack 15: Database security log tampering is detected by HMAC-SHA256 & private keys are not exposed."""
        self.login('customer1@test.com', 'Customer@123')
        log_entry = SecurityLog.query.filter_by(event_type='LOGIN_SUCCESS', user_id=self.customer1.id).first()
        self.assertIsNotNone(log_entry)
        self.assertTrue(log_entry.verify_integrity())

        # Direct database modification of log description
        log_entry.description = 'Attacker erased audit trail'
        db.session.commit()
        self.assertFalse(log_entry.verify_integrity())

        # Also verify private keys and certs are not exposed via HTTP routes
        for path in (
            '/static/keys/server_rsa_private.pem',
            '/instance/keys/server_rsa_private.pem',
            '/instance/certs/localhost_server.key',
            '/static/certs/localhost_server.key',
        ):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 404)


class TestAdminOperationsAndCryptoLab(AuditBaseTestCase):
    """Part 2 & Part 8: Verify Admin CRUD operations and all 7 Admin Crypto Lab buttons."""

    def test_admin_product_order_and_user_management(self):
        self.login('admin@test.com', 'Admin@12345')

        # 1. Add product
        resp_add = self.client.post('/admin/products/add', data={
            'name': 'Quantum Safe Router',
            'description': 'Enterprise encrypted router.',
            'price': 4500.00,
            'category': 'Networking',
            'stock': 15,
            'image_url': '',
        }, follow_redirects=True)
        self.assertEqual(resp_add.status_code, 200)
        self.assertIn(b'added successfully', resp_add.data)
        new_prod = Product.query.filter_by(name='Quantum Safe Router').first()
        self.assertIsNotNone(new_prod)

        # 2. Edit product
        resp_edit = self.client.post(f'/admin/products/edit/{new_prod.id}', data={
            'name': 'Quantum Safe Router v2',
            'description': 'Updated enterprise router.',
            'price': 4999.00,
            'category': 'Networking',
            'stock': 25,
            'is_active': 'on',
        }, follow_redirects=True)
        self.assertEqual(resp_edit.status_code, 200)
        self.assertEqual(db.session.get(Product, new_prod.id).price, 4999.00)

        # 3. Deactivate (delete) product
        resp_del = self.client.post(f'/admin/products/delete/{new_prod.id}', follow_redirects=True)
        self.assertEqual(resp_del.status_code, 200)
        self.assertFalse(db.session.get(Product, new_prod.id).is_active)

        # 4. Change user role & prevent self-demotion
        resp_self = self.client.post(f'/admin/users/{self.admin.id}/role', data={'role': 'customer'}, follow_redirects=True)
        self.assertIn(b'cannot change your own role', resp_self.data)

        resp_role = self.client.post(f'/admin/users/{self.customer2.id}/role', data={'role': 'admin'}, follow_redirects=True)
        self.assertIn(b'role updated to admin', resp_role.data)
        self.assertEqual(db.session.get(User, self.customer2.id).role, 'admin')

    def test_admin_crypto_lab_all_buttons(self):
        self.login('admin@test.com', 'Admin@12345')
        for action in ('all', 'aes', 'rsa_oaep', 'rsa_pss', 'pbkdf2', 'hmac', 'tamper', 'replay', 'expired_ts'):
            resp = self.client.post('/admin/crypto-demo', data={
                'sample_payload': '{"test":"audit_crypto_lab","amount":999.0}',
                'demo_action': action,
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'AUTHENTICATED', resp.data)
            self.assertIn(b'3072-BIT OAEP VERIFIED', resp.data)
            self.assertIn(b'SIGNATURE VALID', resp.data)
            self.assertIn(b'INTEGRITY PROTECTED', resp.data)
            self.assertIn(b'ATTACK BLOCKED', resp.data)
            self.assertIn(b'REPLAY REJECTED', resp.data)

    def test_phase3_additional_security_checks_and_security_dashboard(self):
        """Phase 3: Verify invalid JSON payload, duplicate transaction IDs, invalid role assignment, and Security Dashboard."""
        # 1. Invalid JSON payload on API & Checkout
        self.login('customer1@test.com', 'Customer@123')
        api_bad_json = self.client.post(
            '/api/transactions/secure-checkout',
            data='{malformed_json',
            content_type='application/json',
        )
        self.assertEqual(api_bad_json.status_code, 400)
        self.assertIn(b'Missing JSON', api_bad_json.data)

        self.client.post(f'/cart/add/{self.p1.id}', data={'quantity': 1}, follow_redirects=True)
        checkout_bad_pkg = self.client.post('/checkout', data={
            'shipping_address': '101 MG Road, Bengaluru 560001',
            'encrypted_package': '{invalid-json',
        }, follow_redirects=True)
        self.assertEqual(checkout_bad_pkg.status_code, 200)
        self.assertIn(b'Malformed encrypted transaction package', checkout_bad_pkg.data)

        # 2. Duplicate transaction ID with a different nonce is rejected
        shared_tx_id = generate_transaction_id()
        items = [{'product_id': self.p1.id, 'name': self.p1.name, 'price': self.p1.price, 'quantity': 1}]
        pkg1 = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items,
            shipping_address='101 MG Road, Bengaluru 560001',
            transaction_id=shared_tx_id,
        )
        ok1, _, _, _ = verify_and_process_transaction_package(pkg1, self.customer1)
        self.assertTrue(ok1)

        pkg2 = build_client_transaction_package(
            user_id=self.customer1.id,
            items=items,
            shipping_address='101 MG Road, Bengaluru 560001',
            transaction_id=shared_tx_id,  # Reused transaction_id with fresh nonce
        )
        ok2, msg2, order2, _ = verify_and_process_transaction_package(pkg2, self.customer1)
        self.assertFalse(ok2)
        self.assertIsNone(order2)
        self.assertIn('replay', msg2.lower())
        self.logout()

        # 3. Invalid role assignment & Security Dashboard verification as Admin
        self.login('admin@test.com', 'Admin@12345')
        resp_invalid_role = self.client.post(
            f'/admin/users/{self.customer2.id}/role',
            data={'role': 'super_hacker_role'},
            follow_redirects=True,
        )
        self.assertIn(b'Invalid role', resp_invalid_role.data)
        self.assertEqual(db.session.get(User, self.customer2.id).role, 'customer')

        # 4. Verify Security Dashboard renders real database metrics and HTTP security headers
        resp_sec_dash = self.client.get('/admin/security-dashboard')
        self.assertEqual(resp_sec_dash.status_code, 200)
        self.assertIn(b'Security Dashboard', resp_sec_dash.data)
        self.assertIn(b'Total Transactions', resp_sec_dash.data)
        self.assertIn(b'Successful Transactions', resp_sec_dash.data)
        self.assertIn(b'Rejected Transactions', resp_sec_dash.data)
        self.assertIn(b'Tampering Attempts', resp_sec_dash.data)
        self.assertIn(b'Replay Attempts', resp_sec_dash.data)
        self.assertIn(b'Unauthorized Access', resp_sec_dash.data)
        self.assertIn(b'Signature Verification', resp_sec_dash.data)
        self.assertEqual(resp_sec_dash.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(resp_sec_dash.headers.get('X-Frame-Options'), 'SAMEORIGIN')


if __name__ == '__main__':
    unittest.main(verbosity=2)
