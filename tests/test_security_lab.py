"""
Comprehensive Test Suite for the Admin Cybersecurity Attack Simulation & Defence Centre.

Verifies:
1. Strict backend RBAC (HTTP 403 for customers & unauthenticated guests on all pages & APIs).
2. Navigation isolation (customers never see the new menu; admins see it in Admin Dashboard).
3. CSRF enforcement on state-changing Security Lab POST endpoints.
4. Real backend cryptographic execution & verification across all 8 independent modules.
5. Zero private key or plaintext password exposure in API responses or logs.
6. Accurate recording of both MITIGATED and DEFENCE_FAILED outcomes.
7. Live SOC monitoring metrics & analytics matching persisted SQLite records.
8. Complete isolation from real e-commerce Orders/Transactions/Users & preservation of existing Crypto Lab.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from database.database import db
from models.order import Order
from models.product import Product
from models.security_lab import (
    AttackSimulationEvent,
    LabConsumedNonce,
    LabSyntheticTransaction,
)
from models.transaction import ConsumedNonce, SecurityLog, Transaction
from models.user import User


class SecurityLabTestBase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        admin = User(name='SOC Admin', email='soc_admin@test.com', role='admin')
        admin.set_password('Admin@12345')
        admin.ensure_client_public_key()

        customer = User(name='Regular Customer', email='regular_customer@test.com', role='customer')
        customer.set_password('Customer@123')
        customer.ensure_client_public_key()

        prod = Product(
            name='Test Secure Item',
            description='Synthetic test product',
            price=1999.00,
            category='Electronics',
            stock=25,
        )
        db.session.add_all([admin, customer, prod])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self, email, password):
        return self.client.post(
            '/login',
            data={'email': email, 'password': password},
            follow_redirects=True,
        )

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)


class TestSecurityLabRBACAndIsolation(SecurityLabTestBase):
    """Verify strict RBAC (HTTP 403), navigation isolation, and CSRF enforcement."""

    def test_guest_cannot_access_lab_page_or_apis(self):
        endpoints = [
            ('GET', '/admin/security-lab'),
            ('GET', '/admin/security-lab/api/overview'),
            ('GET', '/admin/security-lab/api/modules'),
            ('GET', '/admin/security-lab/api/logs'),
            ('POST', '/admin/security-lab/api/simulate'),
            ('POST', '/admin/security-lab/api/module6/generate'),
            ('POST', '/admin/security-lab/api/module6/tamper-execute'),
            ('POST', '/admin/security-lab/api/module7/generate-and-submit'),
            ('POST', '/admin/security-lab/api/module7/replay'),
        ]
        for method, path in endpoints:
            if method == 'GET':
                resp = self.client.get(path)
            else:
                resp = self.client.post(path, json={})
            self.assertEqual(resp.status_code, 403, f"Expected 403 for guest on {method} {path}")

    def test_customer_cannot_see_menu_and_gets_403_on_all_endpoints(self):
        self.login('regular_customer@test.com', 'Customer@123')

        # Customer pages must never render the Admin Attack & Defence Lab menu
        for page in ('/', '/products', '/orders', '/cart'):
            resp = self.client.get(page)
            self.assertEqual(resp.status_code, 200)
            self.assertNotIn(b'Cybersecurity Attack &amp; Defence Lab', resp.data)
            self.assertNotIn(b'/admin/security-lab', resp.data)

        # Every lab route & API must return HTTP 403 for customers
        resp_page = self.client.get('/admin/security-lab')
        self.assertEqual(resp_page.status_code, 403)

        for path in ('/admin/security-lab/api/overview', '/admin/security-lab/api/modules', '/admin/security-lab/api/logs'):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 403)
            self.assertFalse(r.get_json()['success'])

        for path in (
            '/admin/security-lab/api/simulate',
            '/admin/security-lab/api/module6/generate',
            '/admin/security-lab/api/module6/tamper-execute',
            '/admin/security-lab/api/module7/generate-and-submit',
            '/admin/security-lab/api/module7/replay',
        ):
            r = self.client.post(path, json={'module_key': 'aes_gcm', 'attack_key': 'ciphertext_tampering'})
            self.assertEqual(r.status_code, 403)
            self.assertFalse(r.get_json()['success'])

        # ACCESS_DENIED events must be recorded in SecurityLog
        denied_count = SecurityLog.query.filter_by(event_type='ACCESS_DENIED').count()
        self.assertGreaterEqual(denied_count, 6)

    def test_admin_sees_menu_and_existing_crypto_lab_is_preserved(self):
        self.login('soc_admin@test.com', 'Admin@12345')

        dash = self.client.get('/admin/')
        self.assertEqual(dash.status_code, 200)
        self.assertIn(b'Cybersecurity Attack &amp; Defence Lab', dash.data)
        self.assertIn(b'/admin/security-lab', dash.data)
        self.assertIn(b'/admin/crypto-demo', dash.data)

        # Existing Crypto Lab must remain fully functional
        crypto_lab = self.client.get('/admin/crypto-demo')
        self.assertEqual(crypto_lab.status_code, 200)
        self.assertIn(b'Hybrid Cryptography &amp; Security Demonstration Lab', crypto_lab.data)

        # New Security Lab page loads cleanly
        sec_lab = self.client.get('/admin/security-lab')
        self.assertEqual(sec_lab.status_code, 200)
        self.assertIn(b'Cybersecurity Attack Simulation &amp; Defence Centre', sec_lab.data)
        self.assertIn(b'AES-256-GCM', sec_lab.data)
        self.assertIn(b'RSA-OAEP-3072', sec_lab.data)
        self.assertIn(b'RSA-PSS', sec_lab.data)
        self.assertIn(b'PBKDF2-SHA256', sec_lab.data)
        self.assertIn(b'HMAC-SHA256', sec_lab.data)
        self.assertIn(b'Ciphertext Tampering Defence', sec_lab.data)
        self.assertIn(b'Nonce Replay Attack Defence', sec_lab.data)
        self.assertIn(b'Expired Timestamp Attack Defence', sec_lab.data)

    def test_csrf_enforced_on_security_lab_post_api(self):
        csrf_app = create_app('testing')
        csrf_app.config['WTF_CSRF_ENABLED'] = True
        with csrf_app.app_context():
            db.create_all()
            admin = User(name='CSRF Admin', email='csrf_admin@test.com', role='admin')
            admin.set_password('Admin@12345')
            db.session.add(admin)
            db.session.commit()

            c = csrf_app.test_client()
            # Login with CSRF token
            login_page = c.get('/login')
            html = login_page.data.decode('utf-8')
            marker = 'name="csrf_token" value="'
            start = html.index(marker) + len(marker)
            token = html[start:html.index('"', start)]
            c.post('/login', data={'email': 'csrf_admin@test.com', 'password': 'Admin@12345', 'csrf_token': token})

            # POST without CSRF token must be rejected with 400
            r_no_csrf = c.post('/admin/security-lab/api/simulate', json={'module_key': 'aes_gcm', 'attack_key': 'ciphertext_tampering'})
            self.assertEqual(r_no_csrf.status_code, 400)

            # POST with valid X-CSRFToken header succeeds
            lab_html = c.get('/admin/security-lab').data.decode('utf-8')
            m2 = 'name="csrf-token" content="'
            s2 = lab_html.index(m2) + len(m2)
            lab_csrf = lab_html[s2:lab_html.index('"', s2)]
            r_ok = c.post(
                '/admin/security-lab/api/simulate',
                json={'module_key': 'aes_gcm', 'attack_key': 'ciphertext_tampering'},
                headers={'X-CSRFToken': lab_csrf},
            )
            self.assertEqual(r_ok.status_code, 200)
            self.assertTrue(r_ok.get_json()['success'])
            db.session.remove()
            db.drop_all()


class TestAllEightSecurityModules(SecurityLabTestBase):
    """Execute real backend simulations across all 8 cryptographic security modules."""

    def setUp(self):
        super().setUp()
        self.login('soc_admin@test.com', 'Admin@12345')

    def _assert_no_secrets_leaked(self, resp_bytes: bytes):
        text = resp_bytes.decode('utf-8', errors='ignore')
        self.assertNotIn('BEGIN PRIVATE KEY', text)
        self.assertNotIn('BEGIN RSA PRIVATE KEY', text)
        self.assertNotIn('password123', text)

    def test_module1_aes_gcm_all_four_attacks(self):
        attacks = [
            'data_theft_interception',
            'ciphertext_tampering',
            'auth_tag_manipulation',
            'unauthorized_key_access',
        ]
        for atk in attacks:
            resp = self.client.post(
                '/admin/security-lab/api/simulate',
                json={'module_key': 'aes_gcm', 'attack_key': atk},
            )
            self.assertEqual(resp.status_code, 200)
            self._assert_no_secrets_leaked(resp.data)
            data = resp.get_json()
            sim = data['simulation']
            self.assertTrue(sim['detected'], f"AES attack {atk} should be detected")
            self.assertTrue(sim['blocked'], f"AES attack {atk} should be blocked")
            self.assertEqual(sim['final_result'], 'MITIGATED')
            self.assertTrue(sim['hmac_valid'])

    def test_module2_rsa_oaep_all_four_attacks(self):
        attacks = [
            'session_key_interception',
            'unauthorized_key_recovery',
            'encrypted_key_payload_manipulation',
            'key_mismatch_attack',
        ]
        for atk in attacks:
            resp = self.client.post(
                '/admin/security-lab/api/simulate',
                json={'module_key': 'rsa_oaep', 'attack_key': atk},
            )
            self.assertEqual(resp.status_code, 200)
            self._assert_no_secrets_leaked(resp.data)
            sim = resp.get_json()['simulation']
            self.assertTrue(sim['detected'])
            self.assertTrue(sim['blocked'])
            self.assertEqual(sim['final_result'], 'MITIGATED')
            self.assertFalse(sim['evidence'].get('unwrap_succeeded', False))

    def test_module3_rsa_pss_all_four_attacks(self):
        attacks = [
            'signature_forgery',
            'signed_transaction_modification',
            'public_key_substitution',
            'invalid_signature_injection',
        ]
        for atk in attacks:
            resp = self.client.post(
                '/admin/security-lab/api/simulate',
                json={'module_key': 'rsa_pss', 'attack_key': atk},
            )
            self.assertEqual(resp.status_code, 200)
            self._assert_no_secrets_leaked(resp.data)
            sim = resp.get_json()['simulation']
            self.assertTrue(sim['detected'])
            self.assertTrue(sim['blocked'])
            self.assertEqual(sim['final_result'], 'MITIGATED')
            ev = sim['evidence']
            self.assertIn('original_transaction_hash', ev)
            self.assertIn('modified_transaction_hash', ev)
            self.assertTrue(ev['original_signature_verified'])
            self.assertFalse(ev['signature_valid'])
            self.assertIn('defence_response', ev)

    def test_module4_pbkdf2_all_scenarios_and_failed_defence_recording(self):
        # 1-3: Brute force, dictionary, rainbow table -> all MITIGATED
        for atk in ('brute_force_simulation', 'dictionary_attack_simulation', 'rainbow_table_demonstration'):
            resp = self.client.post(
                '/admin/security-lab/api/simulate',
                json={'module_key': 'pbkdf2', 'attack_key': atk},
            )
            self.assertEqual(resp.status_code, 200)
            self._assert_no_secrets_leaked(resp.data)
            sim = resp.get_json()['simulation']
            self.assertEqual(sim['final_result'], 'MITIGATED')
            self.assertTrue(sim['blocked'])

        # 4a: Weak password WITH policy enforced -> MITIGATED
        r_enforced = self.client.post(
            '/admin/security-lab/api/simulate',
            json={
                'module_key': 'pbkdf2',
                'attack_key': 'weak_password_testing',
                'options': {'weak_profile': 'common_word', 'enforce_policy': True},
            },
        )
        self.assertEqual(r_enforced.status_code, 200)
        self._assert_no_secrets_leaked(r_enforced.data)
        self.assertEqual(r_enforced.get_json()['simulation']['final_result'], 'MITIGATED')

        # 4b: Weak password WITHOUT policy enforced -> dictionary cracks synthetic hash -> DEFENCE_FAILED!
        r_failed = self.client.post(
            '/admin/security-lab/api/simulate',
            json={
                'module_key': 'pbkdf2',
                'attack_key': 'weak_password_testing',
                'options': {'weak_profile': 'common_word', 'enforce_policy': False},
            },
        )
        self.assertEqual(r_failed.status_code, 200)
        self._assert_no_secrets_leaked(r_failed.data)
        sim_fail = r_failed.get_json()['simulation']
        self.assertFalse(sim_fail['blocked'])
        self.assertEqual(sim_fail['final_result'], 'DEFENCE_FAILED')
        self.assertTrue(sim_fail['evidence']['cracked'])

        # Verify overview accurately counts failed defence attempt from persisted DB
        ov = self.client.get('/admin/security-lab/api/overview').get_json()
        self.assertEqual(ov['metrics']['total_attacks_simulated'], 5)
        self.assertEqual(ov['metrics']['attacks_blocked'], 4)
        self.assertEqual(ov['metrics']['failed_defence_attempts'], 1)
        self.assertEqual(ov['metrics']['mitigation_rate'], 80.0)

    def test_module5_hmac_sha256_all_four_attacks(self):
        attacks = [
            'message_tampering',
            'hmac_forgery',
            'invalid_auth_code_injection',
            'unauthorized_message_modification',
        ]
        for atk in attacks:
            resp = self.client.post(
                '/admin/security-lab/api/simulate',
                json={'module_key': 'hmac_sha256', 'attack_key': atk},
            )
            self.assertEqual(resp.status_code, 200)
            sim = resp.get_json()['simulation']
            self.assertTrue(sim['detected'])
            self.assertTrue(sim['blocked'])
            self.assertEqual(sim['final_result'], 'MITIGATED')
            self.assertTrue(sim['evidence']['constant_time_comparison'])
            self.assertFalse(sim['evidence']['hmac_valid'])

    def test_module6_interactive_ciphertext_tampering_preserves_original_record(self):
        # Step 1: Generate encrypted synthetic transaction
        r_gen = self.client.post(
            '/admin/security-lab/api/module6/generate',
            json={'item_name': 'Lab Audio DAC', 'amount_inr': 5499},
        )
        self.assertEqual(r_gen.status_code, 201)
        tx = r_gen.get_json()['transaction']
        lab_tx_id = tx['lab_tx_id']
        orig_ct = tx['ciphertext_b64']
        orig_sha = tx['original_ciphertext_sha256']

        # Step 2: Tamper selected byte & execute real AES-256-GCM decryption
        r_tamper = self.client.post(
            '/admin/security-lab/api/module6/tamper-execute',
            json={'lab_tx_id': lab_tx_id, 'byte_offset': 3, 'xor_mask': '0xAA'},
        )
        self.assertEqual(r_tamper.status_code, 200)
        sim = r_tamper.get_json()['simulation']
        self.assertEqual(sim['final_result'], 'MITIGATED')
        self.assertTrue(sim['blocked'])
        self.assertTrue(sim['evidence']['original_transaction_unchanged'])
        self.assertTrue(sim['evidence']['original_record_hmac_valid'])

        # Confirm stored LabSyntheticTransaction is untouched in SQLite
        stored = LabSyntheticTransaction.query.filter_by(lab_tx_id=lab_tx_id).first()
        self.assertEqual(stored.ciphertext_b64, orig_ct)
        self.assertEqual(stored.original_ciphertext_sha256, orig_sha)

        # Honest check: submitting UNMODIFIED ciphertext passes decryption -> recorded as DEFENCE_FAILED (not fake green!)
        r_unmodified = self.client.post(
            '/admin/security-lab/api/module6/tamper-execute',
            json={'lab_tx_id': lab_tx_id, 'custom_tampered_b64': orig_ct},
        )
        self.assertEqual(r_unmodified.status_code, 200)
        self.assertEqual(r_unmodified.get_json()['simulation']['final_result'], 'DEFENCE_FAILED')

    def test_module7_nonce_replay_atomic_protection_and_isolation(self):
        # Step 1: Generate & submit legitimate transaction
        r_orig = self.client.post('/admin/security-lab/api/module7/generate-and-submit', json={})
        self.assertEqual(r_orig.status_code, 201)
        cap = r_orig.get_json()['captured']
        self.assertTrue(cap['nonce_consumed'])
        self.assertTrue(cap['signature_verified'])

        # Nonce persisted in isolated LabConsumedNonce, NOT polluting real ConsumedNonce
        self.assertEqual(LabConsumedNonce.query.filter_by(nonce=cap['original_nonce']).count(), 1)
        self.assertEqual(ConsumedNonce.query.filter_by(nonce=cap['original_nonce']).count(), 0)

        # Step 2: Replay exact captured request -> rejected!
        r_rep = self.client.post(
            '/admin/security-lab/api/module7/replay',
            json={'lab_tx_id': cap['lab_tx_id'], 'attack_key': 'captured_request_replay'},
        )
        self.assertEqual(r_rep.status_code, 200)
        sim = r_rep.get_json()['simulation']
        self.assertEqual(sim['final_result'], 'MITIGATED')
        self.assertTrue(sim['blocked'])
        self.assertEqual(sim['evidence']['original_nonce'], cap['original_nonce'])
        self.assertEqual(sim['evidence']['replay_attempts_rejected'], 1)
        self.assertEqual(sim['evidence']['replay_attempts_accepted'], 0)

        # Step 3: Concurrent burst replay -> all 5 duplicates rejected!
        r_burst = self.client.post(
            '/admin/security-lab/api/module7/replay',
            json={'lab_tx_id': cap['lab_tx_id'], 'attack_key': 'concurrent_replay_burst', 'burst_count': 5},
        )
        self.assertEqual(r_burst.status_code, 200)
        burst_sim = r_burst.get_json()['simulation']
        self.assertEqual(burst_sim['final_result'], 'MITIGATED')
        self.assertEqual(burst_sim['evidence']['replay_attempts_rejected'], 5)
        self.assertEqual(burst_sim['evidence']['replay_attempts_accepted'], 0)

    def test_module8_expired_timestamp_all_four_attacks(self):
        attacks = [
            'expired_request_replay',
            'old_transaction_submission',
            'timestamp_manipulation',
            'future_timestamp_injection',
        ]
        for atk in attacks:
            resp = self.client.post(
                '/admin/security-lab/api/simulate',
                json={'module_key': 'expired_timestamp', 'attack_key': atk},
            )
            self.assertEqual(resp.status_code, 200)
            sim = resp.get_json()['simulation']
            self.assertTrue(sim['detected'])
            self.assertTrue(sim['blocked'])
            self.assertEqual(sim['final_result'], 'MITIGATED')
            ev = sim['evidence']
            self.assertIn('request_timestamp', ev)
            self.assertIn('server_timestamp', ev)
            self.assertIn('allowed_validity_window', ev)
            self.assertIn('time_difference_seconds', ev)
            self.assertEqual(ev['validation_result'], 'REJECTED')
            self.assertTrue(ev['combined_with_nonce_guard'])

    def test_monitoring_metrics_match_database_and_ecommerce_tables_untouched(self):
        # Execute 3 simulations across different modules
        self.client.post('/admin/security-lab/api/simulate', json={'module_key': 'aes_gcm', 'attack_key': 'ciphertext_tampering'})
        self.client.post('/admin/security-lab/api/simulate', json={'module_key': 'rsa_pss', 'attack_key': 'signature_forgery'})
        self.client.post('/admin/security-lab/api/simulate', json={'module_key': 'hmac_sha256', 'attack_key': 'hmac_forgery'})

        ov = self.client.get('/admin/security-lab/api/overview').get_json()
        db_total = AttackSimulationEvent.query.count()
        db_blocked = AttackSimulationEvent.query.filter_by(final_result='MITIGATED', blocked=True).count()
        db_failed = AttackSimulationEvent.query.filter_by(final_result='DEFENCE_FAILED').count()

        self.assertEqual(db_total, 3)
        self.assertEqual(ov['metrics']['total_attacks_simulated'], db_total)
        self.assertEqual(ov['metrics']['attacks_blocked'], db_blocked)
        self.assertEqual(ov['metrics']['failed_defence_attempts'], db_failed)
        self.assertEqual(ov['metrics']['detection_rate'], 100.0)
        self.assertEqual(ov['metrics']['mitigation_rate'], 100.0)
        self.assertEqual(len(ov['event_logs']), 3)
        self.assertEqual(sum(ov['analytics']['by_module']['counts']), 3)

        # Event detail endpoint works & HMAC is valid
        first_uid = ov['event_logs'][0]['event_uid']
        detail = self.client.get(f'/admin/security-lab/api/events/{first_uid}').get_json()
        self.assertTrue(detail['success'])
        self.assertTrue(detail['event']['hmac_valid'])

        # Real e-commerce Order & Transaction tables remain 100% untouched!
        self.assertEqual(Order.query.count(), 0)
        self.assertEqual(Transaction.query.count(), 0)


class TestTopNavbarAndISTTimezoneDisplay(SecurityLabTestBase):
    """Verify top navigation bar placement and consistent Asia/Kolkata (IST) display."""

    def test_top_navbar_shows_lab_beside_crypto_lab_for_admin_only(self):
        # 1. Guest must not see it in navbar
        guest_home = self.client.get('/').data.decode('utf-8')
        self.assertNotIn('Cybersecurity Attack &amp; Defence Lab', guest_home)

        # 2. Customer must not see it in navbar
        self.login('regular_customer@test.com', 'Customer@123')
        cust_home = self.client.get('/').data.decode('utf-8')
        self.assertNotIn('Cybersecurity Attack &amp; Defence Lab', cust_home)
        self.assertNotIn('/admin/security-lab', cust_home)
        self.logout()

        # 3. Admin must see it in the TOP NAVBAR directly beside Crypto Lab on all pages
        self.login('soc_admin@test.com', 'Admin@12345')
        for page in ('/', '/products', '/admin/', '/admin/crypto-demo', '/admin/security-lab'):
            resp = self.client.get(page)
            self.assertEqual(resp.status_code, 200)
            html = resp.data.decode('utf-8')
            nav_start = html.index('<nav class="navbar')
            nav_end = html.index('</nav>', nav_start)
            navbar_html = html[nav_start:nav_end]

            idx_crypto = navbar_html.index('Crypto Lab')
            idx_attack_lab = navbar_html.index('Cybersecurity Attack &amp; Defence Lab')
            self.assertGreater(idx_attack_lab, idx_crypto, f"Expected Attack Lab after Crypto Lab in top navbar on {page}")
            self.assertIn('href="/admin/security-lab"', navbar_html)

    def test_ist_timezone_conversion_and_no_double_shift(self):
        from datetime import datetime, timezone
        from services.timezone_utils import IST_TZ, format_ist

        # 16:31:06 UTC == 22:01:06 IST (10:01:06 PM IST)
        naive_utc = datetime(2026, 11, 25, 16, 31, 6)
        aware_utc = datetime(2026, 11, 25, 16, 31, 6, tzinfo=timezone.utc)
        already_ist = datetime(2026, 11, 25, 22, 1, 6, tzinfo=IST_TZ)
        iso_utc = '2026-11-25T16:31:06+00:00'
        iso_ist = '2026-11-25T22:01:06+05:30'
        formatted = '25 Nov 2026, 10:01:06 PM IST'

        expected = '25 Nov 2026, 10:01:06 PM IST'
        self.assertEqual(format_ist(naive_utc), expected)
        self.assertEqual(format_ist(aware_utc), expected)
        self.assertEqual(format_ist(already_ist), expected)
        self.assertEqual(format_ist(iso_utc), expected)
        self.assertEqual(format_ist(iso_ist), expected)
        self.assertEqual(format_ist(formatted), expected)

    def test_ist_timestamps_across_security_pages_and_expired_timestamp_attack(self):
        import re
        from datetime import datetime, timezone

        self.login('soc_admin@test.com', 'Admin@12345')

        # Execute an expired timestamp attack (15 minutes old)
        r_exp = self.client.post(
            '/admin/security-lab/api/simulate',
            json={
                'module_key': 'expired_timestamp',
                'attack_key': 'expired_request_replay',
                'options': {'offset_seconds': 900},
            },
        )
        self.assertEqual(r_exp.status_code, 200)
        sim = r_exp.get_json()['simulation']
        self.assertEqual(sim['final_result'], 'MITIGATED')
        self.assertTrue(sim['blocked'])

        ist_pattern = re.compile(r'^\d{2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2}:\d{2} (AM|PM) IST$')
        self.assertRegex(sim['executed_at'], ist_pattern)
        self.assertTrue(sim['executed_at_utc'].endswith('Z'))

        ev = sim['evidence']
        self.assertRegex(ev['request_timestamp'], ist_pattern)
        self.assertRegex(ev['server_timestamp'], ist_pattern)
        self.assertNotEqual(ev['request_timestamp'], ev['server_timestamp'])
        self.assertGreaterEqual(ev['time_difference_seconds'], 895)
        self.assertIn('request_timestamp_utc', ev)
        self.assertIn('server_timestamp_utc', ev)

        # Verify database still stores UTC (within 30 seconds of current UTC)
        db_ev = AttackSimulationEvent.query.first()
        now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        self.assertLess(abs((now_utc_naive - db_ev.executed_at).total_seconds()), 30)

        # Verify API overview returns IST timestamps and IST chart labels
        ov = self.client.get('/admin/security-lab/api/overview').get_json()
        self.assertRegex(ov['server_time_ist'], ist_pattern)
        self.assertRegex(ov['event_logs'][0]['executed_at'], ist_pattern)
        self.assertTrue(ov['analytics']['activity_over_time']['labels'][0].endswith(' IST'))

        # Verify Admin Security Logs, Security Dashboard, and Admin Dashboard display IST
        for path in ('/admin/security-logs', '/admin/security-dashboard', '/admin/'):
            html = self.client.get(path).data.decode('utf-8')
            self.assertIn(' IST', html, f"Expected IST formatted timestamp on {path}")
        logs_html = self.client.get('/admin/security-logs').data.decode('utf-8')
        self.assertIn('Timestamp (IST)', logs_html)


if __name__ == '__main__':
    unittest.main()
