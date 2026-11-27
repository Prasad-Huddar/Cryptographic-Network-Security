# SECURITY AUDIT CHECKLIST – SECURE E-COMMERCE TRANSACTION SYSTEM

**Project:** Secure E-Commerce Transaction System Using Hybrid Cryptography and TLS  
**Audit Date:** 2026-11-15  
**Scope:** Phase 1 (Core E-Commerce & Access Control) & Phase 2 (Hybrid Cryptography & TLS 1.3 Security)  
**Allowed Status Values:** `PASS` | `FAIL` | `NOT TESTED` | `PARTIAL`

---

## PART 1: Codebase & Architecture Inspection

| # | Audit Check | Target File(s) | Status | Verification Evidence |
|---|-------------|----------------|--------|-----------------------|
| 1.1 | Application factory, HTTPS listener, and seeding | `app.py` | `PASS` | `create_app()`, `seed_database()`, dual HTTP (`5000`) & TLS 1.3 HTTPS (`5443`) server threads verified. |
| 1.2 | Environment configuration & security settings | `config.py` | `PASS` | `PBKDF2_ITERATIONS = 260000`, `TRANSACTION_TIMESTAMP_TOLERANCE_SECONDS = 300`, `HttpOnly`, `SameSite=Lax`, SQLite busy timeout (`30s`) verified. |
| 1.3 | Dependencies pinned and installed | `requirements.txt` | `PASS` | `Flask==3.1.0`, `Flask-SQLAlchemy==3.1.1`, `Flask-Login==0.6.3`, `Flask-WTF==1.2.2`, `cryptography==44.0.0`, `pytest==8.3.4` verified in `venv`. |
| 1.4 | Database initialization & models | `database/db.py`, `models/` | `PASS` | `User`, `Product`, `CartItem`, `Order`, `OrderItem`, `Transaction`, `ConsumedNonce`, `SecurityLog` relationships & constraints verified. |
| 1.5 | Route blueprints & RBAC decorators | `routes/auth.py`, `routes/shop.py`, `routes/cart.py`, `routes/admin.py` | `PASS` | `@login_required`, `@admin_required`, safe redirect validation (`_is_safe_redirect_url`, `_safe_next_url`), and defensive numeric parsing verified. |
| 1.6 | Cryptographic service modules | `services/crypto/` (8 modules) | `PASS` | `__init__.py`, `aes_encryption.py`, `rsa_key_management.py`, `rsa_encryption.py`, `digital_signature.py`, `integrity.py`, `transaction_security.py`, `key_storage.py` all implemented and active. |
| 1.7 | Jinja2 templates & static assets | `templates/`, `static/` | `PASS` | All 15 templates render cleanly with auto-escaping; `static/css/style.css`, `static/js/main.js`, `static/images/placeholder.png` present. |
| 1.8 | Automated test suites | `tests/test_app.py`, `tests/test_phase2_crypto.py`, `tests/test_audit.py` | `PASS` | 84 total automated tests (35 Phase 1 + 22 Phase 2 + 27 Audit tests) all passing (`0` failures). |
| 1.9 | Project & cryptography documentation | `README.md`, `CRYPTOGRAPHY_DOCUMENTATION.md` | `PASS` | Mathematical foundations, architecture diagrams, key lifecycle, and security guarantees documented accurately. |

---

## PART 2: Phase 1 E-Commerce & Authorization Verification

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 2.1 | User registration with automatic RSA-3072 client keypair provisioning | `PASS` | Verified in `test_registration_success`, `test_T01_valid_encrypted_signed_checkout_transaction`, and live browser audit. |
| 2.2 | User login (valid credentials) & session persistence | `PASS` | Verified for `admin@secureshop.com` and `customer@secureshop.com`; logs `LOGIN_SUCCESS`. |
| 2.3 | Invalid login rejection & audit logging | `PASS` | Wrong email/password returns error alert and logs `LOGIN_FAILED` with `FAILURE` status. |
| 2.4 | Password hashing at rest (never plaintext) | `PASS` | Stored format `pbkdf2:sha256:260000$<salt_hex>$<hash_hex>` verified in `users` table. |
| 2.5 | Logout & session termination | `PASS` | Clears session cookie and logs `LOGOUT`. |
| 2.6 | Home page, product catalogue, category filter & search | `PASS` | Verified via `GET /`, `GET /products?category=...`, `GET /products?search=...`. |
| 2.7 | Product details page | `PASS` | Verified via `GET /product/<id>` and `404` on non-existent product ID. |
| 2.8 | Add to cart, update quantity, remove from cart, stock cap enforcement | `PASS` | Verified via `/cart/add/<id>`, `/cart/update/<item_id>`, `/cart/remove/<item_id>`. |
| 2.9 | Checkout, order creation, order history & order status | `PASS` | Verified via `POST /checkout`, `GET /orders`, `GET /order/<id>`. |
| 2.10 | Admin dashboard, product CRUD (add/edit/deactivate) | `PASS` | Verified in `test_admin_product_order_and_user_management`. |
| 2.11 | Admin order status management, user role management & security logs | `PASS` | Verified via `/admin/orders`, `/admin/users/<id>/role` (blocks self-demotion), `/admin/logs`. |
| 2.12 | Guest blocked from protected routes (`/cart`, `/checkout`, `/orders`, `/admin/`) | `PASS` | Returns `302` redirect to `/login`; `/api/transactions/secure` returns `401`. |
| 2.13 | Customer blocked from admin routes (`/admin/*`) | `PASS` | Returns `403 Forbidden` and logs `UNAUTHORIZED_ADMIN_ACCESS`. |
| 2.14 | Customer blocked from viewing another customer's order or transaction (IDOR) | `PASS` | Returns redirect with `Access denied.` flash and logs `UNAUTHORIZED_ORDER_ACCESS` / `UNAUTHORIZED_TRANSACTION_ACCESS`. |

---

## PART 3: Cryptographic Algorithm Verification

### 3.1 AES-256-GCM (`services/crypto/aes_encryption.py`)

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 3.1.1 | AES key length is exactly 256 bits (32 bytes) via `os.urandom(32)` | `PASS` | `len(generate_aes_256_key()) == 32` verified in `test_aes_256_key_and_nonce_lengths`. |
| 3.1.2 | GCM nonce is exactly 96 bits (12 bytes) via `os.urandom(12)` | `PASS` | `len(generate_gcm_nonce()) == 12` verified. |
| 3.1.3 | Authentication tag is 128 bits (16 bytes) and preserved separately | `PASS` | `len(base64.b64decode(enc['auth_tag_b64'])) == 16` verified. |
| 3.1.4 | Fresh AES-256 key generated per transaction | `PASS` | Verified across concurrent transactions (`tx1.wrapped_aes_key != tx2.wrapped_aes_key`). |
| 3.1.5 | Nonce reuse with the same key is strictly rejected (`ValueError`) | `PASS` | `_USED_KEY_NONCE_PAIRS` guard tested in `test_gcm_nonce_reuse_with_same_key_rejected`. |
| 3.1.6 | Modified ciphertext, modified auth tag, and wrong AES key rejected (`InvalidTag`) | `PASS` | Tested in `test_T02_modified_ciphertext_rejected`, `test_T03_modified_gcm_auth_tag_rejected`, `test_aes_gcm_rejects_wrong_key`. |

### 3.2 RSA-OAEP (`services/crypto/rsa_key_management.py`, `services/crypto/rsa_encryption.py`)

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 3.2.1 | RSA key size is 3072 bits | `PASS` | `public_key.key_size == 3072` (wrapped output is 384 bytes) verified. |
| 3.2.2 | Uses OAEP padding with SHA-256 and MGF1(SHA-256) | `PASS` | `padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)` verified. |
| 3.2.3 | Server unwraps 256-bit AES session key; wrong private key fails | `PASS` | Verified in `test_rsa_oaep_wrap_unwrap_and_key_size` and `test_rsa_oaep_rejects_wrong_private_key_and_tampered_wrapped_key`. |
| 3.2.4 | Server private key stored in `instance/keys/server_rsa_private.pem` and never exposed to frontend | `PASS` | Only public key exposed via `/api/crypto/public-key`; private key routes return `404`. |

### 3.3 RSA-PSS (`services/crypto/digital_signature.py`)

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 3.3.1 | Uses RSA-PSS with SHA-256, MGF1(SHA-256), and `PSS.MAX_LENGTH` salt | `PASS` | Verified in `services/crypto/digital_signature.py` and `test_T09_rsa_pss_signature_verification_and_failure`. |
| 3.3.2 | Signs canonical JSON over `(transaction_id, user_id, timestamp, nonce, wrapped_aes_key_b64, gcm_nonce_b64, auth_tag_b64, ciphertext_b64)` | `PASS` | Canonical serialization `canonicalize_transaction_metadata()` verified. |
| 3.3.3 | Valid signatures accepted; tampered packages or wrong user public keys rejected | `PASS` | Verified in `test_T09_rsa_pss_signature_verification_and_failure` and `test_attack_04_digital_signature_tampering`. |
| 3.3.4 | Server verifies signature against authenticated user's registered `User.public_key_pem` | `PASS` | Verified in `verify_and_process_transaction_package` Step 6. |

### 3.4 PBKDF2-HMAC-SHA256 (`services/crypto/integrity.py`)

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 3.4.1 | Unique 128-bit (16-byte) random salt per password via `os.urandom(16)` | `PASS` | Verified in `test_T08_pbkdf2_password_hashing_and_verification`. |
| 3.4.2 | Iteration count is `260,000` (`PBKDF2_ITERATIONS = 260000`) | `PASS` | Verified via hash prefix `pbkdf2:sha256:260000$` and `PBKDF2HMAC` call. |
| 3.4.3 | Constant-time comparison via `hmac.compare_digest` | `PASS` | Verified in `verify_password_pbkdf2()`. |

### 3.5 HMAC-SHA256 (`services/crypto/integrity.py`, `services/crypto/key_storage.py`)

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 3.5.1 | Separate 256-bit HMAC secret stored in `instance/keys/hmac_secret.key` (not hardcoded) | `PASS` | Verified in `load_or_create_hmac_secret()`. |
| 3.5.2 | Detects tampering in both `SecurityLog` and `Transaction` database records | `PASS` | Verified in `test_T07_hmac_verification_and_tamper_detection` and `test_attack_15`. |

### 3.6 Replay Protection (`services/crypto/transaction_security.py`, `models/transaction.py`)

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 3.6.1 | Cryptographically random 128-bit nonce (`secrets.token_hex(16)`) | `PASS` | Verified in `generate_transaction_nonce()`. |
| 3.6.2 | Strict UUIDv4 Transaction ID validation | `PASS` | Rejects malformed or non-v4 UUIDs in `validate_transaction_id()`. |
| 3.6.3 | UTC timestamp window enforcement (`±300` seconds) | `PASS` | Verified in `test_T05_expired_timestamp_rejected` (`>300s` old and `>300s` future rejected). |
| 3.6.4 | Atomic nonce consumption (`db.session.begin_nested()` + `UNIQUE` constraint on `consumed_nonces.nonce_value`) | `PASS` | Verified in `test_T04_duplicate_nonce_replay_rejected` and `test_concurrent_replay_attempts_atomic_protection`. |

---

## PART 4: End-to-End 19-Step Secure Transaction Workflow

| Step | Workflow Action | Status |
|------|-----------------|--------|
| 1–4 | Customer login, browse products, add to cart, proceed to checkout | `PASS` |
| 5–6 | Generate UUIDv4 `transaction_id`, UTC `timestamp`, and 128-bit `nonce` | `PASS` |
| 7–10 | Generate 256-bit AES key, encrypt payload with AES-256-GCM, wrap key with RSA-OAEP-3072, sign package with RSA-PSS-3072 | `PASS` |
| 11 | Transmit encrypted package over TLS 1.3 (`perform_tls_handshake_and_exchange` / HTTPS) | `PASS` |
| 12–13 | Server verifies authentication/authorization, `transaction_id`, `timestamp`, atomic `nonce`, and RSA-PSS signature | `PASS` |
| 14–15 | Server unwraps AES key with RSA-OAEP private key and decrypts/authenticates payload with AES-256-GCM | `PASS` |
| 16–19 | Server recomputes total from DB prices, creates `Order` & `Transaction`, computes record HMAC-SHA256, updates stock, clears cart, and writes HMAC-signed `SecurityLog` | `PASS` |

---

## PART 5: TLS 1.3 & Certificate Verification

| # | Audit Check | Status | Verification Evidence |
|---|-------------|--------|-----------------------|
| 5.1 | TLS 1.3 handshake enforced (`TLSVersion.TLSv1_3` minimum & maximum) | `PASS` | Verified `cipher_info['version'] == 'TLSv1.3'` in `test_T06_tls_1_3_certificate_and_hostname_verification`. |
| 5.2 | Valid CA-signed server certificate (`CN=localhost`, SAN `DNS:localhost`, `IP:127.0.0.1`) accepted | `PASS` | Verified in `test_T06`. |
| 5.3 | Untrusted/rogue self-signed server certificate rejected (`SSLCertVerificationError`) | `PASS` | Verified in `test_T06` Case 2. |
| 5.4 | Wrong hostname (`evil-shop.example.com`) rejected during hostname verification | `PASS` | Verified in `test_T06` Case 3. |
| 5.5 | Expired X.509 server certificate rejected (`SSLCertVerificationError`) | `PASS` | Verified in `test_T06` Case 4. |
| 5.6 | Private keys (`server_rsa_private.pem`, `localhost_server.key`, `local_root_ca.key`) inaccessible via HTTP | `PASS` | Returns `404 Not Found` on all static/instance URL paths. |

---

## PART 6: Controlled Security Attack Simulations (15 Scenarios)

| Attack # | Attack Scenario | Automated Test | Status |
|----------|-----------------|----------------|--------|
| Attack 1 | Ciphertext tampering | `test_attack_01_ciphertext_tampering` | `PASS` |
| Attack 2 | Authentication tag tampering | `test_attack_02_authentication_tag_tampering` | `PASS` |
| Attack 3 | Wrapped AES key tampering | `test_attack_03_wrapped_aes_key_tampering` | `PASS` |
| Attack 4 | Digital signature tampering | `test_attack_04_digital_signature_tampering` | `PASS` |
| Attack 5 | Replay attack using the same nonce | `test_attack_05_replay_attack_same_nonce` | `PASS` |
| Attack 6 | Expired timestamp attack | `test_attack_06_expired_timestamp_attack` | `PASS` |
| Attack 7 | Client-side price manipulation attempt | `test_attack_07_price_manipulation_attempt` | `PASS` |
| Attack 8 | IDOR / accessing another customer's order & transaction | `test_attack_08_idor_other_customers_order_and_transaction` | `PASS` |
| Attack 9 | Unauthorized admin access by a customer | `test_attack_09_unauthorized_admin_access_by_customer` | `PASS` |
| Attack 10 | Unauthorized endpoint access without login | `test_attack_10_unauthorized_endpoint_access_without_login` | `PASS` |
| Attack 11 | SQL injection attempts in login & product search | `test_attack_11_sql_injection_attempts` | `PASS` |
| Attack 12 | XSS attempts in product search & forms | `test_attack_12_xss_escaping` | `PASS` |
| Attack 13 | CSRF attack without token (`WTF_CSRF_ENABLED=True`) | `test_attack_13_csrf_protection_enforced` | `PASS` |
| Attack 14 | Session cookie forgery / tampering | `test_attack_14_session_cookie_tampering` | `PASS` |
| Attack 15 | Database log tampering detection via HMAC-SHA256 | `test_attack_15_database_log_tampering_detected_and_private_keys_protected` | `PASS` |

---

## PART 7: Official CNS Project Test Cases (`T01` – `T10`)

| Test ID | Official Test Case Description | Automated Test | Status |
|---------|--------------------------------|----------------|--------|
| `T01` | Valid encrypted and signed checkout transaction | `test_T01_valid_encrypted_signed_checkout_transaction` | `PASS` |
| `T02` | Modified ciphertext rejected | `test_T02_modified_ciphertext_rejected` | `PASS` |
| `T03` | Modified GCM authentication tag rejected | `test_T03_modified_gcm_auth_tag_rejected` | `PASS` |
| `T04` | Duplicate nonce replay rejected | `test_T04_duplicate_nonce_replay_rejected` | `PASS` |
| `T05` | Expired timestamp rejected | `test_T05_expired_timestamp_rejected` | `PASS` |
| `T06` | Invalid/untrusted TLS certificate, wrong hostname, & expired cert rejected | `test_T06_tls_1_3_certificate_and_hostname_verification` | `PASS` |
| `T07` | HMAC verification and tamper detection | `test_T07_hmac_verification_and_tamper_detection` | `PASS` |
| `T08` | PBKDF2 password hashing and verification | `test_T08_pbkdf2_password_hashing_and_verification` | `PASS` |
| `T09` | RSA-PSS signature verification and failure test | `test_T09_rsa_pss_signature_verification_and_failure` | `PASS` |
| `T10` | Concurrent normal transactions | `test_T10_concurrent_normal_transactions` | `PASS` |

---

## PART 8: Admin Cryptography Lab Verification (`/admin/crypto-demo`)

| # | Button / Demonstration Action | Uses Real Cryptography? | Status |
|---|-------------------------------|-------------------------|--------|
| 8.1 | Test AES-256-GCM Encryption (`demo_action=aes`) | Yes (`generate_aes_256_key`, `encrypt_aes_gcm`, `decrypt_aes_gcm`) | `PASS` |
| 8.2 | Test RSA-OAEP Key Wrapping (`demo_action=rsa_oaep`) | Yes (`wrap_aes_key_rsa_oaep`, `unwrap_aes_key_rsa_oaep`) | `PASS` |
| 8.3 | Test RSA-PSS Digital Signature (`demo_action=rsa_pss`) | Yes (`sign_transaction_package`, `verify_transaction_signature`) | `PASS` |
| 8.4 | Test HMAC-SHA256 Verification (`demo_action=hmac`) | Yes (`compute_hmac_sha256`, `verify_hmac_sha256`) | `PASS` |
| 8.5 | Simulate Tampered Ciphertext Attack (`demo_action=tamper`) | Yes (flips bit `ct_bytes[0] ^= 0xFF` & catches `InvalidTag`) | `PASS` |
| 8.6 | Simulate Duplicate Nonce Replay (`demo_action=replay`) | Yes (calls `consume_nonce_atomically` twice in DB with same nonce) | `PASS` |
| 8.7 | Simulate Expired Timestamp Attack (`demo_action=expired_ts`) | Yes (builds `-600s` UTC timestamp & calls `validate_transaction_timestamp`) | `PASS` |
| 8.8 | Run All 7 Live Tests (`demo_action=all`) | Yes (executes all 7 live cryptographic operations and logs `ADMIN_CRYPTO_LAB_EXECUTED`) | `PASS` |
