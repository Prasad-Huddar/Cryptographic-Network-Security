# COMPLETE INDEPENDENT AUDIT REPORT
## SECURE E-COMMERCE TRANSACTION SYSTEM USING HYBRID CRYPTOGRAPHY AND TLS

**Audit Date:** 2026-11-15  
**Auditor Role:** Senior Python Developer, Cryptography Engineer, Cybersecurity Auditor & QA Engineer  
**Project Path:** `C:\Users\Manish\Downloads\CNS Project`  
**Audit Scope:** Complete Independent Code, Cryptographic, Network Security, Attack Simulation, and QA Audit of Phase 1 & Phase 2

---

## 1. Project Overview

The **Secure E-Commerce Transaction System Using Hybrid Cryptography and TLS** (`SecureShop`) is a full-stack Flask web application implementing an end-to-end cryptographically hardened e-commerce workflow across two completed engineering phases:

- **Phase 1 (Core E-Commerce & Role-Based Access Control):**
  - User registration, authentication, session management (`Flask-Login`), and PBKDF2-HMAC-SHA256 password storage.
  - Product catalogue browsing, category filtering, search, cart management, checkout, order history, and order lifecycle tracking.
  - Admin dashboard with full product CRUD, order status management, user role management, and security audit log inspection.
- **Phase 2 (Hybrid Cryptography, Replay Protection, Tamper Detection & TLS 1.3):**
  - **AES-256-GCM** authenticated symmetric encryption (fresh 256-bit key and 96-bit nonce per transaction, 128-bit authentication tag).
  - **RSA-OAEP (3072-bit, SHA-256, MGF1-SHA256)** asymmetric key wrapping to protect per-transaction AES session keys.
  - **RSA-PSS (3072-bit, SHA-256, MGF1-SHA256)** digital signatures using per-user registered public keys (`User.public_key_pem`).
  - **PBKDF2-HMAC-SHA256** password hashing with individual 128-bit salts and `260,000` iterations.
  - **HMAC-SHA256** record integrity authentication for both `SecurityLog` and `Transaction` records using an isolated 256-bit secret key (`instance/keys/hmac_secret.key`).
  - **Replay Protection** combining UUIDv4 Transaction ID validation, `±300s` UTC timestamp window validation, and atomic database savepoint consumption (`ConsumedNonce` table with `UNIQUE` constraint).
  - **TLS 1.3 / HTTPS** local Root CA (`SecureShop Local Dev Root CA`) and SAN-enabled server certificate (`localhost` / `127.0.0.1`), enforcing TLS 1.3 cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`).

### Audited Codebase Inventory
All project files were inspected line-by-line:
- **Entrypoint & Configuration:** `app.py`, `config.py`, `requirements.txt`, `.env`
- **Database & Models:** `database/database.py`, `models/__init__.py`, `models/user.py`, `models/product.py`, `models/cart.py`, `models/order.py`, `models/transaction.py`
- **Routes:** `routes/__init__.py`, `routes/auth.py`, `routes/shop.py`, `routes/cart.py`, `routes/admin.py`
- **Cryptographic Services (`services/crypto/`):**
  - `__init__.py`
  - `aes_encryption.py`
  - `rsa_key_management.py`
  - `rsa_encryption.py`
  - `digital_signature.py`
  - `integrity.py`
  - `transaction_security.py`
  - `key_storage.py`
- **Templates & Static Assets:** 15 Jinja2 HTML templates in `templates/` (`base.html`, `home.html`, `products.html`, `product_detail.html`, `cart.html`, `checkout.html`, `orders.html`, `order_detail.html`, `transaction_detail.html`, `login.html`, `register.html`, `admin/dashboard.html`, `admin/products.html`, `admin/product_form.html`, `admin/orders.html`, `admin/users.html`, `admin/security_logs.html`, `admin_crypto_demo.html`) and static files (`static/css/style.css`, `static/js/main.js`, `static/images/placeholder.png`).
- **Tests:** `tests/test_app.py` (35 tests), `tests/test_phase2_crypto.py` (22 tests), and `tests/test_audit.py` (27 independent audit tests).
- **Documentation:** `README.md`, `CRYPTOGRAPHY_DOCUMENTATION.md`, `PHASE2_REPORT.md`.

---

## 2. Phase 1 Verification

Every Phase 1 workflow was executed against the running application and verified at both the HTTP response layer and the SQLite database layer:

| Category | Audited Workflow | HTTP Status / Behavior | Database Verification | Result |
|----------|------------------|------------------------|-----------------------|--------|
| **Authentication** | User Registration (`POST /register`) | `200 OK` (redirects to `/login` with success message) | Creates `User` row with `pbkdf2:sha256:260000$...` hash, provisions 3072-bit RSA keypair, writes `REGISTER` `SecurityLog` | **PASS** |
| **Authentication** | User Login (`POST /login`) | `200 OK` (sets `HttpOnly`, `SameSite=Lax` session cookie) | Writes HMAC-signed `LOGIN_SUCCESS` `SecurityLog` | **PASS** |
| **Authentication** | Invalid Login (`POST /login`) | `200 OK` (`Invalid email or password`) | Writes HMAC-signed `LOGIN_FAILED` `SecurityLog` | **PASS** |
| **Authentication** | Logout (`GET /logout`) | `200 OK` (clears session) | Writes HMAC-signed `LOGOUT` `SecurityLog` | **PASS** |
| **E-Commerce** | Home Page (`GET /`) & Catalogue (`GET /products`) | `200 OK` | Queries active `Product` rows; supports `?category=` and `?search=` filters | **PASS** |
| **E-Commerce** | Product Details (`GET /product/<id>`) | `200 OK` (`404` if invalid ID) | Loads product details and related category products | **PASS** |
| **E-Commerce** | Cart Operations (`/cart`, `/cart/add/<id>`, `/cart/update/<id>`, `/cart/remove/<id>`) | `200 OK` | Inserts/updates/deletes `CartItem` rows and enforces available stock limits | **PASS** |
| **E-Commerce** | Checkout & Order Creation (`POST /checkout`) | `200 OK` (redirects to `/order/<id>`) | Creates `Order`, `OrderItem`, `Transaction`, `ConsumedNonce`, decrements `Product.stock`, clears `CartItem` | **PASS** |
| **E-Commerce** | Order History & Detail (`GET /orders`, `GET /order/<id>`) | `200 OK` | Displays customer's orders and links to `/transaction/<tx_id>` | **PASS** |
| **Admin** | Admin Dashboard (`GET /admin/`) | `200 OK` | Displays revenue, order counts, user counts, and recent HMAC-verified security logs | **PASS** |
| **Admin** | Product CRUD (`/admin/products/add`, `/edit/<id>`, `/delete/<id>`) | `200 OK` | Inserts/updates/soft-deletes `Product` rows and logs `ADMIN_ACTION` | **PASS** |
| **Admin** | Manage Orders & Users (`/admin/orders`, `/admin/users`) | `200 OK` | Updates order statuses, updates user roles, blocks admin self-demotion | **PASS** |
| **Admin** | Security Logs (`GET /admin/security-logs`) | `200 OK` | Evaluates `log.verify_integrity()` on every log row and displays `HMAC VALID` / `TAMPERED` badge | **PASS** |
| **Authorization** | Guest -> Protected Pages (`/cart`, `/checkout`, `/orders`, `/admin/`) | `302 Found` -> `/login` | Blocks unauthenticated access | **PASS** |
| **Authorization** | Customer -> Admin Pages (`/admin/*`) | `403 Forbidden` | Blocks horizontal/vertical privilege escalation and logs `ACCESS_DENIED` | **PASS** |
| **Authorization** | Customer 2 -> Customer 1 Order/Transaction (`/order/<id>`, `/transaction/<tx_id>`) | `302` -> `/orders` (`Access denied.`) | Blocks IDOR access and logs `ACCESS_DENIED` | **PASS** |

---

## 3. Phase 2 Verification

All 8 modules under `services/crypto/` were inspected and verified:
1. `services/crypto/__init__.py` – Exports public cryptographic interfaces cleanly without circular dependencies.
2. `services/crypto/aes_encryption.py` – Implements `AESGCM` from `cryptography.hazmat.primitives.ciphers.aead` with explicit separation of the 128-bit authentication tag and runtime `(sha256(key), nonce)` uniqueness tracking.
3. `services/crypto/rsa_key_management.py` – Generates 3072-bit RSA keys (`public_exponent=65537`, `key_size=3072`), manages server private/public keys, and provisions per-user client signing keypairs.
4. `services/crypto/rsa_encryption.py` – Implements RSA-OAEP (`padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)`) for wrapping/unwrapping the 32-byte AES-256 key.
5. `services/crypto/digital_signature.py` – Implements RSA-PSS (`padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)`) with `hashes.SHA256()` over canonical JSON metadata (`sort_keys=True, separators=(',', ':')`).
6. `services/crypto/integrity.py` – Implements `PBKDF2HMAC` (`hashes.SHA256()`, `260,000` iterations, 16-byte random salt) and `hmac.HMAC` (`hashes.SHA256()`) for `SecurityLog` and `Transaction` records.
7. `services/crypto/transaction_security.py` – Implements UUIDv4 validation, UTC timestamp window validation (`±300s`), atomic `ConsumedNonce` savepoint consumption, the 11-step client package builder, the 12-step server verifier, and TLS 1.3 X.509 certificate generation and handshake verification.
8. `services/crypto/key_storage.py` – Stores server keys in `instance/keys/`, separate HMAC secret in `instance/keys/hmac_secret.key`, client keys in `instance/client_keys/`, and TLS certificates in `instance/certs/` with restrictive file permissions (`0o600`).

---

## 4. Cryptographic Algorithm Verification

### 4.1 AES-256-GCM (`services/crypto/aes_encryption.py`)
- **Key Size:** `AES_KEY_BYTES = 32` (256 bits) generated via `secrets.token_bytes(32)`. Verified: `len(key) == 32`.
- **Nonce Size:** `GCM_NONCE_BYTES = 12` (96 bits) generated via `secrets.token_bytes(12)`. Verified: `len(nonce) == 12`.
- **Authentication Tag:** `GCM_TAG_BYTES = 16` (128 bits). `AESGCM.encrypt()` appends the 16-byte tag to the ciphertext; `encrypt_aes_gcm()` splits `ct_body = raw_ct_and_tag[:-16]` and `auth_tag = raw_ct_and_tag[-16:]`, storing and transmitting both explicitly.
- **Nonce Reuse Prevention:** `_USED_KEY_NONCE_PAIRS` tracks `(sha256(key), nonce)` and raises `AESEncryptionError` if the same `(key, nonce)` pair is ever supplied twice.
- **Tamper Rejection:** Any single-bit flip in `ciphertext`, `auth_tag`, `nonce`, `key`, or `associated_data` raises `InvalidTag` -> `AESEncryptionError`.

### 4.2 RSA-OAEP (`services/crypto/rsa_key_management.py`, `services/crypto/rsa_encryption.py`)
- **Key Size:** `RSA_KEY_SIZE = 3072` bits (produces 384-byte wrapped key ciphertexts).
- **Hash & MGF1:** OAEP uses `hashes.SHA256()` and `padding.MGF1(algorithm=hashes.SHA256())`.
- **Private Key Isolation:** The server private key resides in `instance/keys/server_rsa_private.pem` and is never returned by any route or template; `/api/crypto/public-key` exposes only the PEM public key.

### 4.3 RSA-PSS (`services/crypto/digital_signature.py`)
- **Hash & MGF1:** RSA-PSS uses `hashes.SHA256()`, `padding.MGF1(hashes.SHA256())`, and `padding.PSS.MAX_LENGTH`.
- **Signed Canonical Fields:** `transaction_id`, `user_id`, `timestamp`, `nonce`, `wrapped_aes_key`, `gcm_nonce_b64`, `auth_tag_b64`, `ciphertext_b64`.
- **Per-User Registered Public Key Verification:** Each user has an individual 3072-bit RSA public key stored in `users.public_key_pem`. The server verifies signatures strictly against `user.public_key_pem`.

### 4.4 PBKDF2-HMAC-SHA256 (`services/crypto/integrity.py`)
- **Salt:** 16-byte (128-bit) random salt per password via `secrets.token_bytes(16)`.
- **Iterations:** `DEFAULT_PBKDF2_ITERATIONS = 260000`.
- **Verification:** Uses `PBKDF2HMAC.verify()` for constant-time comparison.

### 4.5 HMAC-SHA256 (`services/crypto/integrity.py`, `services/crypto/key_storage.py`)
- **Secret Storage:** 32-byte (256-bit) random secret generated via `secrets.token_bytes(32)` and stored in `instance/keys/hmac_secret.key` (outside source code).
- **Tamper Detection:** Computed over canonical JSON representations of `SecurityLog` (`event_type`, `description`, `user_id`, `ip_address`, `timestamp`) and `Transaction` (`transaction_id`, `order_id`, `user_id`, `nonce`, `timestamp_iso`, `ciphertext_b64`, `wrapped_aes_key`, `gcm_nonce`, `auth_tag`, `digital_signature`, `status`). Direct SQLite edits to either table cause `verify_integrity()` to return `False`.

### 4.6 Replay Protection (`services/crypto/transaction_security.py`)
- **Nonce Generation:** 128-bit random hex nonce (`secrets.token_hex(16)` = 32 hex chars).
- **Timestamp Tolerance:** `±300` seconds around current UTC time (`validate_timestamp`).
- **Transaction ID Validation:** Strict UUIDv4 validation (`uuid.UUID(tx_id, version=4)`).
- **Atomic Nonce Consumption:** `consume_nonce_atomically()` uses `db.session.begin_nested()` (SQLite `SAVEPOINT`) and inserts into `consumed_nonces` (`nonce_value UNIQUE`). Concurrent threads submitting the same nonce result in exactly one commit and `IntegrityError` rejection for all duplicates.

---

## 5. End-to-End Transaction Verification (19-Step Workflow)

Executed and verified in `tests/test_phase2_crypto.py::TestEndToEndSecureWorkflow` and `tests/test_audit.py`:

1. **Customer Authentication:** Customer logs in (`POST /login`) with PBKDF2-HMAC-SHA256 verification.
2. **Browse Catalogue:** Customer views products (`GET /products`).
3. **Add to Cart:** Customer adds item(s) (`POST /cart/add/<id>`).
4. **Proceed to Checkout:** Customer opens `GET /checkout` and submits shipping address (`POST /checkout`).
5. **Transaction ID Generation:** Client generates UUIDv4 `transaction_id` (`generate_transaction_id()`).
6. **Timestamp & Nonce Generation:** Client generates UTC ISO-8601 `timestamp` and 128-bit `nonce`.
7. **Fresh AES-256 Key Generation:** Client generates 32-byte random AES key (`generate_aes_key()`).
8. **AES-256-GCM Encryption:** Client encrypts JSON order payload with AES-256-GCM using canonical metadata (`transaction_id|user_id|timestamp|nonce`) as AAD, yielding `ciphertext_b64`, `gcm_nonce_b64` (12 bytes), and `auth_tag_b64` (16 bytes).
9. **RSA-OAEP Key Wrapping:** Client wraps the 32-byte AES key with the server's 3072-bit RSA public key using RSA-OAEP-SHA256 (`wrapped_aes_key`).
10. **RSA-PSS Digital Signature:** Client signs the canonical package metadata + ciphertext + wrapped key + nonce + tag using the customer's 3072-bit RSA private key (`signature_b64`).
11. **HTTPS / TLS 1.3 Transmission:** Package is transmitted to the server (`POST /checkout` or `POST /api/transaction/submit`).
12. **Server Metadata & Replay Validation:** Server validates customer authentication, UUIDv4 `transaction_id`, `±300s` UTC `timestamp`, and atomically consumes `nonce` in `consumed_nonces`.
13. **Server RSA-PSS Verification:** Server verifies `signature_b64` against `current_user.public_key_pem` and logs `SIGNATURE_VERIFIED`.
14. **Server RSA-OAEP Key Unwrapping:** Server unwraps the 32-byte AES key using `instance/keys/server_rsa_private.pem`.
15. **Server AES-256-GCM Decryption & Tag Authentication:** Server decrypts `ciphertext_b64` and verifies the 128-bit `auth_tag_b64` and AAD, logging `ENCRYPTION_SUCCESS`.
16. **Server Authoritative Price & Stock Verification:** Server ignores client-submitted prices, queries authoritative `Product.price` and `Product.stock` from SQLite, and creates `Order`, `OrderItem`, and `Transaction` records.
17. **Record Integrity HMAC-SHA256:** Server computes `Transaction.integrity_hmac` over all cryptographic fields.
18. **Inventory & Cart Finalization:** Server decrements `Product.stock` and clears the customer's `CartItem` rows.
19. **Audit Logging:** Server creates HMAC-signed `TRANSACTION_CREATED` and `ORDER_PLACED` entries in `security_logs`.

---

## 6. TLS 1.3 Verification

Verified in `services/crypto/transaction_security.py` and `tests/test_audit.py`:
- **Certificate Hierarchy:**
  - Root CA: `instance/certs/local_root_ca.crt` (`CN=SecureShop Local Dev Root CA`, RSA-3072, `BasicConstraints(ca=True)`).
  - Server Certificate: `instance/certs/localhost_server.crt` (`CN=localhost`, `SubjectAlternativeName(DNSName('localhost'), IPAddress(127.0.0.1))`, RSA-3072, signed by Local Root CA).
- **TLS 1.3 Enforcement:** `create_tls_server_context(require_tls13=True)` and `create_tls_client_context(require_tls13=True)` set `minimum_version = ssl.TLSVersion.TLSv1_3` and `maximum_version = ssl.TLSVersion.TLSv1_3`.
- **Negotiated Protocol & Cipher:** Live OpenSSL handshake verifies `protocol_version == 'TLSv1.3'` and cipher `TLS_AES_256_GCM_SHA384` (256-bit).
- **Invalid/Untrusted Certificate Rejection:** Handshake against a rogue self-signed server certificate raises `ssl.SSLCertVerificationError`.
- **Hostname Mismatch Rejection:** Handshake with `server_hostname="wrong.hostname.internal"` raises `ssl.SSLCertVerificationError`.
- **Private Key Non-Exposure:** Requests to `/static/keys/server_rsa_private.pem`, `/instance/keys/server_rsa_private.pem`, `/instance/certs/localhost_server.key`, and `/static/certs/localhost_server.key` all return `404 Not Found`.

---

## 7. Attack Simulation Results (All 15 Controlled Attacks)

All 15 attack simulations were executed against the application and verified in `tests/test_audit.py::TestSecurityAttackSimulations`:

| # | Attack Simulation | Attack Vector Executed | Defense Triggered | Result |
|---|-------------------|------------------------|-------------------|--------|
| 1 | **Ciphertext Tampering** | Flipped byte 0 (`ct[0] ^= 0xFF`) of `ciphertext_b64` | Blocked by RSA-PSS signature check (Step 6) and AES-GCM tag check (Step 8); logged `TAMPERING_DETECTED` | **PASS** |
| 2 | **Authentication Tag Tampering** | Flipped last byte (`tag[-1] ^= 0xFF`) of 128-bit `auth_tag_b64` | Blocked by `AESGCM.decrypt()` (`InvalidTag` -> `AESEncryptionError`) | **PASS** |
| 3 | **Wrapped AES Key Tampering** | Flipped byte 10 (`wk[10] ^= 0xFF`) of `wrapped_aes_key` and re-signed | Blocked by RSA-OAEP `private_key.decrypt()` (`RSAEncryptionError`); logged `TAMPERING_DETECTED` | **PASS** |
| 4 | **Digital Signature Tampering** | Flipped byte 0 (`sig[0] ^= 0xFF`) of `signature_b64` | Blocked by RSA-PSS `public_key.verify()`; logged `INVALID_SIGNATURE` & `TAMPERING_DETECTED` | **PASS** |
| 5 | **Replay Attack (Same Nonce)** | Submitted valid signed transaction package twice | Second submission blocked by atomic `ConsumedNonce` check; logged `REPLAY_ATTEMPT` | **PASS** |
| 6 | **Expired Timestamp Attack** | Submitted signed package with timestamp `-600s` (outside `±300s` window) | Blocked by `validate_timestamp()`; logged `REPLAY_ATTEMPT` | **PASS** |
| 7 | **Price Manipulation Attempt** | Encrypted client payload claiming `price: 0.01` for ₹1,500 laptop (qty 2) | Server ignored client price and billed authoritative DB total (`₹3,000.00`) | **PASS** |
| 8 | **Order/Transaction IDOR** | Customer 2 requested `/order/<c1_id>` and `/transaction/<c1_tx_id>` | Blocked (`Access denied.`); logged `ACCESS_DENIED` | **PASS** |
| 9 | **Unauthorized Admin Access** | Logged-in Customer 1 requested `/admin/`, `/admin/products`, `/admin/orders`, `/admin/users`, `/admin/security-logs`, `/admin/crypto-demo` | Returned `403 Forbidden`; logged `ACCESS_DENIED` | **PASS** |
| 10 | **Unauthenticated Endpoint Access** | Guest requested `/cart`, `/checkout`, `/orders`, `/admin/`, `/api/transaction/submit` | Returned `302 Found` redirecting to `/login` | **PASS** |
| 11 | **SQL Injection Attempts** | Injected `' OR '1'='1' --` into `/login` and `/products?search=...` | Parameterized SQLAlchemy ORM queries neutralized payload; login rejected, tables intact | **PASS** |
| 12 | **Cross-Site Scripting (XSS)** | Submitted `<script>alert('XSS')</script>` to `/products?search=...` | Jinja2 auto-escaping encoded output as `&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;` | **PASS** |
| 13 | **CSRF Attack Simulation** | Submitted `POST /login` without CSRF token when `WTF_CSRF_ENABLED=True` | `Flask-WTF` `CSRFProtect` rejected request with `400 Bad Request` | **PASS** |
| 14 | **Session Cookie Tampering** | Forged session cookie `eyJfdXNlcl9pZCI6IjEifQ.FORGED_TIMESTAMP.FORGED_HMAC_SIGNATURE` targeting `/admin/` and `/cart` | `Flask-Login` / `itsdangerous` rejected invalid cookie signature and redirected to `/login` (`302`) | **PASS** |
| 15 | **Database Log Tampering** | Directly modified `SecurityLog.description` in SQLite after creation | `log_entry.verify_integrity()` recomputed HMAC-SHA256 and returned `False` (`TAMPERED`) | **PASS** |

---

## 8. All 10 Official CNS Project Test Cases (`T01` – `T10`)

| Test ID | Description | Test Procedure | Expected Result | Actual Result | Status | Evidence | Relevant Code File |
|---------|-------------|----------------|-----------------|---------------|--------|----------|--------------------|
| **T01** | Valid Login | Submit registered email (`customer1@test.com`) and password (`Customer@123`) to `POST /login`. | User is authenticated, session is established, and HMAC-signed `LOGIN_SUCCESS` log is created. | `HTTP 200 OK` (`Login successful`), session established, `SecurityLog` created with `verify_integrity() == True`. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T01_valid_login` | `routes/auth.py`, `services/crypto/integrity.py` |
| **T02** | Invalid Password | Submit registered email (`customer1@test.com`) with wrong password (`WrongPass@999`) to `POST /login`. | Authentication is rejected with error message; `LOGIN_FAILED` security log is recorded. | `Invalid email or password` returned; `LOGIN_FAILED` logged with valid HMAC. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T02_invalid_password` | `routes/auth.py`, `models/user.py` |
| **T03** | AES Encryption and Decryption | Generate 256-bit key & 96-bit nonce, encrypt JSON order payload with AAD via AES-256-GCM, and decrypt using the 128-bit auth tag. | Plaintext is encrypted to base64 ciphertext + 16-byte tag and decrypted back to exact original JSON. | 32-byte key, 12-byte nonce, 16-byte tag verified; decrypted bytes match original plaintext (`{"order": "CNS-T03", "amount": 1500.0}`). | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T03_aes_encryption_and_decryption` | `services/crypto/aes_encryption.py` |
| **T04** | Transaction Tampering | Build valid signed hybrid transaction package, flip 1 byte of `ciphertext_b64`, and pass to `verify_and_process_transaction_package()`. | Server detects tampering, rejects transaction, creates no order, and logs `TAMPERING_DETECTED`. | `ok == False`, `order is None`, `TAMPERING_DETECTED` event recorded in `security_logs`. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T04_transaction_tampering` | `services/crypto/transaction_security.py` |
| **T05** | Replay Old Transaction | 1) Submit identical valid transaction package twice. 2) Submit transaction package with timestamp 10 minutes in the past. | Both duplicate-nonce replay and expired-timestamp transaction are rejected and logged as `REPLAY_ATTEMPT`. | Second submission rejected (`Duplicate transaction nonce detected (replay attack blocked)`); 10-min-old package rejected (`Transaction timestamp expired`). | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T05_replay_old_transaction` | `services/crypto/transaction_security.py`, `models/transaction.py` |
| **T06** | Customer Accessing Admin Operation | Log in as `customer1@test.com` (`role='customer'`) and send `GET` and `POST` requests to `/admin/*` endpoints. | All admin endpoints return `403 Forbidden` and record `ACCESS_DENIED` in `security_logs`. | All 6 GET endpoints and `POST /admin/products/add` returned `403 Forbidden`; `ACCESS_DENIED` logged. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T06_customer_accessing_admin_operation` | `routes/admin.py` |
| **T07** | TLS Connection | Establish TLS connection between `create_tls_client_context(require_tls13=True)` and `create_tls_server_context(require_tls13=True)` and exchange payload. | Handshake negotiates `TLSv1.3` with CA-signed certificate and exchanges encrypted application data. | Negotiated `TLSv1.3` (`TLS_AES_256_GCM_SHA384`), received `b"ACK:T07_TLS13_VERIFICATION"`. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T07_tls_connection` | `services/crypto/transaction_security.py` |
| **T08** | Invalid / Untrusted Certificate | Attempt TLS 1.3 handshake against 1) an untrusted self-signed certificate and 2) a valid certificate with mismatched hostname (`wrong.hostname.internal`). | Both handshakes abort with `ssl.SSLCertVerificationError`. | Both connections raised `ssl.SSLCertVerificationError` during handshake. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T08_invalid_untrusted_certificate` | `services/crypto/transaction_security.py` |
| **T09** | Digital Signature Verification | Sign transaction package with Customer 1's 3072-bit RSA-PSS key; verify with 1) Customer 1's public key, 2) Customer 2's public key, and 3) mutated signature bytes. | Valid signature passes with Customer 1's public key; fails with Customer 2's public key and fails when mutated. | `verify_transaction_signature` returned `True` for Customer 1, `False` for Customer 2, and rejected mutated signature (`Invalid RSA-PSS digital signature`). | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T09_digital_signature_verification` | `services/crypto/digital_signature.py` |
| **T10** | Concurrent Normal Transactions | Execute 3 normal encrypted & signed transactions across Customer 1 and Customer 2. | All 3 succeed with unique `transaction_id`, unique `wrapped_aes_key`, unique `gcm_nonce`, accurate stock deduction, and 3 `Order` records. | All 3 transactions succeeded (`Order.query.count() == 3`), unique keys/nonces verified, stock updated from `50 -> 49` and `30 -> 26`. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T10_concurrent_normal_transactions` | `services/crypto/transaction_security.py` |

---

## 9. Admin Cryptography Lab Verification (`/admin/crypto-demo`)

Audited `routes/admin.py` (`/admin/crypto-demo`) and `templates/admin_crypto_demo.html`, and tested all 8 button actions in `tests/test_audit.py::TestAdminOperationsAndCryptoLab::test_admin_crypto_lab_all_buttons`:

1. **`demo_action=aes` (Test AES-256-GCM Encryption):** Calls real `generate_aes_key()`, `generate_gcm_nonce()`, `encrypt_aes_gcm()`, and `decrypt_aes_gcm()`. Displays live key hex preview, 96-bit nonce, 128-bit auth tag, ciphertext, and decrypted plaintext.
2. **`demo_action=rsa_oaep` (Test RSA-OAEP Key Wrapping):** Calls real `wrap_aes_key()` and `unwrap_aes_key()` with the server's 3072-bit RSA keypair and verifies `unwrapped_aes_key == aes_key`.
3. **`demo_action=rsa_pss` (Test RSA-PSS Digital Signature):** Calls real `build_client_transaction_package()` and `verify_transaction_signature()` using the admin user's 3072-bit RSA keypair.
4. **`demo_action=hmac` (Test HMAC-SHA256 Verification):** Calls real `compute_hmac_sha256()` and `verify_hmac_sha256()` using `instance/keys/hmac_secret.key`.
5. **`demo_action=tamper` (Simulate Tampered Ciphertext Attack):** Flips byte 0 (`tampered_ct[0] ^= 0xFF`) of real AES-256-GCM ciphertext and invokes `decrypt_aes_gcm()`, catching the real `AESEncryptionError` (`ATTACK BLOCKED`).
6. **`demo_action=replay` (Simulate Duplicate Nonce Replay):** Calls `consume_nonce_atomically()` twice against the real SQLite `consumed_nonces` table with the same nonce, verifying `first_nonce_accepted == True` and `second_nonce_accepted == False` (`REPLAY REJECTED`).
7. **`demo_action=expired_ts` (Simulate Expired Timestamp Attack):** Generates a real timestamp 10 minutes in the past (`now - 600s`) and calls `validate_timestamp()`, catching `ReplayProtectionError` (`EXPIRED TS REJECTED`).
8. **`demo_action=all` (Run All 7 Live Tests):** Executes all 7 cryptographic demonstrations end-to-end and logs `ADMIN_ACTION` in `security_logs`.

---

## 10. Bugs Discovered During Audit

During the independent code and security inspection, **4 bugs / security weaknesses** were discovered:

1. **Bug #1 (Security Weakness – Unvalidated Open Redirect in `routes/auth.py` and `routes/cart.py`):**
   - `routes/auth.py` (`login()`) redirected directly to `request.args.get('next')` without verifying whether the URL was relative/same-host (`//evil.com` or `https://evil.com`).
   - `routes/cart.py` (`add_to_cart()`) redirected to `request.referrer` without validating the host.
2. **Bug #2 (Input Validation Bug – `NoneType` TypeError on Non-Numeric Form Inputs in `routes/cart.py` and `routes/admin.py`):**
   - `request.form.get('quantity', 1, type=int)` returns `None` when a user or fuzzer submits a non-integer string (e.g. `quantity=abc`), causing `if quantity < 1:` in `routes/cart.py` and `stock < 0` / `price <= 0` in `routes/admin.py` to raise an unhandled `TypeError: '<' not supported between instances of 'NoneType' and 'int'`.
3. **Bug #3 (Admin Crypto Lab – Simulated Nonce Replay Check & Missing Individual Action Buttons):**
   - In `routes/admin.py`, the Admin Crypto Lab previously set `second_nonce_accepted = False` as a boolean after testing signature/timestamp rather than invoking `consume_nonce_atomically()` twice against the SQLite database, and only had a single submit button instead of individual test buttons for each of the 7 required lab demonstrations.
4. **Bug #4 (SQLite Concurrency Timeout Under Multi-Threaded Load in `config.py`):**
   - `config.py` did not configure `connect_args={'timeout': 30}` on the SQLAlchemy SQLite engine, which could cause transient lock errors under heavy concurrent write bursts.

---

## 11. Bugs Fixed

All 4 discovered issues were fixed and verified via automated regression tests:

1. **Fixed Open Redirects (`routes/auth.py`, `routes/cart.py`):**
   - Added `_is_safe_redirect_url(target)` in `routes/auth.py` and `_safe_next_url(target)` in `routes/cart.py` using `urllib.parse.urlsplit` to reject any URL containing a scheme, netloc, or `//` prefix.
2. **Fixed Non-Numeric Form Input Crashes (`routes/cart.py`, `routes/admin.py`):**
   - Added explicit `None` checks in `routes/cart.py` (`add_to_cart`, `update_cart`) and `routes/admin.py` (`add_product`, `edit_product`) so malformed `quantity`, `price`, or `stock` inputs gracefully flash a validation error or default safely instead of raising `TypeError`.
3. **Upgraded Admin Crypto Lab (`routes/admin.py`, `templates/admin_crypto_demo.html`):**
   - Wired the Duplicate Nonce Replay test in `/admin/crypto-demo` to call `consume_nonce_atomically()` twice against the live database (`first_nonce_accepted = True`, `second_nonce_accepted = False`) and added individual interactive buttons for all 7 required demonstrations plus a "Run All 7 Live Tests" button.
4. **Configured SQLite Concurrency Timeout (`config.py`):**
   - Added `SQLALCHEMY_ENGINE_OPTIONS = {'connect_args': {'timeout': 30}}` in `Config`.

---

## 12. Remaining Limitations (Architectural Notes for Future Phases)

1. **Simulated Browser Client Signing Key Custody:**
   - Because standard web browsers do not natively persist hardware-backed RSA-3072 private keys across sessions without WebCrypto IndexedDB key-wrapping or a browser extension, each user's client signing private key is stored in an isolated server directory (`instance/client_keys/user_<id>_private.pem`, mode `0600`) for the web checkout flow while also supporting external client-signed JSON packages at `POST /api/transaction/submit`.
2. **Development Self-Signed Root CA:**
   - The HTTPS listener on port `5443` uses a locally generated Root CA (`instance/certs/local_root_ca.crt`). Browsers will display a self-signed certificate warning unless `local_root_ca.crt` is imported into the OS/browser trust store.
3. **SQLite Database Engine:**
   - SQLite is ideal for single-node academic demonstration and testing; a multi-node production deployment would migrate `SQLALCHEMY_DATABASE_URI` to PostgreSQL.

---

## 13. Final Test Summary

All automated test suites (`tests/test_app.py`, `tests/test_phase2_crypto.py`, and `tests/test_audit.py`) were executed via `pytest -v` and saved to `audit_test_results.txt`:

| Test Suite File | Scope | Tests Executed | Passed | Failed |
|-----------------|-------|----------------|--------|--------|
| `tests/test_app.py` | Phase 1 E-Commerce, Auth, RBAC, Password Security | 35 | **35** | 0 |
| `tests/test_phase2_crypto.py` | Phase 2 Unit & Integration Cryptography Tests | 22 | **22** | 0 |
| `tests/test_audit.py` | Official CNS Test Cases (`T01`–`T10`), 15 Attack Simulations & Admin Lab | 27 | **27** | 0 |
| **TOTAL** | **Complete Project Test Suite** | **84** | **84** | **0** |

**Audit Conclusion:** Phases 1 and 2 of the **Secure E-Commerce Transaction System Using Hybrid Cryptography and TLS** are **100% functional, cryptographically verified, and ready for Phase 3**.
