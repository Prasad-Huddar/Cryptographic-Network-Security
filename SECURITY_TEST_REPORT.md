# COMPREHENSIVE SECURITY & AUTOMATED TEST REPORT
## Secure E-Commerce Transaction System Using Hybrid Cryptography and TLS

**Execution Date:** 2026-11-15  
**Test Runner:** `pytest 9.2.0` (`Python 3.12.10`)  
**Total Executed Tests:** `85`  
**Passed:** `85` (`100%`)  
**Failed:** `0`  
**Raw Log Output:** `test_results.txt`

---

## 1. Official 10 CNS Project Test Cases (`T01` – `T10`)

| Test ID | Test Description | Expected Result | Actual Result | Status | Evidence / Log Location |
|---------|------------------|-----------------|---------------|--------|-------------------------|
| **T01** | Valid login | User authenticated successfully and `LOGIN_SUCCESS` logged with HMAC-SHA256. | Authenticated with HTTP 200 (`Login successful`); `LOGIN_SUCCESS` recorded with valid HMAC. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T01_valid_login` (`test_results.txt`) |
| **T02** | Invalid password | Login rejected with appropriate error message and `LOGIN_FAILED` security log. | Rejected (`Invalid email or password`); `LOGIN_FAILED` recorded with valid HMAC. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T02_invalid_password` (`test_results.txt`) |
| **T03** | AES-256-GCM encrypt/decrypt | Original transaction data recovered exactly using 256-bit key, 96-bit nonce, and 128-bit tag. | Decrypted bytes matched original JSON (`{"order": "CNS-T03", "amount": 1500.0}`) bit-for-bit. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T03_aes_encryption_and_decryption` (`test_results.txt`) |
| **T04** | Transaction tampering | Integrity verification fails when ciphertext is modified and transaction is rejected. | Rejected (`ok=False`, `order=None`); `TAMPERING_DETECTED` logged in `security_logs`. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T04_transaction_tampering` (`test_results.txt`) |
| **T05** | Replay old transaction | Nonce/timestamp verification rejects both duplicate request and 10-minute-old request. | Both duplicate-nonce and expired-timestamp packages rejected; `REPLAY_ATTEMPT` logged. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T05_replay_old_transaction` (`test_results.txt`) |
| **T06** | Customer accesses admin operation | HTTP `403 Access Denied` and `ACCESS_DENIED` security log created. | All 6 GET admin routes and `POST /admin/products/add` returned `403 Forbidden`; `ACCESS_DENIED` logged. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T06_customer_accessing_admin_operation` (`test_results.txt`) |
| **T07** | TLS 1.3 connection | Application communicates over HTTPS using `TLSv1.3` and `TLS_AES_256_GCM_SHA384`. | Handshake negotiated `TLSv1.3` (`TLS_AES_256_GCM_SHA384`) and exchanged encrypted payload. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T07_tls_connection` (`test_results.txt`) |
| **T08** | Invalid/untrusted certificate | Client rejects untrusted self-signed certificate and mismatched hostname. | Both rogue cert and wrong hostname raised `ssl.SSLCertVerificationError`. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T08_invalid_untrusted_certificate` (`test_results.txt`) |
| **T09** | Digital signature verification | Valid RSA-PSS-3072 signature accepted; wrong public key or altered signature rejected. | Accepted for Customer 1's key; rejected for Customer 2's key and rejected when 1 byte mutated. | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T09_digital_signature_verification` (`test_results.txt`) |
| **T10** | Concurrent normal transactions | Multiple transactions process with unique keys/nonces and accurate stock deduction. | All 3 transactions succeeded with distinct keys/nonces; stock updated accurately (`50->49`, `30->26`). | **PASS** | `tests/test_audit.py::TestOfficialCNSTestCases::test_T10_concurrent_normal_transactions` (`test_results.txt`) |

---

## 2. Controlled Security Attack Simulations & Additional Security Tests (`S01` – `S18`)

| Test ID | Test Description | Expected Result | Actual Result | Status | Evidence / Log Location |
|---------|------------------|-----------------|---------------|--------|-------------------------|
| **S01** | Ciphertext tampering (`ciphertext[0] ^= 0xFF`) | Transaction rejected; no order created. | Rejected (`ok=False`, `order=None`). | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_01_ciphertext_tampering` |
| **S02** | GCM authentication tag tampering (`tag[-1] ^= 0xFF`) | `decrypt_aes_gcm` raises `AESEncryptionError`. | Raised `AESEncryptionError` (`InvalidTag`). | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_02_authentication_tag_tampering` |
| **S03** | RSA-OAEP wrapped AES key tampering (`wk[10] ^= 0xFF`) | Server RSA-OAEP unwrap fails and rejects transaction. | Rejected with `Failed to unwrap AES session key`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_03_wrapped_aes_key_tampering` |
| **S04** | RSA-PSS digital signature tampering (`sig[0] ^= 0xFF`) | Server rejects signature and logs `INVALID_SIGNATURE`. | Rejected with `Invalid RSA-PSS digital signature`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_04_digital_signature_tampering` |
| **S05** | Reused replay nonce | Second request with same nonce rejected atomically. | Rejected (`Replay attack detected: nonce or transaction ID has already been consumed`). | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_05_replay_attack_same_nonce` |
| **S06** | Expired timestamp (`-600s` outside `±300s` tolerance) | Rejected as expired timestamp. | Rejected (`Transaction timestamp expired`). | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_06_expired_timestamp_attack` |
| **S07** | Client price manipulation (`price=0.01` for ₹1,500 item) | Server recomputes authoritative DB total (`₹3,000.00`). | Order billed at `3000.00` from SQLite `Product.price`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_07_price_manipulation_attempt` |
| **S08** | IDOR: Customer 2 accesses Customer 1 order & transaction | Blocked with `Access denied.` and `ACCESS_DENIED` log. | Both `/order/<id>` and `/transaction/<tx_id>` blocked. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_08_idor_other_customers_order_and_transaction` |
| **S09** | Customer accesses admin endpoints | HTTP `403 Forbidden`. | All 6 admin routes returned `403`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_09_unauthorized_admin_access_by_customer` |
| **S10** | Unauthenticated guest accesses protected endpoints & API | Redirected (`302`) to `/login`. | `/cart`, `/checkout`, `/orders`, `/admin/`, `/api/transactions/secure-checkout` returned `302` -> `/login`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_10_unauthorized_endpoint_access_without_login` |
| **S11** | SQL injection in login & search (`' OR '1'='1' --`) | Login rejected; search parameterized; tables intact. | Login failed safely; `Product.query.count() == 2`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_11_sql_injection_attempts` |
| **S12** | Cross-site scripting (`<script>alert('XSS')</script>`) | Escaped as HTML entities (`&lt;script&gt;...`). | Rendered safely as `&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_12_xss_escaping` |
| **S13** | CSRF attack (`POST /login` without CSRF token) | Rejected with HTTP `400 Bad Request`. | Returned `400 Bad Request`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_13_csrf_protection_enforced` |
| **S14** | Session cookie tampering / privilege escalation forgery | Forged cookie discarded; redirected (`302`) to `/login`. | `/admin/` and `/cart` returned `302` -> `/login`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_14_session_cookie_tampering` |
| **S15** | Database log tampering & private key HTTP exposure | `verify_integrity()` returns `False`; key URLs return `404`. | Tampered log detected (`False`); all 4 key paths returned `404`. | **PASS** | `tests/test_audit.py::TestSecurityAttackSimulations::test_attack_15_database_log_tampering_detected_and_private_keys_protected` |
| **S16** | Invalid JSON payload, duplicate transaction ID & invalid role | Malformed JSON rejected (`400`/alert); duplicate `transaction_id` rejected; invalid role rejected; Security Dashboard verified. | All checks passed (`200`/`400`) and security headers verified. | **PASS** | `tests/test_audit.py::TestAdminOperationsAndCryptoLab::test_phase3_additional_security_checks_and_security_dashboard` |
| **S17** | Admin CRUD & role self-demotion guard | Add/edit/deactivate product works; admin cannot demote self. | All CRUD operations succeeded; self-demotion blocked. | **PASS** | `tests/test_audit.py::TestAdminOperationsAndCryptoLab::test_admin_product_order_and_user_management` |
| **S18** | Admin Crypto Lab live buttons (`all`, `aes`, `rsa_oaep`, `rsa_pss`, `pbkdf2`, `hmac`, `tamper`, `replay`, `expired_ts`) | All 9 actions execute real cryptography and return `200 OK`. | All 9 actions returned `200 OK` with verified cryptographic output badges. | **PASS** | `tests/test_audit.py::TestAdminOperationsAndCryptoLab::test_admin_crypto_lab_all_buttons` |

---

## 3. Unit & Integration Cryptographic Test Suite (`C01` – `C22`)

| Test ID | Test Description | Expected Result | Actual Result | Status | Evidence / Log Location |
|---------|------------------|-----------------|---------------|--------|-------------------------|
| **C01–C06** | `TestAES256GCM`: key/nonce lengths (32B/12B), encrypt/decrypt, nonce reuse rejection, auth tag & ciphertext tampering, wrong key rejection | All 6 AES-256-GCM assertions pass. | 6 passed (`AESEncryptionError` raised on all invalid inputs). | **PASS** | `tests/test_crypto.py::TestAES256GCM` (`test_results.txt`) |
| **C07–C10** | `TestRSAOAEP`: 3072-bit key validation, OAEP wrap/unwrap, corrupted ciphertext rejection, wrong private key rejection | All 4 RSA-OAEP-3072 assertions pass. | 4 passed (`RSAEncryptionError` raised on wrong key/corrupted data). | **PASS** | `tests/test_crypto.py::TestRSAOAEP` (`test_results.txt`) |
| **C11–C14** | `TestRSAPSSSignatures`: valid signature, altered package rejection, altered signature rejection, wrong public key rejection | All 4 RSA-PSS-3072 assertions pass. | 4 passed. | **PASS** | `tests/test_crypto.py::TestRSAPSSSignatures` (`test_results.txt`) |
| **C15–C16** | `TestPBKDF2AndHMAC`: PBKDF2-HMAC-SHA256 (260k iterations, unique salts) and HMAC-SHA256 tamper detection | Both tests pass. | 2 passed. | **PASS** | `tests/test_crypto.py::TestPBKDF2AndHMAC` (`test_results.txt`) |
| **C17–C20** | `TestReplayAndSecureTransactionFlow`: duplicate nonce rejection, expired timestamp rejection, DB price recomputation, transaction & Crypto Lab pages | All 4 workflow tests pass. | 4 passed. | **PASS** | `tests/test_crypto.py::TestReplayAndSecureTransactionFlow` (`test_results.txt`) |
| **C21–C22** | `TestTLS13Security`: valid TLS 1.3 connection (`TLSv1.3`) and untrusted certificate rejection (`SSLCertVerificationError`) | Both TLS 1.3 tests pass. | 2 passed. | **PASS** | `tests/test_crypto.py::TestTLS13Security` (`test_results.txt`) |

---

## 4. Core E-Commerce & Access Control Test Suite (`E01` – `E35`)

| Test ID | Test Suite Class | Tests | Expected Result | Actual Result | Status | Evidence / Log Location |
|---------|------------------|-------|-----------------|---------------|--------|-------------------------|
| **E01–E05** | `TestRegistration` | 5 | Register page loads, valid registration succeeds, duplicate email, mismatch & weak password rejected. | 5 passed. | **PASS** | `tests/test_app.py::TestRegistration` (`test_results.txt`) |
| **E06–E10** | `TestLogin` | 5 | Login page loads, valid login succeeds, invalid password, non-existent user & logout verified. | 5 passed. | **PASS** | `tests/test_app.py::TestLogin` (`test_results.txt`) |
| **E11–E15** | `TestProductListing` | 5 | Home page, product catalogue, product details, search, and category filter work. | 5 passed. | **PASS** | `tests/test_app.py::TestProductListing` (`test_results.txt`) |
| **E16–E19** | `TestCart` | 4 | Add to cart, view cart, remove from cart, and guest login requirement work. | 4 passed. | **PASS** | `tests/test_app.py::TestCart` (`test_results.txt`) |
| **E20–E23** | `TestCheckoutAndOrders` | 4 | Checkout page, place order, order history, and empty cart guard work. | 4 passed. | **PASS** | `tests/test_app.py::TestCheckoutAndOrders` (`test_results.txt`) |
| **E24–E32** | `TestAccessControl` | 9 | Admin dashboard/products/orders/users accessible to admin; blocked (`403`) for customer; blocked (`302`) for guest. | 9 passed. | **PASS** | `tests/test_app.py::TestAccessControl` (`test_results.txt`) |
| **E33–E35** | `TestPasswordSecurity` | 3 | Passwords hashed with `pbkdf2:sha256:260000`, verified accurately, unique random salts per user. | 3 passed. | **PASS** | `tests/test_app.py::TestPasswordSecurity` (`test_results.txt`) |

---

## 5. OWASP ZAP / Web Application Security Verification Checklist

| OWASP Control Area | Verification Method | Status | Implementation Details |
|--------------------|---------------------|--------|------------------------|
| **Broken Access Control (A01)** | Automated tests `T06`, `S08`, `S09`, `S10`, `E24–E32` | **PASS** | `@login_required`, `@admin_required`, and strict `order.user_id == current_user.id` ownership checks. |
| **Cryptographic Failures (A02)** | Automated tests `T03–T05`, `T07–T09`, `C01–C22` | **PASS** | AES-256-GCM, RSA-OAEP-3072, RSA-PSS-3072, PBKDF2-HMAC-SHA256 (260k iterations), TLS 1.3. |
| **Injection — SQLi & XSS (A03)** | Automated tests `S11`, `S12` | **PASS** | SQLAlchemy ORM bound parameters and Jinja2 auto-escaping across all templates. |
| **Security Misconfiguration & Headers (A05)** | Automated test `S16` (`set_security_headers` in `app.py`) | **PASS** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`. |
| **Identification & Authentication Failures (A07)** | Automated tests `T01`, `T02`, `S14`, `E33–E35` | **PASS** | `HttpOnly`, `SameSite=Lax` signed session cookies, strong password policy, open-redirect protection. |
| **Software & Data Integrity Failures (A08)** | Automated tests `T04`, `T09`, `S15`, `S16` | **PASS** | RSA-PSS transaction signatures, server-side DB price recomputation, HMAC-SHA256 audit log verification. |
| **Security Logging & Monitoring Failures (A09)** | Verified on `/admin/security-dashboard` and `/admin/security-logs` | **PASS** | All logins, failures, RBAC denials, tampering, and replay attempts logged with HMAC-SHA256 tags. |
