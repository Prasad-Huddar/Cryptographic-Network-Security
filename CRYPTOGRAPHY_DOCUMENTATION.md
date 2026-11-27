# Hybrid Cryptography & Network Security Documentation

This document details the cryptographic architecture, algorithms, key management, replay protection mechanisms, and TLS 1.3 security implemented in **SecureShop (Phase 2)**.

---

## 1. Why Hybrid Cryptography Works in This Project

Asymmetric algorithms like **RSA-3072** solve the key distribution and digital signature problems without pre-shared secrets, but they are computationally expensive and cannot directly encrypt arbitrary-length e-commerce order payloads. Conversely, symmetric authenticated ciphers like **AES-256-GCM** encrypt arbitrary-sized payloads at high speed with built-in integrity tags, but require a shared secret key.

**SecureShop combines both paradigms into a Hybrid Cryptographic Pipeline:**
1. **Payload Confidentiality & Integrity (Symmetric AEAD):** For every single transaction, a fresh ephemeral **256-bit AES key** and a unique **96-bit GCM nonce** are generated to encrypt the JSON transaction payload using **AES-256-GCM**, producing a ciphertext and a **128-bit authentication tag**.
2. **Key Encapsulation (Asymmetric Encryption):** The ephemeral 256-bit AES session key is wrapped (encrypted) with the server's **RSA-3072 public key** using **RSA-OAEP (SHA-256, MGF1-SHA256)**. Only the server holds the matching RSA-3072 private key required to unwrap the session key.
3. **Origin Authenticity & Non-Repudiation (Digital Signatures):** The canonical transaction envelope (`transaction_id`, `user_id`, `timestamp`, `nonce`, `ciphertext_b64`, `gcm_nonce_b64`, `auth_tag_b64`, `wrapped_key_b64`) is signed with the authenticated user's registered client key using **RSA-PSS (SHA-256, MGF1-SHA256)**.
4. **Transport Security:** All network traffic is protected in transit over **TLS 1.3 / HTTPS**.

---

## 2. Why AES-256-GCM Is Used (`services/crypto/aes_encryption.py`)

**AES-256-GCM (Galois/Counter Mode)** is an NIST-standardized Authenticated Encryption with Associated Data (**AEAD**) cipher:
- **256-bit Key Strength:** Provides $2^{256}$ key-space resistance against brute-force attacks. A fresh random 32-byte key (`secrets.token_bytes(32)`) is generated per transaction.
- **96-bit Unique Nonce:** Counter mode requires a unique 12-byte initialization vector (`nonce`) per encryption under a given key. Our implementation tracks `(SHA256(key), nonce)` pairs in memory and enforces fresh key+nonce generation for every transaction so a nonce is never reused with the same key.
- **128-bit Authentication Tag (GHASH):** Unlike legacy CBC mode (which is vulnerable to padding oracle attacks if not paired with encrypt-then-MAC), GCM computes a 16-byte authentication tag over both the ciphertext and Additional Authenticated Data (`AAD = transaction_id:user_id:timestamp:nonce`).
- **Tampering Rejection:** Any modification to even a single bit of the ciphertext, nonce, AAD, or authentication tag causes `AESGCM.decrypt()` to raise `InvalidTag` (`AESEncryptionError`) before any plaintext is released.

---

## 3. Why RSA-OAEP Is Used (`services/crypto/rsa_encryption.py`)

**RSA-OAEP (Optimal Asymmetric Encryption Padding)** with **3072-bit keys**, **SHA-256**, and **MGF1(SHA-256)** is used to wrap the ephemeral 256-bit AES session key:
- **Probabilistic Encryption & IND-CCA2 Security:** Legacy PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher's chosen-ciphertext oracle attacks. RSA-OAEP introduces a random seed and a Feistel network using Mask Generation Function `MGF1-SHA256`, achieving semantic security against adaptive chosen-ciphertext attacks (**IND-CCA2**).
- **3072-bit Key Size:** Meets NIST SP 800-57 recommendations for $\ge 128$-bit security strength.
- **Strict Key Separation:** The server's RSA-3072 private key is stored inside `instance/keys/server_rsa_private.pem` (outside public `static/` directories) and never leaves the server. Clients only receive `server_rsa_public.pem`.

---

## 4. Why RSA-PSS Is Used (`services/crypto/digital_signature.py`)

**RSA-PSS (Probabilistic Signature Scheme)** with **SHA-256** and **MGF1(SHA-256)** signs the canonical transaction package:
- **Probabilistic Salt & Tight Security Proof:** Unlike deterministic PKCS#1 v1.5 signatures, RSA-PSS binds a random salt (`PSS.MAX_LENGTH`) with the SHA-256 message digest via MGF1, providing a tight cryptographic reduction to the RSA problem.
- **Canonical Package Signing:** Before signing, the transaction fields (`transaction_id`, `user_id`, `timestamp`, `nonce`, `ciphertext_b64`, `gcm_nonce_b64`, `auth_tag_b64`, `wrapped_key_b64`) are serialized into deterministic canonical UTF-8 JSON (`sort_keys=True, separators=(',', ':')`).
- **Registered Client Public Key:** Each user account has a dedicated client RSA-3072 public key (`User.public_key_pem`) registered to their identity, while the client private key resides in the client keystore (`instance/client_keys/`). The server verifies the signature strictly against `authenticated_user.public_key_pem`, ensuring another user cannot forge a signature on behalf of the customer.

---

## 5. How PBKDF2-HMAC-SHA256 Works (`services/crypto/integrity.py`)

User passwords are never stored in plaintext. Instead, `hash_password_pbkdf2()` derives a 256-bit cryptographic key using **PBKDF2-HMAC-SHA256** (`cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`):
- **Unique 128-bit Random Salt:** Every password hash generates a fresh 16-byte salt (`secrets.token_bytes(16)`), preventing rainbow-table precomputation and ensuring two users with identical passwords have completely different stored hashes.
- **260,000 Iterations:** Applies 260,000 rounds of pseudorandom `HMAC-SHA256` stretching (configurable via `PBKDF2_ITERATIONS`), significantly increasing the computational cost of offline GPU brute-force attacks.
- **Constant-Time Verification:** `PBKDF2HMAC.verify()` compares the derived key in constant time to prevent timing side-channel leaks.

---

## 6. How HMAC-SHA256 Protects Logs & Records (`services/crypto/integrity.py`)

**HMAC-SHA256 (Hash-based Message Authentication Code)** provides tamper detection for database audit logs (`SecurityLog`) and stored transactions (`Transaction`):
- **Dedicated Secret Key:** A 256-bit secret key is generated via `secrets.token_bytes(32)` and stored in `instance/keys/hmac_secret.key` (or injected via `HMAC_SECRET_KEY` environment variable) — never hardcoded in source code.
- **Dual-Pass Construction:** Computes $\text{HMAC}(K, m) = \text{SHA256}\big((K' \oplus \text{opad}) \parallel \text{SHA256}((K' \oplus \text{ipad}) \parallel m)\big)$, which is immune to SHA-256 length-extension attacks.
- **Database Tamper Detection:** If an attacker with direct SQLite access alters a `SecurityLog` description or a `Transaction` amount, `verify_integrity()` fails immediately during audit inspection.

---

## 7. How Nonce, Timestamp, and Transaction ID Prevent Replay Attacks (`services/crypto/transaction_security.py`)

Even if an adversary captures a validly encrypted and signed transaction package in transit, **three layers of replay defense** prevent reuse:
1. **UUIDv4 Transaction ID Validation:** Each request carries a unique UUIDv4 `transaction_id` verified against both `ConsumedNonce` and `Transaction` tables.
2. **UTC Timestamp Window Validation:** The client includes an ISO-8601 UTC timestamp (`timestamp`), which is also bound into the AES-GCM AAD and RSA-PSS signature. The server enforces a configurable freshness window (`±300 seconds` by default). Expired packets (e.g., replayed 10 minutes later) or far-future packets are rejected immediately.
3. **Atomic Nonce Consumption:** Every request includes a 128-bit random `nonce`. Within the freshness window, the server inserts `(nonce, transaction_id)` into the `consumed_nonces` table inside an atomic database savepoint (`db.session.begin_nested()`) backed by `UNIQUE` constraints on both `nonce` and `transaction_id`. Concurrent or sequential replays trigger an `IntegrityError`, aborting the transaction and logging a `REPLAY_ATTEMPT` security event.

---

## 8. How TLS 1.3 Protects Communication & How to Trust the Local Dev CA

### Transport Security (`services/crypto/transaction_security.py`)
- **TLS 1.3 Protocol:** Configured via Python's `ssl.SSLContext` with `ssl.TLSVersion.TLSv1_3`, providing mandatory Ephemeral Diffie-Hellman (**ECDHE**) forward secrecy and AEAD-only cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
- **Certificate Storage:** Generated X.509 certificates and private keys are stored in `instance/certs/` (never inside `static/`):
  - `instance/certs/dev_root_ca.crt` & `dev_root_ca.key`: Local Development Root CA (RSA-3072).
  - `instance/certs/localhost_server.crt` & `localhost_server.key`: Server certificate signed by the Local Development Root CA with Subject Alternative Names (`DNS:localhost`, `IP:127.0.0.1`).
- **Strict Client Certificate Verification:** `create_tls_client_context()` enforces `ssl.CERT_REQUIRED` and `check_hostname = True` against `dev_root_ca.crt`, rejecting untrusted self-signed or mismatched certificates.

### How to Trust the Local Development Root CA on Windows / Browser
> **Note:** A local development CA certificate is strictly for local development/testing. Production deployments use `ProductionConfig` with publicly trusted CA certificates (e.g., Let's Encrypt / DigiCert).

1. **Windows Certificate Store (PowerShell as Current User):**
   ```powershell
   Import-Certificate -FilePath "instance\certs\dev_root_ca.crt" -CertStoreLocation Cert:\CurrentUser\Root
   ```
2. **Python / curl Clients:**
   - Python: `create_tls_client_context()` automatically loads `instance/certs/dev_root_ca.crt`.
   - curl: `curl --cacert instance/certs/dev_root_ca.crt https://127.0.0.1:5443/`

---

## 9. Complete Client-to-Server Secure Transaction Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                               CLIENT WORKFLOW                              │
│                                                                            │
│  1. Authenticate user session                                              │
│  2. Establish HTTPS / TLS 1.3 connection                                   │
│  3. Generate UUIDv4 transaction_id                                         │
│  4. Generate UTC ISO-8601 timestamp                                        │
│  5. Generate 128-bit cryptographic replay nonce                            │
│  6. Build JSON transaction payload (items, shipping_address, metadata)     │
│  7. Generate fresh 256-bit AES session key + unique 96-bit GCM nonce       │
│  8. Encrypt payload with AES-256-GCM -> (ciphertext, 128-bit auth_tag)     │
│  9. Wrap 256-bit AES key with Server RSA-3072 Public Key (RSA-OAEP-SHA256) │
│ 10. Sign canonical envelope with Client RSA-3072 Private Key (RSA-PSS)     │
│ 11. Transmit encrypted + signed package to Server                          │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ HTTPS / TLS 1.3
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                               SERVER WORKFLOW                              │
│                                                                            │
│  1. Verify user authentication (active session)                            │
│  2. Verify customer/admin role authorization                               │
│  3. Validate transaction_id format (UUIDv4) & uniqueness                   │
│  4. Validate UTC timestamp within ±300s freshness window                   │
│  5. Atomically consume replay nonce in consumed_nonces table (UNIQUE)      │
│  6. Verify RSA-PSS digital signature using registered User.public_key_pem  │
│  7. Unwrap 256-bit AES session key using Server RSA-3072 Private Key       │
│  8. Decrypt payload with AES-256-GCM & verify 128-bit authentication tag   │
│  9. Validate inner metadata & recompute total from DB Product.price        │
│ 10. Store Order, OrderItems, and encrypted Transaction artifacts (Base64)  │
│ 11. Compute & store HMAC-SHA256 integrity tags on Transaction & SecurityLog│
│ 12. Return verified transaction confirmation to client                     │
└────────────────────────────────────────────────────────────────────────────┘
```
