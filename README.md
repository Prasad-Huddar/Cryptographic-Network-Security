# SecureShop — Secure E-Commerce Transaction System

An academic and practical prototype of a **Secure E-Commerce Transaction System** using **Hybrid Cryptography** (`AES-256-GCM`, `RSA-OAEP-3072`, `RSA-PSS-3072`), **Key Derivation & Integrity** (`PBKDF2-HMAC-SHA256`, `HMAC-SHA256`), **Replay Protection** (Nonce, Timestamp, UUIDv4 Transaction ID), and **TLS 1.3 / HTTPS**.

---

## Features

### Phase 1 — Core E-Commerce & Access Control
- **User Authentication:** Registration, login, logout, and password change with strong password policy enforcement.
- **Role-Based Access Control (RBAC):** Customer, Admin, and Guest permission boundaries with `403 — Access Denied` enforcement.
- **Product Catalogue:** Search, category filtering, pagination, and product detail views.
- **Shopping Cart & Checkout:** Session-backed cart management, stock validation, and order creation.
- **Admin Dashboard:** Manage products, orders, users, and security audit logs.

### Phase 2 — Hybrid Cryptography & Network Security
- **AES-256-GCM Payload Encryption (`services/crypto/aes_encryption.py`):** Fresh 256-bit AES key and unique 96-bit GCM nonce per transaction, with 128-bit authentication tag verification and nonce-reuse prevention.
- **RSA-OAEP Key Wrapping (`services/crypto/rsa_encryption.py`):** 3072-bit RSA key encapsulation using SHA-256 and MGF1-SHA256.
- **RSA-PSS Digital Signatures (`services/crypto/digital_signature.py`):** 3072-bit RSA-PSS signatures over canonical transaction packages verified against each user's registered public key (`User.public_key_pem`).
- **PBKDF2-HMAC-SHA256 & HMAC-SHA256 (`services/crypto/integrity.py`):** 260,000-iteration salted password derivation and HMAC-SHA256 tamper detection for `SecurityLog` and `Transaction` records.
- **Atomic Replay Protection (`services/crypto/transaction_security.py`):** UUIDv4 transaction ID validation, configurable `±300s` UTC timestamp tolerance, and atomic nonce consumption in the `consumed_nonces` table.
- **Server-Side Price Recomputation:** Never trusts client-submitted prices or totals; recomputes order totals strictly from database `Product.price` records.
- **TLS 1.3 / HTTPS:** Local Development Root CA and SAN server certificate (`instance/certs/`) with TLS 1.3 server/client context factories.
- **Transaction Security Proof & Admin Crypto Lab:**
  - Customer/Admin Transaction Proof page: `/transaction/<transaction_id>`
  - Admin Interactive Cryptography Demonstration Lab: `/admin/crypto-demo`

---

## Quick Start (Windows PowerShell)

1. **Activate the virtual environment:**
   ```powershell
   cd "C:\Users\Manish\Downloads\CNS Project"
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   .\venv\Scripts\Activate.ps1
   ```

2. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```powershell
   python app.py
   ```
   - **HTTP URL:** `http://127.0.0.1:5000/`
   - **HTTPS (TLS 1.3) URL:** `https://127.0.0.1:5443/` (or run `python app.py --https` to serve HTTPS on port `5000`)
   - **Default Admin Account:** `admin@secureshop.com` / `Admin@12345`

4. **Run the complete test suite (57 tests):**
   ```powershell
   pytest -v
   ```

---

## Documentation

- [CRYPTOGRAPHY_DOCUMENTATION.md](CRYPTOGRAPHY_DOCUMENTATION.md) — Detailed technical documentation of all cryptographic algorithms, replay protection, TLS 1.3 setup, and the 11-step client / 12-step server transaction workflow.
