# FACULTY DEMONSTRATION GUIDE (`DEMO_GUIDE.md`)
## Secure E-Commerce Transaction System Using Hybrid Cryptography and TLS

Use this structured 10-minute walkthrough to demonstrate all functional, cryptographic, and network security capabilities of the project to a faculty member or examiner.

---

## Step 1: Start the Application & Show Dual HTTP / TLS 1.3 Listeners (1 Min)

1. Open PowerShell in `C:\Users\Manish\Downloads\CNS Project`:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   .\venv\Scripts\Activate.ps1
   python app.py
   ```
2. Point out the startup output showing:
   - **HTTP Storefront:** `http://127.0.0.1:5000`
   - **HTTPS / TLS 1.3 Listener:** `https://127.0.0.1:5443`
   - Automatic provisioning of the 3072-bit server RSA keypair (`instance/keys/`), 256-bit HMAC secret (`instance/keys/hmac_secret.key`), and X.509 SAN certificates (`instance/certs/`).

---

## Step 2: Storefront & Customer Registration with Key Provisioning (2 Min)

1. Open **`http://127.0.0.1:5000`** (or **`https://127.0.0.1:5443`**).
2. Highlight the redesigned commercial homepage:
   - Deep-navy navigation bar, hero section (`"Quality products. Secured for you."`), Featured Products, Shopping Benefits strip, and Active Security Architecture cards.
3. Click **Register** (`/register`) and create a new customer account:
   - Show the **password visibility toggle** and explain that on registration:
     - The password is hashed with **PBKDF2-HMAC-SHA256 (`260,000` iterations, 128-bit random salt)**.
     - A dedicated **3072-bit RSA keypair** is generated and its public key (`public_key_pem`) is registered to the user record for **RSA-PSS** digital signature verification.

---

## Step 3: Product Catalogue, Cart & Hybrid Cryptographic Checkout (2.5 Min)

1. Log in as the new customer at **`/login`**.
2. Browse **`/products`**:
   - Demonstrate **Category Filtering** (`Electronics`), **Keyword Search**, and **Sorting** (`Price: Low to High`).
3. Click any product to open **`/product/<id>`**, adjust the quantity using the **`+`/`-` stepper**, and click **Add to Cart**.
4. Open **`/cart`**:
   - Show the two-column layout and the **"Your order"** summary card displaying live backend-calculated totals.
5. Click **Proceed to Checkout** (`/checkout`):
   - Point out the **4-Step Cryptographic Pipeline explanation** on the checkout page:
     1. **AES-256-GCM** encryption (fresh 256-bit key + 96-bit nonce + 128-bit tag)
     2. **RSA-OAEP-3072** wrapping of the AES key
     3. **RSA-PSS-3072** digital signature over the canonical envelope
     4. **Atomic Nonce + Timestamp + UUIDv4** replay protection
6. Enter a delivery address and click **Checkout securely — Place Order**.

---

## Step 4: Inspect the Cryptographic Transaction Certificate (1.5 Min)

1. On the **Order Detail** page (`/order/<id>`), click **View Full Cryptographic Proof** (`/transaction/<transaction_id>`).
2. Show the faculty member the 4 green verification badges and the **Stored Cryptographic Envelope (Public Artifacts)**:
   - `AES-256-GCM Encrypted` (`96-bit Nonce`, `128-bit Authentication Tag`, `Encrypted Payload` in Base64)
   - `VERIFIED (RSA-PSS)` (`3072-bit Digital Signature` verified against the customer's registered public key)
   - `Nonce & Timestamp Valid` (`128-bit Replay Nonce` atomically consumed in `consumed_nonces`)
   - `HMAC-SHA256 Verified` (`256-bit Record HMAC Digest`)

---

## Step 5: Demonstrate Role-Based Access Control (RBAC) (1 Min)

1. While still logged in as the customer, manually visit **`http://127.0.0.1:5000/admin/`** in the address bar.
2. Show that the server immediately blocks access with **`403 — Access Denied`** and records an HMAC-signed `ACCESS_DENIED` event in the security audit log.

---

## Step 6: Admin Dashboard, Security Dashboard & Live Crypto Lab (2 Min)

1. Log out and sign in as Admin:
   - **Email:** `admin@secureshop.com`
   - **Password:** `Admin@12345` *(if prompted on first login, update password or use existing admin password)*
2. Navigate to **`/admin/security-dashboard`**:
   - Show live database metrics for **Total Transactions**, **Successful Transactions**, **Rejected Transactions**, **Tampering Attempts**, **Replay Attempts**, **Unauthorized Access Attempts** (including the `403` from Step 5!), and **Consumed Nonces**.
3. Navigate to **`/admin/crypto-demo`** (**Hybrid Cryptography & Security Demonstration Lab**):
   - Click **Run All Live Tests** or individual buttons (`1. AES-256-GCM`, `2. RSA-OAEP-3072`, `3. RSA-PSS Signature`, `4. PBKDF2-SHA256`, `5. HMAC-SHA256`, `6. Simulate Ciphertext Tampering`, `7. Simulate Nonce Replay`, `8. Simulate Expired Timestamp`).
   - Point out how flipping a single byte in the ciphertext triggers `ATTACK BLOCKED` and how submitting the same nonce twice in SQLite triggers `REPLAY REJECTED`.

---

## Step 7: Execute the 85 Automated Tests Live in Terminal (1 Min)

In PowerShell, run:
```powershell
pytest -v
```
Show the examiner that all **85 automated tests** (including the 10 Official CNS Test Cases `T01`–`T10` and 18 security attack simulations) pass with **0 failures**.
