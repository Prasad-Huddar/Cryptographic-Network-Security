"""
Transaction Security, Replay Protection, Hybrid Cryptographic Workflow, and TLS 1.3 Module.

Implements:
- Nonce-based replay protection with atomic database consumption
- Timestamp validation with configurable tolerance window
- UUIDv4 transaction ID validation
- Complete 11-step client hybrid encryption + signing workflow
- Complete 12-step server verification + unwrapping + decryption + price recomputation workflow
- Local Development Root CA & Server TLS Certificate generation (outside static/)
- TLS 1.3 Server and Client SSLContext factories with strict certificate verification
"""
import datetime
from datetime import timezone
import ipaddress
import json
import secrets
import ssl
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.exc import IntegrityError

from database.database import db
from services.crypto.aes_encryption import (
    AESEncryptionError,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_gcm_nonce,
)
from services.crypto.digital_signature import (
    DigitalSignatureError,
    sign_transaction_package,
    verify_transaction_signature,
)
from services.crypto.integrity import compute_transaction_hmac
from services.crypto.key_storage import CERTS_DIR, ensure_key_directories
from services.crypto.rsa_encryption import (
    RSAEncryptionError,
    unwrap_aes_key,
    wrap_aes_key,
)
from services.crypto.rsa_key_management import (
    get_server_private_key_pem,
    get_server_public_key_pem,
    provision_client_keypair,
)

DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300  # 5 minutes


class TransactionSecurityError(Exception):
    """Raised when a transaction fails security validation."""
    pass


# ==============================================================================
# Replay Protection Helpers (Transaction ID, Timestamp, Nonce)
# ==============================================================================

def generate_transaction_id() -> str:
    """Generate a cryptographically random UUIDv4 transaction identifier."""
    return str(uuid.uuid4())


def generate_replay_nonce() -> str:
    """Generate a unique 128-bit (32-hex-char) cryptographically random replay nonce."""
    return secrets.token_hex(16)


def generate_timestamp() -> str:
    """Generate a current UTC ISO-8601 timestamp string."""
    return datetime.datetime.now(timezone.utc).isoformat()


def validate_transaction_id(tx_id: str) -> tuple[bool, str]:
    """
    Validate that transaction_id is a well-formed UUID and has not been used before.
    Returns (is_valid, error_message).
    """
    if not tx_id or not isinstance(tx_id, str):
        return False, "Missing or invalid transaction ID."
    try:
        parsed = uuid.UUID(tx_id)
        if str(parsed).lower() != tx_id.strip().lower():
            return False, "Malformed transaction ID format."
    except (ValueError, AttributeError, TypeError):
        return False, "Invalid UUID format for transaction ID."

    # Check if already present in ConsumedNonce or Transaction tables
    from models.transaction import ConsumedNonce, Transaction
    if ConsumedNonce.query.filter_by(transaction_id=tx_id).first():
        return False, "Duplicate transaction ID detected (replay rejected)."
    if Transaction.query.filter_by(transaction_id=tx_id).first():
        return False, "Transaction ID has already been processed."

    return True, ""


def validate_timestamp(
    timestamp_val: str | float | int,
    tolerance_seconds: int = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS
) -> tuple[bool, str]:
    """
    Validate that the client timestamp is recent and within ±tolerance_seconds of current UTC time.
    Rejects expired or far-future timestamps.
    """
    if timestamp_val is None or timestamp_val == '':
        return False, "Missing transaction timestamp."

    now_utc = datetime.datetime.now(timezone.utc)
    try:
        if isinstance(timestamp_val, (int, float)):
            tx_dt = datetime.datetime.fromtimestamp(float(timestamp_val), tz=timezone.utc)
        elif isinstance(timestamp_val, str):
            ts_str = timestamp_val.strip()
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            tx_dt = datetime.datetime.fromisoformat(ts_str)
            if tx_dt.tzinfo is None:
                tx_dt = tx_dt.replace(tzinfo=timezone.utc)
            else:
                tx_dt = tx_dt.astimezone(timezone.utc)
        else:
            return False, "Invalid timestamp type."
    except Exception:
        return False, "Invalid ISO-8601 timestamp format."

    delta = (now_utc - tx_dt).total_seconds()
    if delta > tolerance_seconds:
        return False, f"Transaction timestamp expired ({int(delta)}s old; max tolerance {tolerance_seconds}s)."
    if delta < -tolerance_seconds:
        return False, "Transaction timestamp is too far in the future (clock skew / invalid timestamp)."

    return True, ""


def consume_nonce_atomically(
    nonce: str,
    transaction_id: str,
    user_id: int | None,
    client_timestamp: str
) -> tuple[bool, str]:
    """
    Validate and atomically consume a replay nonce in the database.
    Uses a nested transaction savepoint and database UNIQUE constraints on both
    nonce and transaction_id to prevent concurrent replay race conditions.
    """
    if not nonce or not isinstance(nonce, str) or len(nonce.strip()) < 16:
        return False, "Invalid or too-short replay nonce."

    nonce_clean = nonce.strip()
    tx_clean = transaction_id.strip()

    from models.transaction import ConsumedNonce
    try:
        with db.session.begin_nested():
            record = ConsumedNonce(
                nonce=nonce_clean,
                transaction_id=tx_clean,
                user_id=user_id,
                client_timestamp=str(client_timestamp),
            )
            db.session.add(record)
            db.session.flush()
        db.session.commit()
        return True, ""
    except IntegrityError:
        db.session.rollback()
        return False, "Replay attack detected: nonce or transaction ID has already been consumed."
    except Exception as exc:
        db.session.rollback()
        return False, f"Failed to record replay nonce: {exc}"


# ==============================================================================
# Client-Side 11-Step Secure Transaction Package Builder
# ==============================================================================

def build_client_transaction_package(
    user_id: int,
    items: list[dict],
    shipping_address: str,
    client_private_key_pem: bytes | str | None = None,
    server_public_key_pem: bytes | str | None = None,
    payment_method: str = 'hybrid_crypto_payment',
    transaction_id: str | None = None,
    timestamp: str | None = None,
    nonce: str | None = None,
    client_reported_total: float | None = None,
) -> dict:
    """
    Execute the Client Secure Transaction Workflow (Steps 3 through 10):
      3. Create transaction ID
      4. Generate UTC timestamp
      5. Generate unique cryptographic replay nonce
      6. Build transaction payload
      7. Generate fresh 256-bit AES key
      8. Encrypt transaction payload using AES-256-GCM (with unique 96-bit nonce)
      9. Wrap AES-256 key using server RSA-3072 public key and RSA-OAEP (SHA-256)
     10. Sign canonical transaction metadata + ciphertext package using client RSA-PSS key
    """
    tx_id = transaction_id if transaction_id is not None else generate_transaction_id()
    ts_str = timestamp if timestamp is not None else generate_timestamp()
    replay_nonce = nonce if nonce is not None else generate_replay_nonce()

    if client_reported_total is None:
        client_reported_total = sum(
            float(item.get('price', 0.0)) * int(item.get('quantity', 1))
            for item in items
        )

    payload_dict = {
        'transaction_id': tx_id,
        'user_id': user_id,
        'timestamp': ts_str,
        'nonce': replay_nonce,
        'shipping_address': shipping_address,
        'payment_method': payment_method,
        'items': items,
        'client_total': round(float(client_reported_total), 2),
    }
    payload_bytes = json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')

    # Step 7 & 8: Fresh AES-256 key + AES-256-GCM authenticated encryption
    aes_key = generate_aes_key()
    gcm_nonce = generate_gcm_nonce(aes_key)
    aad_bytes = f"{tx_id}:{user_id}:{ts_str}:{replay_nonce}".encode('utf-8')
    enc_result = encrypt_aes_gcm(payload_bytes, key=aes_key, nonce=gcm_nonce, associated_data=aad_bytes)

    # Step 9: Wrap fresh AES-256 key with Server RSA-3072 Public Key using RSA-OAEP
    wrap_result = wrap_aes_key(aes_key, public_key_pem=server_public_key_pem)

    # Assemble unsigned envelope
    package = {
        'transaction_id': tx_id,
        'user_id': user_id,
        'timestamp': ts_str,
        'nonce': replay_nonce,
        'ciphertext_b64': enc_result['ciphertext_b64'],
        'gcm_nonce_b64': enc_result['nonce_b64'],
        'auth_tag_b64': enc_result['auth_tag_b64'],
        'wrapped_key_b64': wrap_result['wrapped_key_b64'],
    }

    # Step 10: Sign canonical package using Client RSA-PSS Private Key
    if client_private_key_pem is None:
        from models.user import User
        user = db.session.get(User, user_id)
        identifier = user.email if user else user_id
        client_private_key_pem, pub_pem = provision_client_keypair(identifier)
        if user and not user.public_key_pem:
            user.public_key_pem = pub_pem.decode('utf-8')
            db.session.commit()

    sig_result = sign_transaction_package(package, client_private_key_pem)
    package['signature_b64'] = sig_result['signature_b64']
    return package


# ==============================================================================
# Server-Side 12-Step Verification, Decryption & Order Processing Workflow
# ==============================================================================

def verify_and_process_transaction_package(
    package: dict,
    authenticated_user,
    tolerance_seconds: int = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
):
    """
    Execute the Server Secure Transaction Workflow (Steps 1 through 12):
      1. Verify authentication
      2. Verify customer authorization
      3. Validate transaction ID
      4. Validate timestamp
      5. Validate & atomically consume replay nonce
      6. Verify RSA-PSS digital signature against registered client public key
      7. Unwrap AES-256 key using server RSA-3072 private key (RSA-OAEP)
      8. Decrypt transaction payload using AES-256-GCM and verify 128-bit auth tag
      9. Validate transaction contents and recompute order total from trusted DB product prices
     10. Store Order, OrderItems, and encrypted Transaction record
     11. Store signature, verification status, and HMAC-SHA256 integrity tag
     12. Return transaction confirmation
    """
    from models.order import Order, OrderItem
    from models.product import Product
    from models.transaction import Transaction
    from services.auth_service import log_security_event

    # Step 1: Verify authentication
    if not authenticated_user or not getattr(authenticated_user, 'is_authenticated', False):
        log_security_event('ACCESS_DENIED', 'Unauthenticated transaction submission attempt')
        return False, "Authentication required.", None, None

    if not authenticated_user.is_active_user:
        log_security_event('ACCESS_DENIED', f'Disabled user {authenticated_user.email} attempted transaction', authenticated_user.id)
        return False, "Account is disabled.", None, None

    # Step 2: Verify customer authorization
    if authenticated_user.role not in ('customer', 'admin'):
        log_security_event('ACCESS_DENIED', f'Unauthorized role {authenticated_user.role} attempted transaction', authenticated_user.id)
        return False, "Unauthorized role for transaction.", None, None

    if not isinstance(package, dict):
        return False, "Invalid transaction package format.", None, None

    tx_id = str(package.get('transaction_id', '')).strip()
    ts_str = str(package.get('timestamp', '')).strip()
    replay_nonce = str(package.get('nonce', '')).strip()
    package_user_id = package.get('user_id')

    if package_user_id != authenticated_user.id:
        log_security_event(
            'ACCESS_DENIED',
            f'User ID mismatch in transaction package (expected {authenticated_user.id}, got {package_user_id})',
            authenticated_user.id
        )
        return False, "Transaction user ID does not match authenticated user.", None, None

    # Step 3: Validate transaction ID
    tx_valid, tx_err = validate_transaction_id(tx_id)
    if not tx_valid:
        log_security_event('REPLAY_ATTEMPT', f'Transaction ID validation failed ({tx_id}): {tx_err}', authenticated_user.id)
        return False, tx_err, None, None

    # Step 4: Validate timestamp
    ts_valid, ts_err = validate_timestamp(ts_str, tolerance_seconds=tolerance_seconds)
    if not ts_valid:
        log_security_event('REPLAY_ATTEMPT', f'Timestamp validation failed for tx {tx_id}: {ts_err}', authenticated_user.id)
        return False, ts_err, None, None

    # Step 5: Validate and atomically consume replay nonce
    nonce_ok, nonce_err = consume_nonce_atomically(
        nonce=replay_nonce,
        transaction_id=tx_id,
        user_id=authenticated_user.id,
        client_timestamp=ts_str
    )
    if not nonce_ok:
        log_security_event('REPLAY_ATTEMPT', f'Replay nonce rejected for tx {tx_id}: {nonce_err}', authenticated_user.id)
        return False, nonce_err, None, None

    # Step 6: Verify RSA-PSS digital signature against the user's registered public key
    client_pub_pem = authenticated_user.ensure_client_public_key()
    db.session.commit()

    signature_b64 = package.get('signature_b64', '')
    sig_valid = verify_transaction_signature(package, signature_b64, client_pub_pem)
    if not sig_valid:
        log_security_event(
            'INVALID_SIGNATURE',
            f'RSA-PSS signature verification failed for transaction {tx_id}',
            authenticated_user.id
        )
        log_security_event(
            'TAMPERING_DETECTED',
            f'Transaction package tampering or untrusted signing key rejected for tx {tx_id}',
            authenticated_user.id
        )
        return False, "Digital signature verification failed: transaction altered or untrusted key.", None, None

    log_security_event('SIGNATURE_VERIFIED', f'RSA-PSS signature verified for transaction {tx_id}', authenticated_user.id)

    # Step 7: Unwrap AES-256 key using server RSA-3072 private key and RSA-OAEP
    try:
        aes_key = unwrap_aes_key(package.get('wrapped_key_b64', ''), get_server_private_key_pem())
    except RSAEncryptionError as exc:
        log_security_event('TAMPERING_DETECTED', f'RSA-OAEP key unwrapping failed for tx {tx_id}: {exc}', authenticated_user.id)
        return False, "Failed to unwrap session key (RSA-OAEP decryption failed).", None, None

    # Step 8: Decrypt transaction payload using AES-256-GCM and verify 128-bit auth tag
    aad_bytes = f"{tx_id}:{authenticated_user.id}:{ts_str}:{replay_nonce}".encode('utf-8')
    try:
        decrypted_bytes = decrypt_aes_gcm(
            ciphertext=package.get('ciphertext_b64', ''),
            key=aes_key,
            nonce=package.get('gcm_nonce_b64', ''),
            auth_tag=package.get('auth_tag_b64', ''),
            associated_data=aad_bytes
        )
        payload = json.loads(decrypted_bytes.decode('utf-8'))
    except (AESEncryptionError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        log_security_event('TAMPERING_DETECTED', f'AES-256-GCM authentication/decryption failed for tx {tx_id}: {exc}', authenticated_user.id)
        return False, "Transaction payload decryption failed: ciphertext or authentication tag tampered.", None, None

    log_security_event('ENCRYPTION_SUCCESS', f'AES-256-GCM payload verified and decrypted for tx {tx_id}', authenticated_user.id)

    # Step 9: Validate decrypted transaction contents & recompute prices from server DB
    if (
        payload.get('transaction_id') != tx_id
        or payload.get('nonce') != replay_nonce
        or payload.get('timestamp') != ts_str
        or payload.get('user_id') != authenticated_user.id
    ):
        log_security_event('TAMPERING_DETECTED', f'Inner payload metadata mismatch for tx {tx_id}', authenticated_user.id)
        return False, "Inner payload metadata mismatch.", None, None

    shipping_address = str(payload.get('shipping_address', '')).strip()
    if not shipping_address or len(shipping_address) < 10:
        return False, "Please enter a valid shipping address (at least 10 characters).", None, None

    raw_items = payload.get('items', [])
    if not raw_items or not isinstance(raw_items, list):
        return False, "Cart is empty.", None, None

    server_total = 0.0
    order_items = []

    for item in raw_items:
        product_id = item.get('product_id')
        quantity = int(item.get('quantity', 0))
        if quantity <= 0:
            return False, "Invalid item quantity.", None, None

        product = db.session.get(Product, product_id)
        if not product or not product.is_active:
            return False, f"Product '{item.get('name', product_id)}' is no longer available.", None, None
        if product.stock < quantity:
            return False, f"Insufficient stock for '{product.name}'. Only {product.stock} available.", None, None

        # Always use trusted database product.price, NEVER client-submitted price
        trusted_price = float(product.price)
        order_item = OrderItem(
            product_id=product.id,
            product_name=product.name,
            quantity=quantity,
            price=trusted_price,
        )
        order_items.append(order_item)
        server_total += trusted_price * quantity

        # Deduct stock
        product.stock -= quantity

    server_total = round(server_total, 2)

    # Step 10 & 11: Store Order, OrderItems, and encrypted Transaction record with verification status & HMAC
    order = Order(
        order_number=tx_id[:8].upper(),
        user_id=authenticated_user.id,
        total_amount=server_total,
        shipping_address=shipping_address,
        payment_method=str(payload.get('payment_method', 'hybrid_crypto_payment')),
        status='confirmed',
    )
    db.session.add(order)
    db.session.flush()

    for oi in order_items:
        oi.order_id = order.id
        db.session.add(oi)

    verification_status = 'VERIFIED'
    tx_hmac = compute_transaction_hmac(
        transaction_id=tx_id,
        user_id=authenticated_user.id,
        order_id=order.id,
        amount=server_total,
        encrypted_payload=package['ciphertext_b64'],
        wrapped_aes_key=package['wrapped_key_b64'],
        gcm_nonce=package['gcm_nonce_b64'],
        auth_tag=package['auth_tag_b64'],
        digital_signature=signature_b64,
        replay_nonce=replay_nonce,
        client_timestamp=ts_str,
        verification_status=verification_status,
    )

    transaction = Transaction(
        transaction_id=tx_id,
        user_id=authenticated_user.id,
        order_id=order.id,
        amount=server_total,
        status='completed',
        payment_method=order.payment_method,
        encrypted_payload=package['ciphertext_b64'],
        wrapped_aes_key=package['wrapped_key_b64'],
        gcm_nonce=package['gcm_nonce_b64'],
        auth_tag=package['auth_tag_b64'],
        digital_signature=signature_b64,
        client_timestamp=ts_str,
        replay_nonce=replay_nonce,
        verification_status=verification_status,
        encryption_algorithm='AES-256-GCM + RSA-OAEP-3072 + RSA-PSS-SHA256',
        integrity_hmac=tx_hmac,
    )
    db.session.add(transaction)
    db.session.commit()

    log_security_event(
        'TRANSACTION_CREATED',
        f'Secure transaction {tx_id} stored and verified for order {order.order_number}',
        authenticated_user.id
    )
    log_security_event(
        'ORDER_PLACED',
        f'Order {order.order_number} placed for ₹{server_total:,.2f} (Hybrid Crypto Verified)',
        authenticated_user.id
    )

    return True, f"Order {order.order_number} placed successfully!", order, transaction


# ==============================================================================
# HTTPS / TLS 1.3 Certificate Generation & SSLContext Configuration
# ==============================================================================

def get_tls_cert_paths() -> dict[str, Path]:
    """Return paths for the local Development Root CA and Server TLS certificate/key."""
    ensure_key_directories()
    return {
        'ca_cert': CERTS_DIR / 'dev_root_ca.crt',
        'ca_key': CERTS_DIR / 'dev_root_ca.key',
        'server_cert': CERTS_DIR / 'localhost_server.crt',
        'server_key': CERTS_DIR / 'localhost_server.key',
    }


def ensure_local_tls_certificates() -> dict[str, Path]:
    """
    Generate a local Development Root CA and a CA-signed Server TLS certificate
    for localhost / 127.0.0.1 if they do not already exist in instance/certs/.
    Certificates are kept strictly outside public static directories.
    """
    paths = get_tls_cert_paths()
    if all(p.exists() for p in paths.values()):
        return paths

    now = datetime.datetime.now(timezone.utc)

    # 1. Generate Development Root CA (RSA 3072-bit)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShop Development CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureShop Local Development Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Generate Server Certificate signed by the Development Root CA
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShop E-Commerce"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    paths['ca_key'].write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths['ca_cert'].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths['server_key'].write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths['server_cert'].write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    return paths


def generate_untrusted_self_signed_cert(output_dir: Path | None = None) -> tuple[Path, Path]:
    """
    Generate a separate untrusted self-signed certificate (not signed by our Dev Root CA)
    for testing invalid certificate rejection in TLS verification tests.
    """
    target_dir = output_dir or CERTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    cert_path = target_dir / 'untrusted_self_signed.crt'
    key_path = target_dir / 'untrusted_self_signed.key'

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    now = datetime.datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Untrusted Rogue Cert"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def create_tls_server_context(
    cert_path: Path | str | None = None,
    key_path: Path | str | None = None,
    require_tls13: bool = True,
) -> ssl.SSLContext:
    """
    Create a secure server-side SSLContext configured for TLS 1.3 (or TLS 1.2+ fallback).
    """
    paths = ensure_local_tls_certificates()
    c_path = Path(cert_path) if cert_path else paths['server_cert']
    k_path = Path(key_path) if key_path else paths['server_key']

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if require_tls13 and hasattr(ssl.TLSVersion, 'TLSv1_3'):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.load_cert_chain(certfile=str(c_path), keyfile=str(k_path))
    return ctx


def create_tls_client_context(
    ca_cert_path: Path | str | None = None,
    require_tls13: bool = True,
) -> ssl.SSLContext:
    """
    Create a secure client-side SSLContext that strictly validates server certificates
    and hostnames against the trusted CA certificate (never disables verification).
    """
    paths = ensure_local_tls_certificates()
    ca_path = Path(ca_cert_path) if ca_cert_path else paths['ca_cert']

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    if require_tls13 and hasattr(ssl.TLSVersion, 'TLSv1_3'):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx


def perform_tls_handshake_and_exchange(
    server_ctx: ssl.SSLContext,
    client_ctx: ssl.SSLContext,
    message: bytes = b"SECURE_TX_PING",
    server_hostname: str = "localhost",
) -> dict:
    """
    Execute a complete OpenSSL TLS 1.3 handshake and encrypted data exchange between
    client_ctx and server_ctx using standard ssl.MemoryBIO streams.
    Strictly enforces X.509 certificate chain and hostname verification (raises
    ssl.SSLCertVerificationError if the server certificate is untrusted or mismatched).
    """
    client_in = ssl.MemoryBIO()
    client_out = ssl.MemoryBIO()
    server_in = ssl.MemoryBIO()
    server_out = ssl.MemoryBIO()

    client_ssl = client_ctx.wrap_bio(
        client_in,
        client_out,
        server_side=False,
        server_hostname=server_hostname,
    )
    server_ssl = server_ctx.wrap_bio(
        server_in,
        server_out,
        server_side=True,
    )

    def _pump():
        data_c2s = client_out.read()
        if data_c2s:
            server_in.write(data_c2s)
        data_s2c = server_out.read()
        if data_s2c:
            client_in.write(data_s2c)

    client_done = False
    server_done = False
    for _ in range(20):
        if not client_done:
            try:
                client_ssl.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        _pump()

        if not server_done:
            try:
                server_ssl.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError:
                _pump()
                raise
        _pump()

        if client_done and server_done:
            break

    # Finalize any post-handshake TLS 1.3 NewSessionTicket records and send application data
    client_ssl.write(message)
    _pump()
    received_by_server = server_ssl.read(4096)
    server_ssl.write(b"ACK:" + received_by_server)
    _pump()
    received_by_client = client_ssl.read(4096)

    return {
        'protocol_version': client_ssl.version(),
        'cipher': client_ssl.cipher(),
        'server_cert_subject': client_ssl.getpeercert(),
        'response': received_by_client,
    }

