"""
Cryptographic Integrity & Password Derivation Module.

Implements:
1. PBKDF2-HMAC-SHA256 password hashing and constant-time verification using Python's
   cryptography library (with individual random salts and configurable iterations).
2. HMAC-SHA256 message authentication for security logs and stored transaction records
   using a dedicated secret key managed by key_storage.py.
"""
import json
import secrets
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import check_password_hash as _werkzeug_check_hash
from services.crypto.key_storage import get_hmac_secret

DEFAULT_PBKDF2_ITERATIONS = 260000
MIN_PBKDF2_ITERATIONS = 100000
PBKDF2_SALT_BYTES = 16
PBKDF2_KEY_LENGTH = 32


class IntegrityError(Exception):
    """Raised when HMAC or PBKDF2 parameters are invalid."""
    pass


# ==============================================================================
# PBKDF2-HMAC-SHA256 Password Hashing
# ==============================================================================

def hash_password_pbkdf2(
    password: str,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    salt: bytes | None = None
) -> str:
    """
    Derive a PBKDF2-HMAC-SHA256 password hash with a unique random 128-bit salt.
    Format: pbkdf2:sha256:<iterations>$<salt_hex>$<derived_key_hex>
    """
    if not password or not isinstance(password, str):
        raise IntegrityError("Password must be a non-empty string.")
    if iterations < MIN_PBKDF2_ITERATIONS:
        raise IntegrityError(f"Iterations must be at least {MIN_PBKDF2_ITERATIONS}.")

    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    elif len(salt) < 16:
        raise IntegrityError("Salt must be at least 16 bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(password.encode('utf-8'))
    return f"pbkdf2:sha256:{iterations}${salt.hex()}${derived_key.hex()}"


def verify_password_pbkdf2(stored_hash: str, password: str) -> bool:
    """
    Verify a password against a stored PBKDF2-HMAC-SHA256 hash in constant time.
    Supports both cryptography-generated hex-salt hashes and legacy Werkzeug PBKDF2 hashes.
    """
    if not stored_hash or not password or not isinstance(password, str):
        return False

    try:
        parts = stored_hash.split('$')
        if len(parts) == 3 and parts[0].startswith('pbkdf2:sha256:'):
            header, salt_part, digest_hex = parts
            iterations = int(header.split(':')[2])
            try:
                salt_bytes = bytes.fromhex(salt_part)
                expected_key = bytes.fromhex(digest_hex)
                if len(salt_bytes) == PBKDF2_SALT_BYTES and len(expected_key) == PBKDF2_KEY_LENGTH:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=len(expected_key),
                        salt=salt_bytes,
                        iterations=iterations,
                    )
                    kdf.verify(password.encode('utf-8'), expected_key)
                    return True
            except ValueError:
                # Fallback to Werkzeug format if salt is ASCII-encoded rather than hex
                return _werkzeug_check_hash(stored_hash, password)
            except InvalidKey:
                return False
        return _werkzeug_check_hash(stored_hash, password)
    except Exception:
        return False


# ==============================================================================
# HMAC-SHA256 Record & Security Log Integrity
# ==============================================================================

def _normalize_hmac_input(data: bytes | str | dict) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode('utf-8')
    if isinstance(data, dict):
        return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    raise IntegrityError("Data for HMAC must be bytes, str, or dict.")


def compute_hmac_sha256(data: bytes | str | dict, secret_key: bytes | None = None) -> str:
    """
    Compute HMAC-SHA256 hex digest for the given data using the server's HMAC secret.
    """
    key = secret_key if secret_key is not None else get_hmac_secret()
    if isinstance(key, str):
        key = key.encode('utf-8')
    msg_bytes = _normalize_hmac_input(data)

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg_bytes)
    return h.finalize().hex()


def verify_hmac_sha256(
    data: bytes | str | dict,
    expected_hmac_hex: str,
    secret_key: bytes | None = None
) -> bool:
    """
    Verify an HMAC-SHA256 hex digest in constant time using cryptography.hazmat.primitives.hmac.
    Returns True if authentic and unmodified, False otherwise.
    """
    if not expected_hmac_hex or not isinstance(expected_hmac_hex, str):
        return False
    try:
        expected_bytes = bytes.fromhex(expected_hmac_hex)
        key = secret_key if secret_key is not None else get_hmac_secret()
        if isinstance(key, str):
            key = key.encode('utf-8')
        msg_bytes = _normalize_hmac_input(data)

        h = hmac.HMAC(key, hashes.SHA256())
        h.update(msg_bytes)
        h.verify(expected_bytes)
        return True
    except (ValueError, InvalidSignature, Exception):
        return False


def compute_security_log_hmac(
    event_type: str,
    description: str,
    user_id: int | None,
    ip_address: str | None,
    timestamp_iso: str
) -> str:
    """Compute HMAC-SHA256 for a SecurityLog record."""
    payload = {
        'event_type': str(event_type or ''),
        'description': str(description or ''),
        'user_id': user_id,
        'ip_address': str(ip_address or ''),
        'timestamp': str(timestamp_iso or ''),
    }
    return compute_hmac_sha256(payload)


def verify_security_log_hmac(log_record) -> bool:
    """Verify the HMAC-SHA256 tag of a SecurityLog model instance."""
    if not getattr(log_record, 'integrity_hmac', None):
        return False
    ts_iso = log_record.timestamp.isoformat() if log_record.timestamp else ''
    payload = {
        'event_type': str(log_record.event_type or ''),
        'description': str(log_record.description or ''),
        'user_id': log_record.user_id,
        'ip_address': str(log_record.ip_address or ''),
        'timestamp': ts_iso,
    }
    return verify_hmac_sha256(payload, log_record.integrity_hmac)


def compute_transaction_hmac(
    transaction_id: str,
    user_id: int | None,
    order_id: int | None,
    amount: float,
    encrypted_payload: str,
    wrapped_aes_key: str,
    gcm_nonce: str,
    auth_tag: str,
    digital_signature: str,
    replay_nonce: str,
    client_timestamp: str,
    verification_status: str
) -> str:
    """Compute HMAC-SHA256 over a stored Transaction record to detect database tampering."""
    payload = {
        'transaction_id': str(transaction_id or ''),
        'user_id': user_id,
        'order_id': order_id,
        'amount': round(float(amount or 0.0), 2),
        'encrypted_payload': str(encrypted_payload or ''),
        'wrapped_aes_key': str(wrapped_aes_key or ''),
        'gcm_nonce': str(gcm_nonce or ''),
        'auth_tag': str(auth_tag or ''),
        'digital_signature': str(digital_signature or ''),
        'replay_nonce': str(replay_nonce or ''),
        'client_timestamp': str(client_timestamp or ''),
        'verification_status': str(verification_status or ''),
    }
    return compute_hmac_sha256(payload)


def verify_transaction_hmac(tx_record) -> bool:
    """Verify the stored HMAC-SHA256 integrity tag of a Transaction model instance."""
    if not getattr(tx_record, 'integrity_hmac', None):
        return False
    payload = {
        'transaction_id': str(tx_record.transaction_id or ''),
        'user_id': tx_record.user_id,
        'order_id': tx_record.order_id,
        'amount': round(float(tx_record.amount or 0.0), 2),
        'encrypted_payload': str(tx_record.encrypted_payload or ''),
        'wrapped_aes_key': str(tx_record.wrapped_aes_key or ''),
        'gcm_nonce': str(tx_record.gcm_nonce or ''),
        'auth_tag': str(tx_record.auth_tag or ''),
        'digital_signature': str(tx_record.digital_signature or ''),
        'replay_nonce': str(tx_record.replay_nonce or ''),
        'client_timestamp': str(tx_record.client_timestamp or ''),
        'verification_status': str(tx_record.verification_status or ''),
    }
    return verify_hmac_sha256(payload, tx_record.integrity_hmac)
