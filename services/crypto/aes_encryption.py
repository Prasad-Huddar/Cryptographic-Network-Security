"""
AES-256-GCM Authenticated Symmetric Encryption Module.

Provides:
- Cryptographically secure 256-bit (32-byte) AES key generation
- Unique 96-bit (12-byte) GCM nonce generation with reuse prevention
- Authenticated encryption (AES-256-GCM) with separate ciphertext and 128-bit authentication tag
- Authenticated decryption with strict tag verification and tampering rejection
"""
import base64
import hashlib
import secrets
import threading
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE_BYTES = 32   # 256 bits
GCM_NONCE_SIZE_BYTES = 12  # 96 bits
GCM_TAG_SIZE_BYTES = 16    # 128 bits

# Track (key_digest, nonce) pairs in-memory to guarantee a nonce is never reused with the same key
_used_key_nonce_pairs = set()
_nonce_lock = threading.Lock()


class AESEncryptionError(Exception):
    """Raised when AES-256-GCM encryption or decryption fails."""
    pass


def generate_aes_key() -> bytes:
    """Generate a fresh cryptographically secure 256-bit (32-byte) AES key."""
    return secrets.token_bytes(AES_KEY_SIZE_BYTES)


def generate_gcm_nonce(key: bytes | None = None) -> bytes:
    """
    Generate a cryptographically random 96-bit (12-byte) GCM nonce.
    If a key is provided, guarantees the nonce has not been used with that key.
    """
    for _ in range(10):
        nonce = secrets.token_bytes(GCM_NONCE_SIZE_BYTES)
        if key is None:
            return nonce
        key_hash = hashlib.sha256(key).digest()
        with _nonce_lock:
            if (key_hash, nonce) not in _used_key_nonce_pairs:
                return nonce
    raise AESEncryptionError("Failed to generate a unique GCM nonce.")


def _validate_key_and_nonce(key: bytes, nonce: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != AES_KEY_SIZE_BYTES:
        raise AESEncryptionError(f"Invalid AES key length: expected {AES_KEY_SIZE_BYTES} bytes (256 bits).")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != GCM_NONCE_SIZE_BYTES:
        raise AESEncryptionError(f"Invalid GCM nonce length: expected {GCM_NONCE_SIZE_BYTES} bytes (96 bits).")


def encrypt_aes_gcm(
    plaintext: bytes | str,
    key: bytes | None = None,
    nonce: bytes | None = None,
    associated_data: bytes | str | None = None
) -> dict:
    """
    Encrypt plaintext using AES-256-GCM.

    Returns a dictionary containing:
    - key: raw 32-byte AES key
    - nonce: raw 12-byte GCM nonce
    - ciphertext: raw encrypted bytes (excluding tag)
    - auth_tag: raw 16-byte GCM authentication tag
    - nonce_b64: Base64-encoded nonce
    - ciphertext_b64: Base64-encoded ciphertext
    - auth_tag_b64: Base64-encoded authentication tag
    """
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    elif isinstance(plaintext, (bytes, bytearray)):
        plaintext_bytes = bytes(plaintext)
    else:
        raise AESEncryptionError("Plaintext must be bytes or str.")

    if len(plaintext_bytes) == 0:
        raise AESEncryptionError("Plaintext payload cannot be empty.")

    if associated_data is not None and isinstance(associated_data, str):
        aad_bytes = associated_data.encode('utf-8')
    else:
        aad_bytes = associated_data

    if key is None:
        key = generate_aes_key()
    if nonce is None:
        nonce = generate_gcm_nonce(key)

    _validate_key_and_nonce(key, nonce)

    # Enforce strict (key, nonce) uniqueness
    key_hash = hashlib.sha256(key).digest()
    with _nonce_lock:
        pair = (key_hash, bytes(nonce))
        if pair in _used_key_nonce_pairs:
            raise AESEncryptionError("GCM nonce reuse detected for the same AES key! Encryption aborted.")
        _used_key_nonce_pairs.add(pair)

    try:
        aesgcm = AESGCM(bytes(key))
        ct_and_tag = aesgcm.encrypt(bytes(nonce), plaintext_bytes, aad_bytes)
    except Exception as exc:
        raise AESEncryptionError(f"AES-256-GCM encryption failed: {exc}") from exc

    ciphertext = ct_and_tag[:-GCM_TAG_SIZE_BYTES]
    auth_tag = ct_and_tag[-GCM_TAG_SIZE_BYTES:]

    return {
        'key': bytes(key),
        'nonce': bytes(nonce),
        'ciphertext': ciphertext,
        'auth_tag': auth_tag,
        'nonce_b64': base64.b64encode(nonce).decode('ascii'),
        'ciphertext_b64': base64.b64encode(ciphertext).decode('ascii'),
        'auth_tag_b64': base64.b64encode(auth_tag).decode('ascii'),
    }


def _to_bytes(val: bytes | str, field_name: str) -> bytes:
    if isinstance(val, (bytes, bytearray)):
        return bytes(val)
    if isinstance(val, str):
        try:
            return base64.b64decode(val.encode('ascii'), validate=True)
        except Exception as exc:
            raise AESEncryptionError(f"Invalid Base64 encoding for {field_name}: {exc}") from exc
    raise AESEncryptionError(f"{field_name} must be bytes or Base64 string.")


def decrypt_aes_gcm(
    ciphertext: bytes | str,
    key: bytes | str,
    nonce: bytes | str,
    auth_tag: bytes | str,
    associated_data: bytes | str | None = None
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext and verify the 128-bit authentication tag.
    Raises AESEncryptionError if the key is wrong, ciphertext was modified, or auth_tag is invalid.
    """
    key_bytes = _to_bytes(key, 'key') if isinstance(key, str) else key
    nonce_bytes = _to_bytes(nonce, 'nonce')
    ciphertext_bytes = _to_bytes(ciphertext, 'ciphertext')
    tag_bytes = _to_bytes(auth_tag, 'auth_tag')

    _validate_key_and_nonce(key_bytes, nonce_bytes)

    if len(tag_bytes) != GCM_TAG_SIZE_BYTES:
        raise AESEncryptionError(f"Invalid GCM authentication tag length: expected {GCM_TAG_SIZE_BYTES} bytes.")

    if len(ciphertext_bytes) == 0:
        raise AESEncryptionError("Ciphertext cannot be empty.")

    if associated_data is not None and isinstance(associated_data, str):
        aad_bytes = associated_data.encode('utf-8')
    else:
        aad_bytes = associated_data

    try:
        aesgcm = AESGCM(bytes(key_bytes))
        combined = ciphertext_bytes + tag_bytes
        plaintext = aesgcm.decrypt(nonce_bytes, combined, aad_bytes)
        return plaintext
    except InvalidTag as exc:
        raise AESEncryptionError("AES-256-GCM authentication tag verification failed: tampering or wrong key detected.") from exc
    except Exception as exc:
        raise AESEncryptionError(f"AES-256-GCM decryption error: {exc}") from exc
