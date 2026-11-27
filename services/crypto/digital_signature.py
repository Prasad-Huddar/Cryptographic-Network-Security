"""
RSA-PSS Digital Signature Module.

Implements:
- Deterministic canonicalization of transaction metadata and ciphertext packages
- RSA-PSS signing with SHA-256 and MGF1(SHA-256)
- RSA-PSS signature verification against the authenticated user's registered public key
"""
import base64
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from services.crypto.rsa_key_management import load_private_key, load_public_key, RSA_KEY_SIZE_BITS


class DigitalSignatureError(Exception):
    """Raised when RSA-PSS signature creation or verification fails."""
    pass


CANONICAL_SIGNED_FIELDS = (
    'transaction_id',
    'user_id',
    'timestamp',
    'nonce',
    'ciphertext_b64',
    'gcm_nonce_b64',
    'auth_tag_b64',
    'wrapped_key_b64',
)


def canonicalize_transaction_package(package: dict | bytes | str) -> bytes:
    """
    Produce deterministic canonical UTF-8 bytes for a transaction package or message.
    If a dict is provided, extracts the canonical fields (or sorts all keys if custom dict)
    and serializes with sorted keys and compact separators.
    """
    if isinstance(package, bytes):
        return package
    if isinstance(package, str):
        return package.encode('utf-8')
    if isinstance(package, dict):
        if all(field in package for field in CANONICAL_SIGNED_FIELDS):
            subset = {field: package[field] for field in CANONICAL_SIGNED_FIELDS}
        else:
            subset = {k: v for k, v in package.items() if k != 'signature_b64'}
        return json.dumps(subset, sort_keys=True, separators=(',', ':')).encode('utf-8')
    raise DigitalSignatureError("Unsupported transaction package type for canonicalization.")


def sign_transaction_package(
    package: dict | bytes | str,
    private_key_pem: bytes | str,
    passphrase: bytes | str | None = None
) -> dict:
    """
    Sign canonical transaction metadata and ciphertext package using RSA-PSS with SHA-256.

    Returns a dictionary containing:
    - signature: raw signature bytes
    - signature_b64: Base64-encoded signature
    - canonical_bytes: exact bytes signed
    """
    canonical_bytes = canonicalize_transaction_package(package)
    try:
        priv_key = load_private_key(private_key_pem, passphrase=passphrase)
        if priv_key.key_size < RSA_KEY_SIZE_BITS:
            raise DigitalSignatureError(f"RSA signing key must be at least {RSA_KEY_SIZE_BITS} bits.")

        pss_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )
        signature = priv_key.sign(canonical_bytes, pss_padding, hashes.SHA256())
        return {
            'signature': signature,
            'signature_b64': base64.b64encode(signature).decode('ascii'),
            'canonical_bytes': canonical_bytes,
        }
    except DigitalSignatureError:
        raise
    except Exception as exc:
        raise DigitalSignatureError(f"RSA-PSS signing failed: {exc}") from exc


def verify_transaction_signature(
    package: dict | bytes | str,
    signature: bytes | str,
    public_key_pem: bytes | str
) -> bool:
    """
    Verify an RSA-PSS (SHA-256) signature against a registered client public key.
    Returns True if valid, False if invalid or if the transaction package was altered.
    """
    if not public_key_pem:
        return False

    try:
        if isinstance(signature, str):
            sig_bytes = base64.b64decode(signature.encode('ascii'), validate=True)
        elif isinstance(signature, (bytes, bytearray)):
            sig_bytes = bytes(signature)
        else:
            return False

        canonical_bytes = canonicalize_transaction_package(package)
        pub_key = load_public_key(public_key_pem)
        if pub_key.key_size < RSA_KEY_SIZE_BITS:
            return False

        pss_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.AUTO,
        )
        pub_key.verify(sig_bytes, canonical_bytes, pss_padding, hashes.SHA256())
        return True
    except (InvalidSignature, Exception):
        return False
