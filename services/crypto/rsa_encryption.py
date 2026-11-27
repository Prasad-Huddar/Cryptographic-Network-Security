"""
RSA-OAEP Key Wrapping and Asymmetric Encryption Module.

Implements:
- RSA-OAEP with SHA-256 and MGF1(SHA-256)
- Wrapping (encrypting) 256-bit AES session keys with the server's RSA-3072 public key
- Unwrapping (decrypting) wrapped AES keys on the server using the server's RSA-3072 private key
"""
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from services.crypto.rsa_key_management import (
    load_public_key,
    load_private_key,
    get_server_public_key_pem,
    get_server_private_key_pem,
    RSA_KEY_SIZE_BITS,
)


class RSAEncryptionError(Exception):
    """Raised when RSA-OAEP encryption or decryption fails."""
    pass


def _oaep_padding() -> padding.OAEP:
    """Return standard RSA-OAEP padding with SHA-256 and MGF1(SHA-256)."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_aes_key(aes_key: bytes, public_key_pem: bytes | str | None = None) -> dict:
    """
    Wrap (encrypt) a 256-bit AES key using RSA-OAEP (SHA-256, MGF1-SHA256).
    Defaults to the server's RSA-3072 public key if public_key_pem is not specified.

    Returns a dictionary containing:
    - wrapped_key: raw encrypted bytes
    - wrapped_key_b64: Base64-encoded wrapped key
    """
    if not isinstance(aes_key, (bytes, bytearray)) or len(aes_key) != 32:
        raise RSAEncryptionError("AES key to wrap must be exactly 32 bytes (256 bits).")

    if public_key_pem is None:
        public_key_pem = get_server_public_key_pem()

    try:
        pub_key = load_public_key(public_key_pem)
        if pub_key.key_size < RSA_KEY_SIZE_BITS:
            raise RSAEncryptionError(f"RSA public key must be at least {RSA_KEY_SIZE_BITS} bits.")
        wrapped = pub_key.encrypt(bytes(aes_key), _oaep_padding())
        return {
            'wrapped_key': wrapped,
            'wrapped_key_b64': base64.b64encode(wrapped).decode('ascii'),
        }
    except RSAEncryptionError:
        raise
    except Exception as exc:
        raise RSAEncryptionError(f"RSA-OAEP key wrapping failed: {exc}") from exc


def unwrap_aes_key(
    wrapped_key: bytes | str,
    private_key_pem: bytes | str | None = None,
    passphrase: bytes | str | None = None
) -> bytes:
    """
    Unwrap (decrypt) a wrapped AES-256 key on the server using RSA-OAEP (SHA-256, MGF1-SHA256).
    Defaults to the server's RSA-3072 private key if private_key_pem is not specified.
    """
    if isinstance(wrapped_key, str):
        try:
            wrapped_bytes = base64.b64decode(wrapped_key.encode('ascii'), validate=True)
        except Exception as exc:
            raise RSAEncryptionError(f"Invalid Base64 for wrapped AES key: {exc}") from exc
    elif isinstance(wrapped_key, (bytes, bytearray)):
        wrapped_bytes = bytes(wrapped_key)
    else:
        raise RSAEncryptionError("wrapped_key must be bytes or Base64 string.")

    if private_key_pem is None:
        private_key_pem = get_server_private_key_pem()

    try:
        priv_key = load_private_key(private_key_pem, passphrase=passphrase)
        aes_key = priv_key.decrypt(wrapped_bytes, _oaep_padding())
        if len(aes_key) != 32:
            raise RSAEncryptionError("Unwrapped key length does not match 256-bit AES key.")
        return aes_key
    except RSAEncryptionError:
        raise
    except Exception as exc:
        raise RSAEncryptionError(f"RSA-OAEP key unwrapping failed: {exc}") from exc
