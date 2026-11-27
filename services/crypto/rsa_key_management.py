"""
RSA 3072-bit Key Management Module.

Provides:
- RSA 3072-bit key pair generation
- Private key serialization (PKCS#8 PEM) and public key serialization (SubjectPublicKeyInfo PEM)
- Server RSA-3072 key pair lifecycle management (private key remains strictly on server)
- Client RSA-3072 signing key pair provisioning per user
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from services.crypto.key_storage import (
    get_server_key_paths,
    save_key_file,
    load_key_file,
    get_client_private_key_path,
    get_client_public_key_path,
)

RSA_KEY_SIZE_BITS = 3072
RSA_PUBLIC_EXPONENT = 65537

# In-memory cache to avoid redundant disk I/O and speed up test suites
_server_key_cache: tuple[bytes, bytes] | None = None
_client_key_cache: dict[str, tuple[bytes, bytes]] = {}


class RSAKeyManagementError(Exception):
    """Raised when RSA key generation or loading fails."""
    pass


def generate_rsa_keypair(
    key_size: int = RSA_KEY_SIZE_BITS,
    passphrase: bytes | str | None = None
) -> tuple[bytes, bytes]:
    """
    Generate an RSA key pair (default 3072-bit).
    Returns (private_key_pem, public_key_pem) as bytes.
    """
    if key_size < RSA_KEY_SIZE_BITS:
        raise RSAKeyManagementError(f"RSA key size must be at least {RSA_KEY_SIZE_BITS} bits.")

    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=key_size,
    )

    if passphrase:
        pwd_bytes = passphrase.encode('utf-8') if isinstance(passphrase, str) else passphrase
        encryption_alg = serialization.BestAvailableEncryption(pwd_bytes)
    else:
        encryption_alg = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg,
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def load_private_key(private_pem: bytes | str, passphrase: bytes | str | None = None):
    """Load an RSA private key from PEM bytes or string."""
    pem_bytes = private_pem.encode('utf-8') if isinstance(private_pem, str) else private_pem
    pwd_bytes = passphrase.encode('utf-8') if isinstance(passphrase, str) else passphrase
    try:
        key = serialization.load_pem_private_key(pem_bytes, password=pwd_bytes)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RSAKeyManagementError("Loaded private key is not an RSA key.")
        return key
    except Exception as exc:
        raise RSAKeyManagementError(f"Failed to load RSA private key: {exc}") from exc


def load_public_key(public_pem: bytes | str):
    """Load an RSA public key from PEM bytes or string."""
    pem_bytes = public_pem.encode('utf-8') if isinstance(public_pem, str) else public_pem
    try:
        key = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(key, rsa.RSAPublicKey):
            raise RSAKeyManagementError("Loaded public key is not an RSA key.")
        return key
    except Exception as exc:
        raise RSAKeyManagementError(f"Failed to load RSA public key: {exc}") from exc


def get_or_create_server_keypair() -> tuple[bytes, bytes]:
    """
    Retrieve the server's RSA-3072 (private_pem, public_pem), generating and persisting
    it in instance/keys/ if it does not yet exist.
    """
    global _server_key_cache
    if _server_key_cache is not None:
        return _server_key_cache

    priv_path, pub_path = get_server_key_paths()
    priv_pem = load_key_file(priv_path)
    pub_pem = load_key_file(pub_path)

    if priv_pem and pub_pem:
        try:
            priv_key = load_private_key(priv_pem)
            if priv_key.key_size >= RSA_KEY_SIZE_BITS:
                _server_key_cache = (priv_pem, pub_pem)
                return _server_key_cache
        except RSAKeyManagementError:
            pass

    priv_pem, pub_pem = generate_rsa_keypair(RSA_KEY_SIZE_BITS)
    save_key_file(priv_path, priv_pem)
    save_key_file(pub_path, pub_pem)
    _server_key_cache = (priv_pem, pub_pem)
    return _server_key_cache


def get_server_private_key_pem() -> bytes:
    """Return the server's RSA-3072 private key PEM (server-side use only)."""
    priv_pem, _ = get_or_create_server_keypair()
    return priv_pem


def get_server_public_key_pem() -> str:
    """Return the server's RSA-3072 public key PEM string safe for client distribution."""
    _, pub_pem = get_or_create_server_keypair()
    return pub_pem.decode('utf-8')


def provision_client_keypair(identifier: str | int) -> tuple[bytes, bytes]:
    """
    Provision or retrieve a client RSA-3072 signing key pair for a given user identifier.
    Returns (client_private_pem, client_public_pem).
    """
    cache_key = str(identifier)
    if cache_key in _client_key_cache:
        return _client_key_cache[cache_key]

    priv_path = get_client_private_key_path(cache_key)
    pub_path = get_client_public_key_path(cache_key)
    priv_pem = load_key_file(priv_path)
    pub_pem = load_key_file(pub_path)

    if priv_pem and pub_pem:
        try:
            priv_key = load_private_key(priv_pem)
            if priv_key.key_size >= RSA_KEY_SIZE_BITS:
                _client_key_cache[cache_key] = (priv_pem, pub_pem)
                return priv_pem, pub_pem
        except RSAKeyManagementError:
            pass

    priv_pem, pub_pem = generate_rsa_keypair(RSA_KEY_SIZE_BITS)
    save_key_file(priv_path, priv_pem)
    save_key_file(pub_path, pub_pem)
    _client_key_cache[cache_key] = (priv_pem, pub_pem)
    return priv_pem, pub_pem
