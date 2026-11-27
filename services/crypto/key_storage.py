"""
Secure Key Storage Module.

Manages persistent storage of:
- Server RSA-3072 private and public keys (stored outside public static directories)
- Separate HMAC-SHA256 secret key (generated securely and stored in instance/keys/, never hardcoded)
- Client RSA-3072 key pairs for user transaction signing (client private key kept in client keystore;
  only public key registered on the server User record)
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
INSTANCE_DIR = BASE_DIR / 'instance'
KEYS_DIR = INSTANCE_DIR / 'keys'
CLIENT_KEYS_DIR = INSTANCE_DIR / 'client_keys'
CERTS_DIR = INSTANCE_DIR / 'certs'


def ensure_key_directories() -> None:
    """Ensure private key and certificate directories exist outside static/."""
    for directory in (INSTANCE_DIR, KEYS_DIR, CLIENT_KEYS_DIR, CERTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def get_server_key_paths() -> tuple[Path, Path]:
    """Return paths for the server RSA-3072 private and public keys."""
    ensure_key_directories()
    return KEYS_DIR / 'server_rsa_private.pem', KEYS_DIR / 'server_rsa_public.pem'


def get_hmac_secret() -> bytes:
    """
    Retrieve or generate the separate 256-bit HMAC secret key.
    Checks HMAC_SECRET_KEY environment variable first, then instance/keys/hmac_secret.key.
    Never hardcodes secrets in source code.
    """
    env_secret = os.environ.get('HMAC_SECRET_KEY')
    if env_secret:
        return env_secret.encode('utf-8')

    ensure_key_directories()
    secret_path = KEYS_DIR / 'hmac_secret.key'
    if secret_path.exists():
        data = secret_path.read_bytes()
        if len(data) >= 32:
            return data

    fresh_secret = secrets.token_bytes(32)
    secret_path.write_bytes(fresh_secret)
    return fresh_secret


def save_key_file(path: Path, data: bytes) -> None:
    """Save key material to disk inside instance directory."""
    ensure_key_directories()
    path.write_bytes(data)


def load_key_file(path: Path) -> bytes | None:
    """Load key material from disk if it exists."""
    if path.exists():
        return path.read_bytes()
    return None


def get_client_private_key_path(identifier: str | int) -> Path:
    """Return path in the client keystore for a user's private signing key."""
    ensure_key_directories()
    safe_id = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in str(identifier))
    return CLIENT_KEYS_DIR / f'client_{safe_id}_private.pem'


def get_client_public_key_path(identifier: str | int) -> Path:
    """Return path in the client keystore for a user's public verification key."""
    ensure_key_directories()
    safe_id = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in str(identifier))
    return CLIENT_KEYS_DIR / f'client_{safe_id}_public.pem'
