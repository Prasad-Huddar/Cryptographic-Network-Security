"""
Isolated Ephemeral Cryptographic Sandbox Key Store & Key-Access Policy Vault.

Security Guarantees:
- Never loads, uses, or exposes the production server RSA private key or HMAC secret.
- Generates isolated in-memory RSA-3072 keypairs and a dedicated 256-bit lab HMAC secret.
- Private keys and raw symmetric secrets are strictly encapsulated inside backend memory
  and are never serialized into API responses, logs, or frontend state.
"""
import hashlib
import secrets
import threading
from services.crypto.rsa_key_management import generate_rsa_keypair, RSA_KEY_SIZE_BITS

_key_lock = threading.Lock()
_lab_server_keypair: tuple[bytes, bytes] | None = None
_lab_client_keypair: tuple[bytes, bytes] | None = None
_lab_attacker_keypair: tuple[bytes, bytes] | None = None
_lab_hmac_secret: bytes | None = None


class KeyAccessDeniedError(PermissionError):
    """Raised when an unauthorized caller attempts to extract raw key material from the vault."""
    pass


def get_lab_server_keypair() -> tuple[bytes, bytes]:
    """Return isolated ephemeral RSA-3072 (private_pem, public_pem) for Lab RSA-OAEP."""
    global _lab_server_keypair
    with _key_lock:
        if _lab_server_keypair is None:
            _lab_server_keypair = generate_rsa_keypair(RSA_KEY_SIZE_BITS)
        return _lab_server_keypair


def get_lab_client_keypair() -> tuple[bytes, bytes]:
    """Return isolated ephemeral RSA-3072 (private_pem, public_pem) for legitimate Lab RSA-PSS."""
    global _lab_client_keypair
    with _key_lock:
        if _lab_client_keypair is None:
            _lab_client_keypair = generate_rsa_keypair(RSA_KEY_SIZE_BITS)
        return _lab_client_keypair


def get_lab_attacker_keypair() -> tuple[bytes, bytes]:
    """Return isolated ephemeral RSA-3072 (private_pem, public_pem) representing a rogue attacker."""
    global _lab_attacker_keypair
    with _key_lock:
        if _lab_attacker_keypair is None:
            _lab_attacker_keypair = generate_rsa_keypair(RSA_KEY_SIZE_BITS)
        return _lab_attacker_keypair


def get_lab_hmac_secret() -> bytes:
    """Return isolated ephemeral 256-bit secret key exclusively for Lab Module 5 HMAC tests."""
    global _lab_hmac_secret
    with _key_lock:
        if _lab_hmac_secret is None:
            _lab_hmac_secret = secrets.token_bytes(32)
        return _lab_hmac_secret


def key_fingerprint(key_material: bytes | str) -> str:
    """Return a non-reversible SHA-256 fingerprint preview safe for display and logging."""
    raw = key_material.encode('utf-8') if isinstance(key_material, str) else bytes(key_material)
    return hashlib.sha256(raw).hexdigest()[:32]


class AccessControlVault:
    """
    Simulated HSM / Key-Isolation Vault enforcing strict RBAC and non-exportable key policy.
    Used by Module 1 (Unauthorized Key Access) to execute real access-control enforcement
    against unauthorized attempts to retrieve symmetric AES-256 key material.
    """

    ALLOWED_INTERNAL_ROLES = frozenset({'crypto_hsm_internal'})

    def __init__(self):
        self._keys: dict[str, dict] = {}
        self._lock = threading.Lock()

    def store_ephemeral_key(self, key_id: str, raw_key: bytes, algorithm: str = 'AES-256-GCM') -> dict:
        fp = key_fingerprint(raw_key)
        with self._lock:
            self._keys[key_id] = {
                'raw': bytes(raw_key),
                'algorithm': algorithm,
                'key_bits': len(raw_key) * 8,
                'fingerprint': fp,
                'exportable': False,
            }
        return {
            'key_id': key_id,
            'algorithm': algorithm,
            'key_bits': len(raw_key) * 8,
            'fingerprint': fp,
            'exportable': False,
        }

    def attempt_raw_key_export(self, key_id: str, caller_role: str, caller_identity: str) -> bytes:
        """
        Attempt to extract raw key material.
        Strict policy: non-exportable keys are ALWAYS denied to external/customer/web roles.
        """
        with self._lock:
            entry = self._keys.get(key_id)

        if entry is None:
            raise KeyAccessDeniedError(f"Key '{key_id}' not found in isolated vault.")

        if not entry['exportable']:
            raise KeyAccessDeniedError(
                f"ACCESS DENIED (HTTP 403 / HSM Policy): Raw export of non-exportable "
                f"{entry['algorithm']} key '{key_id}' is strictly prohibited for caller "
                f"'{caller_identity}' (role='{caller_role}')."
            )

        if caller_role not in self.ALLOWED_INTERNAL_ROLES:
            raise KeyAccessDeniedError(
                f"RBAC Policy Violation: Caller role '{caller_role}' lacks hardware vault clearance."
            )

        return entry['raw']

    def purge_key(self, key_id: str) -> None:
        with self._lock:
            self._keys.pop(key_id, None)


lab_key_vault = AccessControlVault()
