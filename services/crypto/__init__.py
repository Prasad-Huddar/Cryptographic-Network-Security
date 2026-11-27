"""
SecureShop Hybrid Cryptography and Network Security Package.

Exposes:
- AES-256-GCM symmetric authenticated encryption
- RSA-3072 key management
- RSA-OAEP asymmetric key wrapping
- RSA-PSS digital signatures
- PBKDF2-HMAC-SHA256 password hashing and HMAC-SHA256 record integrity
- Nonce/timestamp/transaction-ID replay protection and end-to-end transaction security
- TLS 1.3 server and client configuration
"""
from services.crypto.aes_encryption import (
    AESEncryptionError,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_gcm_nonce,
)
from services.crypto.digital_signature import (
    DigitalSignatureError,
    canonicalize_transaction_package,
    sign_transaction_package,
    verify_transaction_signature,
)
from services.crypto.integrity import (
    IntegrityError,
    compute_hmac_sha256,
    compute_security_log_hmac,
    compute_transaction_hmac,
    hash_password_pbkdf2,
    verify_hmac_sha256,
    verify_password_pbkdf2,
    verify_security_log_hmac,
    verify_transaction_hmac,
)
from services.crypto.key_storage import (
    get_hmac_secret,
    get_server_key_paths,
)
from services.crypto.rsa_encryption import (
    RSAEncryptionError,
    unwrap_aes_key,
    wrap_aes_key,
)
from services.crypto.rsa_key_management import (
    RSAKeyManagementError,
    generate_rsa_keypair,
    get_or_create_server_keypair,
    get_server_private_key_pem,
    get_server_public_key_pem,
    load_private_key,
    load_public_key,
    provision_client_keypair,
)
from services.crypto.transaction_security import (
    TransactionSecurityError,
    build_client_transaction_package,
    consume_nonce_atomically,
    create_tls_client_context,
    create_tls_server_context,
    ensure_local_tls_certificates,
    generate_replay_nonce,
    generate_timestamp,
    generate_transaction_id,
    generate_untrusted_self_signed_cert,
    get_tls_cert_paths,
    validate_timestamp,
    validate_transaction_id,
    verify_and_process_transaction_package,
)

__all__ = [
    'AESEncryptionError',
    'generate_aes_key',
    'generate_gcm_nonce',
    'encrypt_aes_gcm',
    'decrypt_aes_gcm',
    'RSAKeyManagementError',
    'generate_rsa_keypair',
    'load_private_key',
    'load_public_key',
    'get_or_create_server_keypair',
    'get_server_private_key_pem',
    'get_server_public_key_pem',
    'provision_client_keypair',
    'RSAEncryptionError',
    'wrap_aes_key',
    'unwrap_aes_key',
    'DigitalSignatureError',
    'canonicalize_transaction_package',
    'sign_transaction_package',
    'verify_transaction_signature',
    'IntegrityError',
    'hash_password_pbkdf2',
    'verify_password_pbkdf2',
    'compute_hmac_sha256',
    'verify_hmac_sha256',
    'compute_security_log_hmac',
    'verify_security_log_hmac',
    'compute_transaction_hmac',
    'verify_transaction_hmac',
    'get_hmac_secret',
    'get_server_key_paths',
    'TransactionSecurityError',
    'generate_transaction_id',
    'generate_replay_nonce',
    'generate_timestamp',
    'validate_transaction_id',
    'validate_timestamp',
    'consume_nonce_atomically',
    'build_client_transaction_package',
    'verify_and_process_transaction_package',
    'ensure_local_tls_certificates',
    'generate_untrusted_self_signed_cert',
    'get_tls_cert_paths',
    'create_tls_server_context',
    'create_tls_client_context',
]
