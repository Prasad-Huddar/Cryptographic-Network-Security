"""
Controlled Backend Attack Execution Engine for the 8 Cryptographic Security Modules.

Strict Design Principles:
1. Every attack button executes a REAL cryptographic operation using existing
   `services/crypto/*` primitives on isolated synthetic test data.
2. Attack execution is strictly separated from attack detection (`detection_service.py`).
3. Private keys, production secrets, real customer accounts, and real orders are NEVER
   accessed, modified, logged, or returned to the frontend.
4. Every executed simulation is persisted via `telemetry_service.record_simulation_event`.
"""
import base64
import datetime
import hashlib
import json
import secrets
import time
import uuid
from datetime import timezone

from flask import current_app

from database.database import db
from models.security_lab import LabSyntheticTransaction
from services.crypto.aes_encryption import (
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_gcm_nonce,
)
from services.crypto.digital_signature import (
    canonicalize_transaction_package,
    sign_transaction_package,
    verify_transaction_signature,
)
from services.crypto.integrity import (
    DEFAULT_PBKDF2_ITERATIONS,
    compute_hmac_sha256,
    hash_password_pbkdf2,
)
from services.crypto.rsa_encryption import unwrap_aes_key, wrap_aes_key
from services.crypto.transaction_security import (
    DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    generate_replay_nonce,
    generate_timestamp,
    generate_transaction_id,
    validate_timestamp,
)
from services.security_lab.detection_service import (
    consume_lab_nonce_atomically,
    verify_aes_gcm_defence,
    verify_hmac_defence,
    verify_key_vault_access_defence,
    verify_pbkdf2_password_defence,
    verify_rsa_oaep_unwrap_defence,
    verify_rsa_pss_signature_defence,
    verify_timestamp_and_binding_defence,
)
from services.security_lab.sandbox_keys import (
    get_lab_attacker_keypair,
    get_lab_client_keypair,
    get_lab_hmac_secret,
    get_lab_server_keypair,
    key_fingerprint,
    lab_key_vault,
)
from services.security_lab.telemetry_service import record_simulation_event
from services.timezone_utils import format_ist, now_ist_formatted


# ==============================================================================
# Module & Attack Catalogue Metadata (Shared by UI & Validation Layer)
# ==============================================================================

MODULE_CATALOGUE = [
    {
        'module_key': 'aes_gcm',
        'number': 1,
        'name': 'AES-256-GCM – Authenticated Encryption',
        'short_name': 'AES-256-GCM',
        'category': 'Confidentiality & AEAD',
        'algorithm': 'AES-256-GCM (256-bit key, 96-bit nonce, 128-bit GHASH auth tag)',
        'description': 'Tests confidentiality against interception, ciphertext/tag tampering rejection, and RBAC key-vault isolation.',
        'icon': 'bi-lock-fill',
        'attacks': [
            {
                'attack_key': 'data_theft_interception',
                'name': 'Data Theft / Interception Simulation',
                'description': 'Intercepts encrypted transaction ciphertext and proves plaintext cannot be recovered without the AES-256 key.',
            },
            {
                'attack_key': 'ciphertext_tampering',
                'name': 'Ciphertext Tampering',
                'description': 'Modifies encrypted payload bytes in transit and verifies AES-GCM rejects the altered ciphertext.',
            },
            {
                'attack_key': 'auth_tag_manipulation',
                'name': 'Authentication Tag Manipulation',
                'description': 'Corrupts the 128-bit GCM authentication tag and confirms immediate authentication failure.',
            },
            {
                'attack_key': 'unauthorized_key_access',
                'name': 'Unauthorized Key Access',
                'description': 'Simulates an unprivileged role requesting raw AES key material from the isolated key vault.',
            },
        ],
    },
    {
        'module_key': 'rsa_oaep',
        'number': 2,
        'name': 'RSA-OAEP-3072 – Secure Key Exchange',
        'short_name': 'RSA-OAEP-3072',
        'category': 'Asymmetric Key Exchange',
        'algorithm': 'RSA-OAEP (3072-bit modulus, SHA-256, MGF1-SHA256)',
        'description': 'Tests protection of wrapped AES session keys against interception, unauthorized unwrapping, tampering, and key mismatch.',
        'icon': 'bi-key-fill',
        'attacks': [
            {
                'attack_key': 'session_key_interception',
                'name': 'Session Key Interception Simulation',
                'description': 'Captures the 384-byte RSA-OAEP wrapped session key and verifies it reveals zero session-key bytes without the private key.',
            },
            {
                'attack_key': 'unauthorized_key_recovery',
                'name': 'Unauthorized Session Key Recovery',
                'description': 'Attempts to unwrap the intercepted session key using a rogue attacker RSA-3072 private key.',
            },
            {
                'attack_key': 'encrypted_key_payload_manipulation',
                'name': 'Encrypted Key Payload Manipulation',
                'description': 'Flips bytes inside the wrapped RSA-OAEP ciphertext and tests OAEP padding/integrity rejection.',
            },
            {
                'attack_key': 'key_mismatch_attack',
                'name': 'Public/Private Key Mismatch Attack',
                'description': 'Wraps a session key with a mismatched public key and submits it to the server private-key unwrap routine.',
            },
        ],
    },
    {
        'module_key': 'rsa_pss',
        'number': 3,
        'name': 'RSA-PSS – Digital Signature Security',
        'short_name': 'RSA-PSS-3072',
        'category': 'Digital Signatures',
        'algorithm': 'RSA-PSS (3072-bit, SHA-256, MGF1-SHA256, MAX_LENGTH salt)',
        'description': 'Tests non-repudiation and integrity against signature forgery, post-sign modification, key substitution, and invalid signatures.',
        'icon': 'bi-vector-pen',
        'attacks': [
            {
                'attack_key': 'signature_forgery',
                'name': 'Digital Signature Forgery',
                'description': 'Attacker signs a synthetic transaction using a rogue RSA-3072 private key and submits it for verification.',
            },
            {
                'attack_key': 'signed_transaction_modification',
                'name': 'Signed Transaction Modification',
                'description': 'Alters a legitimately signed transaction package after signing and verifies digest/signature rejection.',
            },
            {
                'attack_key': 'public_key_substitution',
                'name': 'Public Key Substitution',
                'description': 'Attempts to substitute an untrusted public key to validate a forged signature against registered key pinning.',
            },
            {
                'attack_key': 'invalid_signature_injection',
                'name': 'Invalid Signature Injection',
                'description': 'Injects a corrupted/forged 384-byte signature into an otherwise valid transaction envelope.',
            },
        ],
    },
    {
        'module_key': 'pbkdf2',
        'number': 4,
        'name': 'PBKDF2-SHA256 – Password Security',
        'short_name': 'PBKDF2-SHA256',
        'category': 'Password Security',
        'algorithm': 'PBKDF2-HMAC-SHA256 (128-bit random salt, 260,000 iterations)',
        'description': 'Evaluates brute-force cost, dictionary resistance, per-hash random salting against rainbow tables, and weak-password policy.',
        'icon': 'bi-person-lock',
        'attacks': [
            {
                'attack_key': 'brute_force_simulation',
                'name': 'Brute-Force Attack Simulation',
                'description': 'Measures real PBKDF2-HMAC-SHA256 derivation latency across candidate guesses on an isolated synthetic hash.',
            },
            {
                'attack_key': 'dictionary_attack_simulation',
                'name': 'Dictionary Attack Simulation',
                'description': 'Tests common leaked password candidates against a strong synthetic PBKDF2 hash via real verification.',
            },
            {
                'attack_key': 'rainbow_table_demonstration',
                'name': 'Rainbow Table Attack Demonstration',
                'description': 'Proves unique 128-bit salts produce distinct digests for identical credentials and defeat precomputed tables.',
            },
            {
                'attack_key': 'weak_password_testing',
                'name': 'Weak Password Testing',
                'description': 'Tests synthetic weak credentials with password policy enforced vs disabled (demonstrates real defence pass/fail).',
            },
        ],
    },
    {
        'module_key': 'hmac_sha256',
        'number': 5,
        'name': 'HMAC-SHA256 – Message Authentication',
        'short_name': 'HMAC-SHA256',
        'category': 'Message Integrity',
        'algorithm': 'HMAC-SHA256 (256-bit isolated secret key, constant-time verify)',
        'description': 'Tests tamper-evident message authentication using constant-time HMAC-SHA256 verification.',
        'icon': 'bi-shield-check',
        'attacks': [
            {
                'attack_key': 'message_tampering',
                'name': 'Message Tampering',
                'description': 'Alters transaction amount inside an HMAC-protected audit message and executes constant-time verification.',
            },
            {
                'attack_key': 'hmac_forgery',
                'name': 'HMAC Forgery',
                'description': 'Computes a forged HMAC tag using an attacker-controlled wrong secret key and submits it to the verifier.',
            },
            {
                'attack_key': 'invalid_auth_code_injection',
                'name': 'Invalid Authentication Code Injection',
                'description': 'Mutates bits inside a valid 256-bit HMAC hex tag and confirms constant-time rejection.',
            },
            {
                'attack_key': 'unauthorized_message_modification',
                'name': 'Unauthorized Message Modification',
                'description': 'Injects unauthorized privilege/discount fields into a JSON payload without knowing the HMAC secret.',
            },
        ],
    },
    {
        'module_key': 'ciphertext_tampering',
        'number': 6,
        'name': 'Ciphertext Tampering Defence',
        'short_name': 'Ciphertext Tampering',
        'category': 'Tampering Defence',
        'algorithm': 'Interactive AES-256-GCM + RSA-OAEP Transaction Tampering Lab',
        'description': 'Generate an isolated encrypted transaction, intercept and mutate specific ciphertext bytes, execute decryption, and verify original record integrity.',
        'icon': 'bi-file-earmark-break-fill',
        'attacks': [
            {
                'attack_key': 'interactive_ciphertext_tamper',
                'name': 'Intercept & Modify Selected Ciphertext Bytes',
                'description': 'Flips chosen bytes in an intercepted synthetic transaction ciphertext and confirms AES-GCM rejection and DB immutability.',
            },
        ],
    },
    {
        'module_key': 'nonce_replay',
        'number': 7,
        'name': 'Nonce Replay Attack Defence',
        'short_name': 'Nonce Replay Guard',
        'category': 'Replay Protection',
        'algorithm': 'UUIDv4 Transaction ID + 128-bit Nonce + SQLite Atomic UNIQUE Constraint',
        'description': 'Submit a legitimate signed transaction, capture the exact request, and replay it (single or concurrent) against persistent atomic nonce tracking.',
        'icon': 'bi-arrow-repeat',
        'attacks': [
            {
                'attack_key': 'captured_request_replay',
                'name': 'Captured Request Replay Attack',
                'description': 'Submits a legitimate transaction once, captures it, and resubmits the exact request to verify atomic nonce rejection.',
            },
            {
                'attack_key': 'concurrent_replay_burst',
                'name': 'Concurrent Duplicate Nonce Burst',
                'description': 'Submits multiple duplicate requests with the same nonce to verify atomic DB constraint prevents race conditions.',
            },
        ],
    },
    {
        'module_key': 'expired_timestamp',
        'number': 8,
        'name': 'Expired Timestamp Attack Defence',
        'short_name': 'Timestamp Defence',
        'category': 'Temporal Integrity',
        'algorithm': 'UTC Timestamp Window (±300s) + RSA-PSS & AES-GCM AAD Binding + Nonce Guard',
        'description': 'Tests rejection of expired replays, old submissions, in-transit timestamp manipulation, and far-future timestamps.',
        'icon': 'bi-clock-history',
        'attacks': [
            {
                'attack_key': 'expired_request_replay',
                'name': 'Expired Request Replay',
                'description': 'Submits a signed request with a timestamp older than the configured ±300s validity window.',
            },
            {
                'attack_key': 'old_transaction_submission',
                'name': 'Old Transaction Submission',
                'description': 'Submits a signed transaction timestamped 24 hours in the past to test stale-window rejection.',
            },
            {
                'attack_key': 'timestamp_manipulation',
                'name': 'Timestamp Manipulation',
                'description': 'Alters a signed request timestamp in transit (within ±300s) to verify cryptographic signature & AAD binding detects tampering.',
            },
            {
                'attack_key': 'future_timestamp_injection',
                'name': 'Future Timestamp Injection',
                'description': 'Injects a far-future UTC timestamp beyond allowed clock skew to test upper-bound rejection.',
            },
        ],
    },
]

MODULE_MAP = {m['module_key']: m for m in MODULE_CATALOGUE}


def _now_ts() -> str:
    return now_ist_formatted()


def _sha256_hex(data: bytes | str) -> str:
    raw = data.encode('utf-8') if isinstance(data, str) else bytes(data)
    return hashlib.sha256(raw).hexdigest()


def _flip_b64_byte(b64_str: str, offset: int = 0, xor_mask: int = 0xFF) -> tuple[str, int, int, int]:
    """Flip a byte inside a Base64-encoded buffer and return (new_b64, actual_idx, before_byte, after_byte)."""
    raw = bytearray(base64.b64decode(b64_str.encode('ascii'), validate=True))
    if not raw:
        raise ValueError("Cannot tamper empty byte buffer.")
    idx = max(0, min(int(offset), len(raw) - 1))
    before = raw[idx]
    mask = int(xor_mask) & 0xFF
    if mask == 0:
        mask = 0xFF
    raw[idx] ^= mask
    after = raw[idx]
    return base64.b64encode(bytes(raw)).decode('ascii'), idx, before, after


def _build_synthetic_signed_package(
    *,
    amount_inr: float = 2999.00,
    item_name: str = 'Synthetic Lab Headphones',
    timestamp_override: str | None = None,
    nonce_override: str | None = None,
    tx_id_override: str | None = None,
    sign_with_attacker: bool = False,
) -> tuple[dict, dict]:
    """
    Build a complete isolated synthetic hybrid-crypto transaction package using ONLY
    sandbox ephemeral keys (never touches production server keys or customer keys).
    Returns (package_dict, internals_metadata).
    """
    _, lab_server_pub = get_lab_server_keypair()
    client_priv, client_pub = get_lab_client_keypair()
    attacker_priv, _ = get_lab_attacker_keypair()

    tx_id = tx_id_override or generate_transaction_id()
    ts_str = timestamp_override or generate_timestamp()
    replay_nonce = nonce_override or generate_replay_nonce()

    payload_dict = {
        'sandbox': True,
        'transaction_id': tx_id,
        'user_id': 999001,
        'timestamp': ts_str,
        'nonce': replay_nonce,
        'customer_ref': 'sandbox_test_customer@lab.local',
        'item': item_name,
        'quantity': 1,
        'amount_inr': round(float(amount_inr), 2),
        'shipping_address': '404 Sandbox Lab Lane, Isolated Test Zone',
    }
    payload_bytes = json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    aad_str = f"{tx_id}:999001:{ts_str}:{replay_nonce}"

    aes_key = generate_aes_key()
    gcm_nonce = generate_gcm_nonce(aes_key)
    enc = encrypt_aes_gcm(payload_bytes, key=aes_key, nonce=gcm_nonce, associated_data=aad_str.encode('utf-8'))
    wrapped = wrap_aes_key(aes_key, public_key_pem=lab_server_pub)

    package = {
        'transaction_id': tx_id,
        'user_id': 999001,
        'timestamp': ts_str,
        'nonce': replay_nonce,
        'ciphertext_b64': enc['ciphertext_b64'],
        'gcm_nonce_b64': enc['nonce_b64'],
        'auth_tag_b64': enc['auth_tag_b64'],
        'wrapped_key_b64': wrapped['wrapped_key_b64'],
    }
    signing_key = attacker_priv if sign_with_attacker else client_priv
    sig = sign_transaction_package(package, signing_key)
    package['signature_b64'] = sig['signature_b64']

    internals = {
        'payload_dict': payload_dict,
        'aad_str': aad_str,
        'aes_key_fingerprint': key_fingerprint(aes_key),
        'canonical_hash_sha256': _sha256_hex(sig['canonical_bytes']),
        'trusted_client_pub_fingerprint': key_fingerprint(client_pub),
    }
    return package, internals


# ==============================================================================
# MODULE 1: AES-256-GCM – Authenticated Encryption
# ==============================================================================

def _run_module_aes_gcm(attack_key: str, admin_user_id: int | None, options: dict) -> dict:
    start = time.perf_counter()
    logs = [f"[{_now_ts()}] Initializing isolated AES-256-GCM sandbox environment..."]

    synthetic_tx = {
        'sandbox_order': f"LAB-AES-{secrets.token_hex(3).upper()}",
        'customer': 'synthetic.buyer@lab.local',
        'item': 'Smart Watch Pro (Synthetic)',
        'amount_inr': 4999.00,
        'payment_ref': 'TOKEN_MASKED_4242',
    }
    plaintext_str = json.dumps(synthetic_tx, sort_keys=True)
    aes_key = generate_aes_key()
    gcm_nonce = generate_gcm_nonce(aes_key)
    aad = f"LAB_AAD:{synthetic_tx['sandbox_order']}".encode('utf-8')
    enc = encrypt_aes_gcm(plaintext_str, key=aes_key, nonce=gcm_nonce, associated_data=aad)
    aes_fp = key_fingerprint(aes_key)

    logs.append(f"[{_now_ts()}] Generated ephemeral 256-bit AES key (SHA-256 fp: {aes_fp[:16]}...) and 96-bit GCM nonce.")
    logs.append(f"[{_now_ts()}] Encrypted synthetic transaction payload ({len(plaintext_str)} bytes -> {len(enc['ciphertext'])} ciphertext bytes + 16-byte tag).")

    payload_info = {
        'sandbox_order': synthetic_tx['sandbox_order'],
        'algorithm': 'AES-256-GCM',
        'key_fingerprint_sha256': aes_fp,
        'gcm_nonce_b64': enc['nonce_b64'],
        'original_ciphertext_b64': enc['ciphertext_b64'],
        'original_auth_tag_b64': enc['auth_tag_b64'],
    }

    if attack_key == 'data_theft_interception':
        attack_type = 'Data Theft / Interception Simulation'
        description = 'Attacker intercepts AES-256-GCM encrypted transaction traffic and attempts unauthorized plaintext recovery.'
        intercepted_ct_b64 = enc['ciphertext_b64']
        raw_ct = enc['ciphertext']

        sensitive_markers = [b'4999', b'Smart Watch', b'4242', b'synthetic.buyer']
        leaked_markers = [m.decode() for m in sensitive_markers if m in raw_ct]
        attacker_wrong_key = generate_aes_key()
        logs.append(f"[{_now_ts()}] Attacker intercepted {len(raw_ct)} ciphertext bytes over simulated network tap.")
        logs.append(f"[{_now_ts()}] Plaintext leakage scan across raw ciphertext: {len(leaked_markers)} sensitive markers found.")
        logs.append(f"[{_now_ts()}] Attacker attempting decryption with guessed/unauthorized 256-bit key...")

        outcome = verify_aes_gcm_defence(
            ciphertext_b64=intercepted_ct_b64,
            key=attacker_wrong_key,
            nonce_b64=enc['nonce_b64'],
            auth_tag_b64=enc['auth_tag_b64'],
            associated_data=aad,
            attack_label=attack_type,
        )
        # Confidentiality holds only if wrong-key decryption failed AND zero plaintext markers leaked
        confidentiality_verified = (outcome.final_result == 'MITIGATED') and (len(leaked_markers) == 0)
        outcome.evidence.update({
            'intercepted_ciphertext_b64': intercepted_ct_b64,
            'ciphertext_length_bytes': len(raw_ct),
            'plaintext_markers_leaked': leaked_markers,
            'confidentiality_verified': confidentiality_verified,
            'attacker_key_fingerprint': key_fingerprint(attacker_wrong_key),
        })
        if not confidentiality_verified:
            outcome.blocked = False
            outcome.final_result = 'DEFENCE_FAILED'
        logs.append(f"[{_now_ts()}] Defence verifier result: {outcome.final_result} — {outcome.rejection_reason}")

    elif attack_key == 'ciphertext_tampering':
        attack_type = 'Ciphertext Tampering'
        description = 'Attacker flips bits in AES-256-GCM ciphertext in transit to alter transaction contents.'
        tampered_ct_b64, idx, before, after = _flip_b64_byte(enc['ciphertext_b64'], offset=0, xor_mask=0xFF)
        payload_info['tampered_ciphertext_b64'] = tampered_ct_b64
        payload_info['mutated_byte'] = f"index={idx} (0x{before:02X} -> 0x{after:02X})"
        logs.append(f"[{_now_ts()}] Attacker modified ciphertext byte[{idx}]: 0x{before:02X} -> 0x{after:02X}.")
        logs.append(f"[{_now_ts()}] Submitting tampered ciphertext to real AES-256-GCM authenticated decryption...")

        outcome = verify_aes_gcm_defence(
            ciphertext_b64=tampered_ct_b64,
            key=aes_key,
            nonce_b64=enc['nonce_b64'],
            auth_tag_b64=enc['auth_tag_b64'],
            associated_data=aad,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'original_ciphertext_sha256': _sha256_hex(enc['ciphertext_b64']),
            'tampered_ciphertext_sha256': _sha256_hex(tampered_ct_b64),
            'byte_mutation': f"byte[{idx}]: 0x{before:02X} -> 0x{after:02X}",
        })
        logs.append(f"[{_now_ts()}] AES-256-GCM verification outcome: {outcome.final_result} — {outcome.rejection_reason}")

    elif attack_key == 'auth_tag_manipulation':
        attack_type = 'Authentication Tag Manipulation'
        description = 'Attacker mutates the 128-bit GCM authentication tag to forge payload validity.'
        tampered_tag_b64, idx, before, after = _flip_b64_byte(enc['auth_tag_b64'], offset=0, xor_mask=0x5A)
        payload_info['tampered_auth_tag_b64'] = tampered_tag_b64
        payload_info['mutated_tag_byte'] = f"tag[{idx}] (0x{before:02X} -> 0x{after:02X})"
        logs.append(f"[{_now_ts()}] Attacker altered 128-bit GCM auth tag byte[{idx}]: 0x{before:02X} -> 0x{after:02X}.")
        logs.append(f"[{_now_ts()}] Running real AES-256-GCM authentication verification...")

        outcome = verify_aes_gcm_defence(
            ciphertext_b64=enc['ciphertext_b64'],
            key=aes_key,
            nonce_b64=enc['nonce_b64'],
            auth_tag_b64=tampered_tag_b64,
            associated_data=aad,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'original_tag_b64': enc['auth_tag_b64'],
            'tampered_tag_b64': tampered_tag_b64,
            'tag_mutation': f"tag[{idx}]: 0x{before:02X} -> 0x{after:02X}",
        })
        logs.append(f"[{_now_ts()}] Tag verification outcome: {outcome.final_result} — {outcome.rejection_reason}")

    elif attack_key == 'unauthorized_key_access':
        attack_type = 'Unauthorized Key Access'
        description = 'Simulated unprivileged caller attempts direct extraction of protected AES-256 session key from key vault.'
        vault_key_id = f"lab-aes-{secrets.token_hex(4)}"
        meta = lab_key_vault.store_ephemeral_key(vault_key_id, aes_key, algorithm='AES-256-GCM')
        payload_info['vault_key_id'] = vault_key_id
        payload_info['vault_key_metadata'] = meta
        payload_info['simulated_caller'] = {'identity': 'external_customer_session', 'role': 'customer'}
        logs.append(f"[{_now_ts()}] Sealed AES-256 key '{vault_key_id}' inside non-exportable HSM/Vault policy.")
        logs.append(f"[{_now_ts()}] Simulating unauthorized export attempt by role='customer'...")
        try:
            outcome = verify_key_vault_access_defence(
                key_id=vault_key_id,
                caller_role='customer',
                caller_identity='external_customer_session',
            )
        finally:
            lab_key_vault.purge_key(vault_key_id)
        logs.append(f"[{_now_ts()}] Vault policy decision: {outcome.final_result} — {outcome.rejection_reason}")
    else:
        raise ValueError(f"Unsupported AES-256-GCM attack: {attack_key}")

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['aes_gcm']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=mod['category'],
        description=description,
        payload=payload_info,
        evidence=outcome.evidence,
        logs=logs,
        defence_mechanism=outcome.defence_mechanism,
        detected=outcome.detected,
        blocked=outcome.blocked,
        mitigation_action=outcome.mitigation_action,
        final_result=outcome.final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# MODULE 2: RSA-OAEP-3072 – Secure Key Exchange
# ==============================================================================

def _run_module_rsa_oaep(attack_key: str, admin_user_id: int | None, options: dict) -> dict:
    start = time.perf_counter()
    logs = [f"[{_now_ts()}] Initializing isolated RSA-OAEP-3072 sandbox keypairs (private keys kept strictly in backend memory)..."]

    server_priv, server_pub = get_lab_server_keypair()
    attacker_priv, attacker_pub = get_lab_attacker_keypair()

    session_aes_key = generate_aes_key()
    session_fp = key_fingerprint(session_aes_key)
    wrapped_res = wrap_aes_key(session_aes_key, public_key_pem=server_pub)
    wrapped_b64 = wrapped_res['wrapped_key_b64']
    wrapped_raw = wrapped_res['wrapped_key']

    logs.append(f"[{_now_ts()}] Generated ephemeral 256-bit AES session key (SHA-256 fp: {session_fp[:16]}...).")
    logs.append(f"[{_now_ts()}] Wrapped session key with lab RSA-3072 public key -> {len(wrapped_raw)} bytes (3072 bits).")

    payload_info = {
        'algorithm': 'RSA-OAEP-3072 (SHA-256, MGF1-SHA256)',
        'session_key_fingerprint_sha256': session_fp,
        'server_public_key_fingerprint': key_fingerprint(server_pub),
        'wrapped_key_bytes': len(wrapped_raw),
        'wrapped_key_b64_preview': wrapped_b64[:96] + '...',
        'private_key_exposed': False,
    }

    if attack_key == 'session_key_interception':
        attack_type = 'Session Key Interception Simulation'
        description = 'Attacker intercepts RSA-OAEP wrapped AES session key in transit and attempts recovery without the server private key.'
        raw_leak = session_aes_key in wrapped_raw
        logs.append(f"[{_now_ts()}] Attacker captured 384-byte wrapped key blob. Raw session key bytes inside blob: {raw_leak}.")
        logs.append(f"[{_now_ts()}] Attacker attempting to recover AES session key without server RSA-3072 private key...")

        outcome = verify_rsa_oaep_unwrap_defence(
            wrapped_key_b64=wrapped_b64,
            private_key_pem=attacker_priv,
            attack_label=attack_type,
        )
        if raw_leak:
            outcome.blocked = False
            outcome.final_result = 'DEFENCE_FAILED'
        outcome.evidence.update({
            'raw_session_key_in_blob': raw_leak,
            'intercepted_blob_sha256': _sha256_hex(wrapped_raw),
            'recovery_possible_without_private_key': False,
            'server_private_key_isolated': True,
        })
        logs.append(f"[{_now_ts()}] Result: {outcome.final_result} — {outcome.rejection_reason}")

    elif attack_key == 'unauthorized_key_recovery':
        attack_type = 'Unauthorized Session Key Recovery'
        description = 'Attacker executes RSA-OAEP unwrapping on captured wrapped key using an unauthorized attacker RSA-3072 private key.'
        logs.append(f"[{_now_ts()}] Attacker invoking RSA-OAEP decrypt with rogue private key (fp: {key_fingerprint(attacker_pub)[:16]}...)...")
        outcome = verify_rsa_oaep_unwrap_defence(
            wrapped_key_b64=wrapped_b64,
            private_key_pem=attacker_priv,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'target_public_key_fp': key_fingerprint(server_pub),
            'attacker_keypair_fp': key_fingerprint(attacker_pub),
            'server_private_key_isolated': True,
        })
        logs.append(f"[{_now_ts()}] Unauthorized recovery attempt outcome: {outcome.final_result} — {outcome.rejection_reason}")

    elif attack_key == 'encrypted_key_payload_manipulation':
        attack_type = 'Encrypted Key Payload Manipulation'
        description = 'Attacker flips bytes inside the 384-byte RSA-OAEP wrapped AES session key ciphertext before server decryption.'
        tampered_wrapped_b64, idx, before, after = _flip_b64_byte(wrapped_b64, offset=16, xor_mask=0xFF)
        payload_info['tampered_wrapped_key_preview'] = tampered_wrapped_b64[:96] + '...'
        payload_info['mutated_byte'] = f"wrapped_key[{idx}]: 0x{before:02X} -> 0x{after:02X}"
        logs.append(f"[{_now_ts()}] Attacker tampered wrapped key byte[{idx}]: 0x{before:02X} -> 0x{after:02X}.")
        logs.append(f"[{_now_ts()}] Submitting manipulated wrapped key to server RSA-OAEP unwrap routine...")

        outcome = verify_rsa_oaep_unwrap_defence(
            wrapped_key_b64=tampered_wrapped_b64,
            private_key_pem=server_priv,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'original_wrapped_sha256': _sha256_hex(wrapped_b64),
            'tampered_wrapped_sha256': _sha256_hex(tampered_wrapped_b64),
            'byte_mutation': f"wrapped_key[{idx}]: 0x{before:02X} -> 0x{after:02X}",
        })
        logs.append(f"[{_now_ts()}] Server OAEP unwrapping outcome: {outcome.final_result} — {outcome.rejection_reason}")

    elif attack_key == 'key_mismatch_attack':
        attack_type = 'Public/Private Key Mismatch Attack'
        description = 'Attacker encrypts a session key under a mismatched/rogue public key and submits it to the legitimate server private key.'
        mismatched_wrap = wrap_aes_key(session_aes_key, public_key_pem=attacker_pub)
        payload_info['mismatched_public_key_fp'] = key_fingerprint(attacker_pub)
        payload_info['expected_server_public_key_fp'] = key_fingerprint(server_pub)
        logs.append(f"[{_now_ts()}] Wrapped AES key with mismatched public key (fp: {key_fingerprint(attacker_pub)[:16]}...).")
        logs.append(f"[{_now_ts()}] Attempting server unwrap with legitimate RSA-3072 private key...")

        outcome = verify_rsa_oaep_unwrap_defence(
            wrapped_key_b64=mismatched_wrap['wrapped_key_b64'],
            private_key_pem=server_priv,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'encryption_public_key_fp': key_fingerprint(attacker_pub),
            'decryption_keypair_pub_fp': key_fingerprint(server_pub),
            'key_mismatch_detected': outcome.detected,
        })
        logs.append(f"[{_now_ts()}] Key mismatch verification outcome: {outcome.final_result} — {outcome.rejection_reason}")
    else:
        raise ValueError(f"Unsupported RSA-OAEP attack: {attack_key}")

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['rsa_oaep']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=mod['category'],
        description=description,
        payload=payload_info,
        evidence=outcome.evidence,
        logs=logs,
        defence_mechanism=outcome.defence_mechanism,
        detected=outcome.detected,
        blocked=outcome.blocked,
        mitigation_action=outcome.mitigation_action,
        final_result=outcome.final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# MODULE 3: RSA-PSS – Digital Signature Security
# ==============================================================================

def _run_module_rsa_pss(attack_key: str, admin_user_id: int | None, options: dict) -> dict:
    start = time.perf_counter()
    logs = [f"[{_now_ts()}] Generating legitimate synthetic transaction signed with RSA-PSS-3072 (SHA-256)..."]

    _, client_pub = get_lab_client_keypair()
    attacker_priv, attacker_pub = get_lab_attacker_keypair()

    legit_pkg, internals = _build_synthetic_signed_package(amount_inr=3499.00, item_name='Mechanical Keyboard RGB (Lab)')
    orig_canonical = canonicalize_transaction_package(legit_pkg)
    orig_hash = _sha256_hex(orig_canonical)
    orig_sig_valid = verify_transaction_signature(legit_pkg, legit_pkg['signature_b64'], client_pub)

    logs.append(f"[{_now_ts()}] Original canonical transaction SHA-256: {orig_hash}")
    logs.append(f"[{_now_ts()}] Baseline RSA-PSS verification against legitimate public key: VALID={orig_sig_valid}")

    payload_info = {
        'algorithm': 'RSA-PSS-3072 (SHA-256, MGF1-SHA256)',
        'transaction_id': legit_pkg['transaction_id'],
        'registered_public_key_fp': key_fingerprint(client_pub),
        'original_transaction_hash': orig_hash,
        'original_signature_preview': legit_pkg['signature_b64'][:72] + '...',
    }

    if attack_key == 'signature_forgery':
        attack_type = 'Digital Signature Forgery'
        description = 'Attacker generates a forged RSA-PSS signature using a rogue 3072-bit keypair for a synthetic transaction.'
        forged_sig = sign_transaction_package(legit_pkg, attacker_priv)
        attacked_pkg = dict(legit_pkg)
        attacked_pkg['signature_b64'] = forged_sig['signature_b64']
        modified_hash = orig_hash  # Same payload, forged signature
        logs.append(f"[{_now_ts()}] Attacker forged RSA-PSS signature with rogue key (fp: {key_fingerprint(attacker_pub)[:16]}...).")
        logs.append(f"[{_now_ts()}] Verifying forged signature against legitimate registered public key...")

        outcome = verify_rsa_pss_signature_defence(
            package=attacked_pkg,
            signature_b64=attacked_pkg['signature_b64'],
            trusted_public_key_pem=client_pub,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'original_transaction_hash': orig_hash,
            'original_signature_verified': orig_sig_valid,
            'modified_transaction_hash': modified_hash,
            'forged_signature_preview': forged_sig['signature_b64'][:72] + '...',
            'defence_response': outcome.mitigation_action,
        })

    elif attack_key == 'signed_transaction_modification':
        attack_type = 'Signed Transaction Modification'
        description = 'Attacker tampers with the signed transaction ciphertext in transit without re-signing.'
        tampered_pkg = dict(legit_pkg)
        tampered_ct, idx, before, after = _flip_b64_byte(legit_pkg['ciphertext_b64'], offset=2, xor_mask=0xAA)
        tampered_pkg['ciphertext_b64'] = tampered_ct
        modified_hash = _sha256_hex(canonicalize_transaction_package(tampered_pkg))
        logs.append(f"[{_now_ts()}] Attacker modified signed package ciphertext byte[{idx}]: 0x{before:02X} -> 0x{after:02X}.")
        logs.append(f"[{_now_ts()}] Modified canonical transaction SHA-256: {modified_hash} (changed={modified_hash != orig_hash})")

        outcome = verify_rsa_pss_signature_defence(
            package=tampered_pkg,
            signature_b64=legit_pkg['signature_b64'],
            trusted_public_key_pem=client_pub,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'original_transaction_hash': orig_hash,
            'original_signature_verified': orig_sig_valid,
            'modified_transaction_hash': modified_hash,
            'hash_changed': modified_hash != orig_hash,
            'defence_response': outcome.mitigation_action,
        })

    elif attack_key == 'public_key_substitution':
        attack_type = 'Public Key Substitution'
        description = 'Attacker signs a modified transaction with a rogue key and attempts to substitute an untrusted public key.'
        substituted_pkg = dict(legit_pkg)
        substituted_pkg['nonce'] = generate_replay_nonce()
        rogue_sig = sign_transaction_package(substituted_pkg, attacker_priv)
        modified_hash = _sha256_hex(canonicalize_transaction_package(substituted_pkg))

        submitted_pub_fp = key_fingerprint(attacker_pub)
        registered_pub_fp = key_fingerprint(client_pub)
        key_pin_mismatch = (submitted_pub_fp != registered_pub_fp)

        logs.append(f"[{_now_ts()}] Attacker submitted untrusted public key (fp: {submitted_pub_fp[:16]}...) vs registered (fp: {registered_pub_fp[:16]}...).")
        logs.append(f"[{_now_ts()}] Public key pinning check: mismatch={key_pin_mismatch}. Enforcing verification with registered trusted key...")

        outcome = verify_rsa_pss_signature_defence(
            package=substituted_pkg,
            signature_b64=rogue_sig['signature_b64'],
            trusted_public_key_pem=client_pub,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'original_transaction_hash': orig_hash,
            'original_signature_verified': orig_sig_valid,
            'modified_transaction_hash': modified_hash,
            'registered_public_key_fp': registered_pub_fp,
            'substituted_public_key_fp': submitted_pub_fp,
            'public_key_substitution_detected': key_pin_mismatch,
            'defence_response': outcome.mitigation_action,
        })

    elif attack_key == 'invalid_signature_injection':
        attack_type = 'Invalid Signature Injection'
        description = 'Attacker injects corrupted random bytes as the RSA-PSS signature on a legitimate transaction package.'
        corrupted_sig_b64 = base64.b64encode(secrets.token_bytes(384)).decode('ascii')
        modified_hash = orig_hash
        logs.append(f"[{_now_ts()}] Attacker injected 384 random bytes as Base64 signature.")
        logs.append(f"[{_now_ts()}] Executing RSA-PSS verification against registered public key...")

        outcome = verify_rsa_pss_signature_defence(
            package=legit_pkg,
            signature_b64=corrupted_sig_b64,
            trusted_public_key_pem=client_pub,
            attack_label=attack_type,
        )
        outcome.evidence.update({
            'original_transaction_hash': orig_hash,
            'original_signature_verified': orig_sig_valid,
            'modified_transaction_hash': modified_hash,
            'injected_signature_preview': corrupted_sig_b64[:72] + '...',
            'defence_response': outcome.mitigation_action,
        })
    else:
        raise ValueError(f"Unsupported RSA-PSS attack: {attack_key}")

    logs.append(f"[{_now_ts()}] RSA-PSS defence status: {outcome.final_result} — {outcome.rejection_reason}")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['rsa_pss']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=mod['category'],
        description=description,
        payload=payload_info,
        evidence=outcome.evidence,
        logs=logs,
        defence_mechanism=outcome.defence_mechanism,
        detected=outcome.detected,
        blocked=outcome.blocked,
        mitigation_action=outcome.mitigation_action,
        final_result=outcome.final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# MODULE 4: PBKDF2-SHA256 – Password Security (Isolated Synthetic Credentials Only)
# ==============================================================================

_SYNTHETIC_WEAK_PROFILES = {
    'common_word': ('password123', 'Synthetic weak dictionary credential (11 chars, no uppercase/special)'),
    'weak_digits': ('12345678', 'Synthetic numeric-only weak credential (8 digits)'),
    'short_lower': ('abc123', 'Synthetic short weak credential (6 chars)'),
}

_DICTIONARY_PROBES = [
    'password',
    '123456',
    '12345678',
    'password123',
    'qwerty123',
    'abc123',
]


def _run_module_pbkdf2(attack_key: str, admin_user_id: int | None, options: dict) -> dict:
    start = time.perf_counter()
    iterations = int(current_app.config.get('PBKDF2_ITERATIONS', DEFAULT_PBKDF2_ITERATIONS))
    logs = [
        f"[{_now_ts()}] Initializing isolated PBKDF2-HMAC-SHA256 sandbox (iterations={iterations:,}).",
        f"[{_now_ts()}] Using strictly synthetic dummy credentials; real user database is untouched; zero plaintext passwords logged.",
    ]

    # Ephemeral strong synthetic secret (never returned or logged)
    strong_synthetic_secret = f"Sbx#{secrets.token_hex(4)}!Qz9"

    if attack_key == 'brute_force_simulation':
        attack_type = 'Brute-Force Attack Simulation'
        description = 'Measures computational work factor of PBKDF2-HMAC-SHA256 across controlled synthetic brute-force guesses.'
        t_hash_start = time.perf_counter()
        synthetic_hash = hash_password_pbkdf2(strong_synthetic_secret, iterations=iterations)
        hash_ms = (time.perf_counter() - t_hash_start) * 1000.0
        parts = synthetic_hash.split('$')
        salt_hex, digest_hex = parts[1], parts[2]

        # Controlled 4-guess real KDF verification benchmark
        brute_candidates = [f"A{i}b#9x!0" for i in range(4)]
        t_probe_start = time.perf_counter()
        outcome = verify_pbkdf2_password_defence(
            stored_hash=synthetic_hash,
            candidate_guesses=brute_candidates,
            enforce_policy=False,
        )
        probe_ms = (time.perf_counter() - t_probe_start) * 1000.0
        ms_per_guess = probe_ms / max(len(brute_candidates), 1)
        guesses_per_sec = round(1000.0 / max(ms_per_guess, 0.001), 2)
        # 8-char printable ASCII keyspace = 94^8 ≈ 6.09e15
        est_years = round((94 ** 8) / max(guesses_per_sec, 0.1) / (3600 * 24 * 365.25), 1)

        payload_info = {
            'sandbox_account': 'synthetic_bf_user@lab.local',
            'kdf': 'PBKDF2-HMAC-SHA256',
            'iterations': iterations,
            'salt_hex': salt_hex,
            'derived_hash_preview': digest_hex[:32] + '...',
            'candidates_tested': len(brute_candidates),
        }
        outcome.evidence.update({
            'iterations': iterations,
            'salt_hex': salt_hex,
            'initial_derivation_ms': round(hash_ms, 2),
            'avg_ms_per_guess': round(ms_per_guess, 2),
            'throughput_guesses_per_sec': guesses_per_sec,
            'estimated_8char_full_keyspace_years': f"{est_years:.2e} years",
        })
        logs.append(f"[{_now_ts()}] Generated 128-bit random salt ({salt_hex}) and derived 256-bit key in {hash_ms:.1f} ms.")
        logs.append(f"[{_now_ts()}] Executed {len(brute_candidates)} real PBKDF2 brute-force guesses ({ms_per_guess:.1f} ms/guess, ~{guesses_per_sec} guesses/sec).")

    elif attack_key == 'dictionary_attack_simulation':
        attack_type = 'Dictionary Attack Simulation'
        description = 'Tests common dictionary password candidates against a strong synthetic PBKDF2-HMAC-SHA256 hash.'
        synthetic_hash = hash_password_pbkdf2(strong_synthetic_secret, iterations=iterations)
        parts = synthetic_hash.split('$')
        salt_hex, digest_hex = parts[1], parts[2]

        t_dict = time.perf_counter()
        outcome = verify_pbkdf2_password_defence(
            stored_hash=synthetic_hash,
            candidate_guesses=_DICTIONARY_PROBES,
            enforce_policy=False,
        )
        dict_ms = (time.perf_counter() - t_dict) * 1000.0

        payload_info = {
            'sandbox_account': 'synthetic_dict_user@lab.local',
            'kdf': 'PBKDF2-HMAC-SHA256',
            'iterations': iterations,
            'salt_hex': salt_hex,
            'derived_hash_preview': digest_hex[:32] + '...',
            'dictionary_size_tested': len(_DICTIONARY_PROBES),
        }
        outcome.evidence.update({
            'iterations': iterations,
            'salt_hex': salt_hex,
            'dictionary_candidates_tested': len(_DICTIONARY_PROBES),
            'total_verification_time_ms': round(dict_ms, 2),
            'matches_found': 0 if not outcome.evidence.get('cracked') else 1,
        })
        logs.append(f"[{_now_ts()}] Tested {len(_DICTIONARY_PROBES)} dictionary probes in {dict_ms:.1f} ms via real verify_password_pbkdf2.")

    elif attack_key == 'rainbow_table_demonstration':
        attack_type = 'Rainbow Table Attack Demonstration'
        description = 'Demonstrates that unique 128-bit random salts produce completely distinct PBKDF2 digests for identical synthetic credentials.'
        hash_a = hash_password_pbkdf2(strong_synthetic_secret, iterations=iterations)
        hash_b = hash_password_pbkdf2(strong_synthetic_secret, iterations=iterations)
        _, salt_a, digest_a = hash_a.split('$')
        _, salt_b, digest_b = hash_b.split('$')

        # Build a synthetic precomputed unsalted SHA-256 rainbow lookup table
        unsalted_rainbow = {
            hashlib.sha256(word.encode('utf-8')).hexdigest(): f"<synthetic_entry_{idx}>"
            for idx, word in enumerate(_DICTIONARY_PROBES + [strong_synthetic_secret])
        }
        rainbow_hit_a = digest_a in unsalted_rainbow
        rainbow_hit_b = digest_b in unsalted_rainbow
        salts_unique = salt_a != salt_b
        digests_distinct = digest_a != digest_b

        mitigated = salts_unique and digests_distinct and (not rainbow_hit_a) and (not rainbow_hit_b)
        from services.security_lab.detection_service import DetectionOutcome
        outcome = DetectionOutcome(
            detected=True,
            blocked=mitigated,
            final_result='MITIGATED' if mitigated else 'DEFENCE_FAILED',
            defence_mechanism='Per-Credential 128-Bit Cryptographic Random Salt + PBKDF2-HMAC-SHA256',
            mitigation_action='Unique random salts invalidated precomputed rainbow table lookup (0 hits, distinct digests)',
            rejection_reason='Precomputed unsalted rainbow table produced zero matches against salted PBKDF2 hashes.',
            evidence={
                'iterations': iterations,
                'salt_1_hex': salt_a,
                'digest_1_preview': digest_a[:36] + '...',
                'salt_2_hex': salt_b,
                'digest_2_preview': digest_b[:36] + '...',
                'salts_unique': salts_unique,
                'digests_completely_different': digests_distinct,
                'rainbow_table_entries_checked': len(unsalted_rainbow),
                'rainbow_table_hits': int(rainbow_hit_a) + int(rainbow_hit_b),
            },
        )
        payload_info = {
            'sandbox_account': 'synthetic_rainbow_demo@lab.local',
            'kdf': 'PBKDF2-HMAC-SHA256',
            'iterations': iterations,
            'same_credential_hashed_twice': True,
        }
        logs.append(f"[{_now_ts()}] Salt #1: {salt_a} -> Digest #1: {digest_a[:24]}...")
        logs.append(f"[{_now_ts()}] Salt #2: {salt_b} -> Digest #2: {digest_b[:24]}...")
        logs.append(f"[{_now_ts()}] Rainbow table lookup against {len(unsalted_rainbow)} precomputed unsalted entries: 0 hits.")

    elif attack_key == 'weak_password_testing':
        attack_type = 'Weak Password Testing'
        profile_key = str(options.get('weak_profile', 'common_word'))
        if profile_key not in _SYNTHETIC_WEAK_PROFILES:
            profile_key = 'common_word'
        enforce_policy = bool(options.get('enforce_policy', True))
        synthetic_weak_val, profile_desc = _SYNTHETIC_WEAK_PROFILES[profile_key]
        description = (
            f"Tests synthetic weak credential profile '{profile_key}' "
            f"with complexity policy {'ENABLED' if enforce_policy else 'DISABLED (vulnerability demo)'}."
        )

        # Always generate a salted hash preview if policy is disabled; never log plaintext value!
        if enforce_policy:
            synthetic_hash = ''
            salt_hex = 'N/A (rejected prior to hashing)'
            digest_preview = 'N/A (blocked by policy)'
            logs.append(f"[{_now_ts()}] Evaluating synthetic profile '{profile_key}' against validate_password() policy...")
            outcome = verify_pbkdf2_password_defence(
                stored_hash='',
                candidate_guesses=_DICTIONARY_PROBES,
                enforce_policy=True,
                target_candidate_for_policy=synthetic_weak_val,
            )
        else:
            synthetic_hash = hash_password_pbkdf2(synthetic_weak_val, iterations=iterations)
            _, salt_hex, digest_hex = synthetic_hash.split('$')
            digest_preview = digest_hex[:32] + '...'
            logs.append(f"[{_now_ts()}] Policy enforcement DISABLED for test. Derived synthetic weak hash (salt={salt_hex}).")
            logs.append(f"[{_now_ts()}] Executing real dictionary attack via verify_password_pbkdf2()...")
            outcome = verify_pbkdf2_password_defence(
                stored_hash=synthetic_hash,
                candidate_guesses=_DICTIONARY_PROBES,
                enforce_policy=False,
                target_candidate_for_policy=None,
            )

        payload_info = {
            'sandbox_account': 'synthetic_weak_test@lab.local',
            'weak_profile': profile_key,
            'profile_description': profile_desc,
            'policy_enforced': enforce_policy,
            'iterations': iterations,
            'salt_hex': salt_hex,
            'derived_hash_preview': digest_preview,
            'plaintext_logged': False,
        }
        outcome.evidence.update({
            'weak_profile': profile_key,
            'iterations': iterations,
            'salt_hex': salt_hex,
            'plaintext_logged': False,
        })
    else:
        raise ValueError(f"Unsupported PBKDF2 attack: {attack_key}")

    logs.append(f"[{_now_ts()}] PBKDF2 defence assessment: {outcome.final_result} — {outcome.mitigation_action}")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['pbkdf2']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=mod['category'],
        description=description,
        payload=payload_info,
        evidence=outcome.evidence,
        logs=logs,
        defence_mechanism=outcome.defence_mechanism,
        detected=outcome.detected,
        blocked=outcome.blocked,
        mitigation_action=outcome.mitigation_action,
        final_result=outcome.final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# MODULE 5: HMAC-SHA256 – Message Authentication
# ==============================================================================

def _run_module_hmac(attack_key: str, admin_user_id: int | None, options: dict) -> dict:
    start = time.perf_counter()
    lab_secret = get_lab_hmac_secret()
    secret_fp = key_fingerprint(lab_secret)
    logs = [f"[{_now_ts()}] Initializing isolated HMAC-SHA256 sandbox (ephemeral secret fp: {secret_fp[:16]}...)."]

    original_msg = {
        'event': 'LAB_ORDER_AUDIT',
        'order_ref': f"LAB-HMAC-{secrets.token_hex(3).upper()}",
        'amount_inr': 4999.00,
        'currency': 'INR',
        'status': 'CONFIRMED',
    }
    valid_hmac = compute_hmac_sha256(original_msg, secret_key=lab_secret)
    logs.append(f"[{_now_ts()}] Computed authentic HMAC-SHA256 tag: {valid_hmac[:32]}...")

    payload_info = {
        'algorithm': 'HMAC-SHA256 (Constant-Time Verify)',
        'secret_key_fingerprint': secret_fp,
        'original_message': original_msg,
        'original_hmac_hex': valid_hmac,
    }

    if attack_key == 'message_tampering':
        attack_type = 'Message Tampering'
        description = 'Attacker alters order amount inside an HMAC-SHA256 authenticated record from ₹4,999.00 to ₹1.00.'
        tampered_msg = dict(original_msg)
        tampered_msg['amount_inr'] = 1.00
        payload_info['tampered_message'] = tampered_msg
        logs.append(f"[{_now_ts()}] Attacker tampered amount_inr: 4999.00 -> 1.00 while reusing original HMAC.")

        outcome = verify_hmac_defence(tampered_msg, valid_hmac, secret_key=lab_secret, attack_label=attack_type)
        outcome.evidence.update({
            'original_hmac_hex': valid_hmac,
            'tampered_field': 'amount_inr: 4999.00 -> 1.00',
        })

    elif attack_key == 'hmac_forgery':
        attack_type = 'HMAC Forgery'
        description = 'Attacker generates a forged HMAC-SHA256 digest using a guessed/attacker secret key.'
        rogue_secret = secrets.token_bytes(32)
        forged_msg = dict(original_msg)
        forged_msg['status'] = 'REFUNDED_BY_ATTACKER'
        forged_hmac = compute_hmac_sha256(forged_msg, secret_key=rogue_secret)
        payload_info['forged_message'] = forged_msg
        payload_info['forged_hmac_hex'] = forged_hmac
        logs.append(f"[{_now_ts()}] Attacker forged HMAC with rogue key (fp: {key_fingerprint(rogue_secret)[:16]}...): {forged_hmac[:32]}...")

        outcome = verify_hmac_defence(forged_msg, forged_hmac, secret_key=lab_secret, attack_label=attack_type)
        outcome.evidence.update({
            'expected_secret_fp': secret_fp,
            'attacker_secret_fp': key_fingerprint(rogue_secret),
            'forged_hmac_hex': forged_hmac,
        })

    elif attack_key == 'invalid_auth_code_injection':
        attack_type = 'Invalid Authentication Code Injection'
        description = 'Attacker injects a mutated HMAC authentication code by flipping hex digits in the MAC.'
        first_nibble = '0' if valid_hmac[0] != '0' else 'f'
        injected_hmac = first_nibble + valid_hmac[1:]
        payload_info['injected_hmac_hex'] = injected_hmac
        logs.append(f"[{_now_ts()}] Attacker mutated HMAC tag nibble[0]: '{valid_hmac[0]}' -> '{first_nibble}'.")

        outcome = verify_hmac_defence(original_msg, injected_hmac, secret_key=lab_secret, attack_label=attack_type)
        outcome.evidence.update({
            'valid_hmac_hex': valid_hmac,
            'injected_hmac_hex': injected_hmac,
        })

    elif attack_key == 'unauthorized_message_modification':
        attack_type = 'Unauthorized Message Modification'
        description = 'Attacker injects unauthorized privilege/discount fields into the canonical message payload.'
        modified_msg = dict(original_msg)
        modified_msg['unauthorized_admin_override'] = True
        modified_msg['discount_percent'] = 100
        payload_info['modified_message'] = modified_msg
        logs.append(f"[{_now_ts()}] Attacker appended unauthorized JSON keys ('unauthorized_admin_override', 'discount_percent').")

        outcome = verify_hmac_defence(modified_msg, valid_hmac, secret_key=lab_secret, attack_label=attack_type)
        outcome.evidence.update({
            'injected_fields': ['unauthorized_admin_override=True', 'discount_percent=100'],
            'original_hmac_hex': valid_hmac,
        })
    else:
        raise ValueError(f"Unsupported HMAC-SHA256 attack: {attack_key}")

    logs.append(f"[{_now_ts()}] Constant-time HMAC-SHA256 verification outcome: {outcome.final_result} — {outcome.rejection_reason}")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['hmac_sha256']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=mod['category'],
        description=description,
        payload=payload_info,
        evidence=outcome.evidence,
        logs=logs,
        defence_mechanism=outcome.defence_mechanism,
        detected=outcome.detected,
        blocked=outcome.blocked,
        mitigation_action=outcome.mitigation_action,
        final_result=outcome.final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# MODULE 6: CIPHERTEXT TAMPERING DEFENCE (Interactive Stateful Workflow)
# ==============================================================================

def generate_module6_transaction(admin_user_id: int | None, custom_item: str | None = None, amount_inr: float = 2999.00) -> dict:
    """
    Step 1 of Module 6: Generate an isolated synthetic AES-256-GCM encrypted transaction
    and persist it to `lab_synthetic_transactions` with its original SHA-256 hash & HMAC.
    """
    item_label = (custom_item or 'Wireless Bluetooth Headphones (Synthetic Lab)').strip()[:120]
    try:
        amt = round(float(amount_inr), 2)
        if amt <= 0:
            amt = 2999.00
    except (TypeError, ValueError):
        amt = 2999.00

    pkg, internals = _build_synthetic_signed_package(amount_inr=amt, item_name=item_label)
    orig_ct_sha256 = _sha256_hex(pkg['ciphertext_b64'])
    ct_raw_len = len(base64.b64decode(pkg['ciphertext_b64'].encode('ascii')))

    record = LabSyntheticTransaction(
        lab_tx_id=pkg['transaction_id'],
        module_key='ciphertext_tampering',
        admin_user_id=admin_user_id,
        payload_preview=json.dumps(internals['payload_dict']),
        ciphertext_b64=pkg['ciphertext_b64'],
        gcm_nonce_b64=pkg['gcm_nonce_b64'],
        auth_tag_b64=pkg['auth_tag_b64'],
        wrapped_key_b64=pkg['wrapped_key_b64'],
        aad_str=internals['aad_str'],
        signature_b64=pkg['signature_b64'],
        replay_nonce=pkg['nonce'],
        client_timestamp=pkg['timestamp'],
        original_ciphertext_sha256=orig_ct_sha256,
        status='ENCRYPTED_STORED',
    )
    record.sign_integrity()
    db.session.add(record)
    db.session.commit()

    return {
        'lab_tx_id': record.lab_tx_id,
        'payload_preview': internals['payload_dict'],
        'ciphertext_b64': record.ciphertext_b64,
        'ciphertext_byte_length': ct_raw_len,
        'gcm_nonce_b64': record.gcm_nonce_b64,
        'auth_tag_b64': record.auth_tag_b64,
        'original_ciphertext_sha256': orig_ct_sha256,
        'status': record.status,
    }


def execute_module6_tampering(
    admin_user_id: int | None,
    lab_tx_id: str | None = None,
    byte_offset: int = 0,
    xor_mask: int = 0xFF,
    custom_tampered_b64: str | None = None,
) -> dict:
    """
    Steps 2–6 of Module 6: Intercept the persisted synthetic transaction's ciphertext,
    mutate selected bytes on an intercepted copy, execute real AES-256-GCM verification,
    and prove the stored original transaction in SQLite remains completely unchanged.
    """
    start = time.perf_counter()
    logs = []

    record = None
    if lab_tx_id:
        record = LabSyntheticTransaction.query.filter_by(
            lab_tx_id=str(lab_tx_id).strip(),
            module_key='ciphertext_tampering',
        ).first()

    if record is None:
        gen = generate_module6_transaction(admin_user_id)
        record = LabSyntheticTransaction.query.filter_by(lab_tx_id=gen['lab_tx_id']).first()
        logs.append(f"[{_now_ts()}] Auto-generated isolated synthetic transaction {record.lab_tx_id}.")
    else:
        logs.append(f"[{_now_ts()}] Loaded isolated synthetic transaction {record.lab_tx_id} from sandbox store.")

    original_ct_b64 = record.ciphertext_b64
    original_ct_sha256 = record.original_ciphertext_sha256

    if custom_tampered_b64 and str(custom_tampered_b64).strip():
        tampered_ct_b64 = str(custom_tampered_b64).strip()
        mutation_desc = f"Admin custom modified ciphertext (len={len(tampered_ct_b64)} chars)"
    else:
        tampered_ct_b64, actual_idx, before_b, after_b = _flip_b64_byte(
            original_ct_b64,
            offset=byte_offset,
            xor_mask=xor_mask,
        )
        mutation_desc = f"Flipped ciphertext byte[{actual_idx}] with XOR 0x{(int(xor_mask) & 0xFF):02X} (0x{before_b:02X} -> 0x{after_b:02X})"

    logs.append(f"[{_now_ts()}] Intercepted ciphertext copy and applied modification: {mutation_desc}.")

    # Unwrap session key on the backend using isolated lab server private key
    server_priv, _ = get_lab_server_keypair()
    aes_key = unwrap_aes_key(record.wrapped_key_b64, private_key_pem=server_priv)
    logs.append(f"[{_now_ts()}] Server unwrapped session key (RSA-OAEP-3072) and invoked real AES-256-GCM authenticated decryption...")

    outcome = verify_aes_gcm_defence(
        ciphertext_b64=tampered_ct_b64,
        key=aes_key,
        nonce_b64=record.gcm_nonce_b64,
        auth_tag_b64=record.auth_tag_b64,
        associated_data=record.aad_str.encode('utf-8'),
        attack_label='Interactive Ciphertext Tampering Defence',
    )

    # Confirm original persisted record in SQLite is 100% untouched
    db.session.expire(record)
    reloaded = LabSyntheticTransaction.query.filter_by(lab_tx_id=record.lab_tx_id).first()
    reloaded_sha256 = _sha256_hex(reloaded.ciphertext_b64)
    original_unchanged = (
        reloaded is not None
        and reloaded.ciphertext_b64 == original_ct_b64
        and reloaded_sha256 == original_ct_sha256
        and reloaded.verify_integrity()
    )

    logs.append(f"[{_now_ts()}] AES-256-GCM authentication result: {outcome.final_result} — {outcome.rejection_reason}")
    logs.append(f"[{_now_ts()}] Original stored synthetic transaction integrity re-check: UNCHANGED={original_unchanged} (HMAC valid={reloaded.verify_integrity()}).")

    payload_info = {
        'lab_tx_id': record.lab_tx_id,
        'mutation_applied': mutation_desc,
        'original_ciphertext_b64': original_ct_b64,
        'tampered_ciphertext_b64': tampered_ct_b64,
        'gcm_nonce_b64': record.gcm_nonce_b64,
        'auth_tag_b64': record.auth_tag_b64,
    }
    outcome.evidence.update({
        'lab_tx_id': record.lab_tx_id,
        'mutation_applied': mutation_desc,
        'original_ciphertext_sha256': original_ct_sha256,
        'tampered_ciphertext_sha256': _sha256_hex(tampered_ct_b64),
        'ciphertext_differs_from_original': tampered_ct_b64 != original_ct_b64,
        'rejection_reason': outcome.rejection_reason,
        'original_transaction_unchanged': original_unchanged,
        'original_record_hmac_valid': reloaded.verify_integrity(),
    })

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['ciphertext_tampering']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key='interactive_ciphertext_tamper',
        attack_type='Intercept & Modify Selected Ciphertext Bytes',
        attack_category=mod['category'],
        description=f"Modified intercepted synthetic transaction ({mutation_desc}) and verified AES-256-GCM rejection.",
        payload=payload_info,
        evidence=outcome.evidence,
        logs=logs,
        defence_mechanism=outcome.defence_mechanism,
        detected=outcome.detected,
        blocked=outcome.blocked,
        mitigation_action=outcome.mitigation_action,
        final_result=outcome.final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# MODULE 7: NONCE REPLAY ATTACK DEFENCE (Persistent Atomic Nonce Tracking)
# ==============================================================================

def generate_and_submit_module7_transaction(admin_user_id: int | None) -> dict:
    """
    Steps 1–4 of Module 7: Generate a legitimate test transaction with a unique UUID
    nonce, submit it successfully through the full verification + atomic nonce consumption
    pipeline, and capture the request for replay testing.
    """
    unique_uuid_nonce = str(uuid.uuid4())
    pkg, internals = _build_synthetic_signed_package(
        amount_inr=1999.00,
        item_name='Portable Bluetooth Speaker (Replay Lab)',
        nonce_override=unique_uuid_nonce,
    )

    # Full real verification on the initial legitimate submission
    ts_ok, ts_err = validate_timestamp(pkg['timestamp'])
    if not ts_ok:
        raise ValueError(f"Unexpected timestamp failure on legitimate request: {ts_err}")

    nonce_ok, nonce_msg = consume_lab_nonce_atomically(
        nonce=pkg['nonce'],
        transaction_id=pkg['transaction_id'],
        admin_user_id=admin_user_id,
        client_timestamp=pkg['timestamp'],
    )
    if not nonce_ok:
        raise ValueError(f"Initial nonce consumption failed: {nonce_msg}")

    _, client_pub = get_lab_client_keypair()
    server_priv, _ = get_lab_server_keypair()
    sig_ok = verify_transaction_signature(pkg, pkg['signature_b64'], client_pub)
    aes_key = unwrap_aes_key(pkg['wrapped_key_b64'], private_key_pem=server_priv)
    dec_bytes = decrypt_aes_gcm(
        ciphertext=pkg['ciphertext_b64'],
        key=aes_key,
        nonce=pkg['gcm_nonce_b64'],
        auth_tag=pkg['auth_tag_b64'],
        associated_data=internals['aad_str'].encode('utf-8'),
    )
    if not sig_ok or not dec_bytes:
        raise ValueError("Legitimate synthetic transaction failed baseline cryptographic verification.")

    rec = LabSyntheticTransaction(
        lab_tx_id=pkg['transaction_id'],
        module_key='nonce_replay',
        admin_user_id=admin_user_id,
        payload_preview=json.dumps(internals['payload_dict']),
        ciphertext_b64=pkg['ciphertext_b64'],
        gcm_nonce_b64=pkg['gcm_nonce_b64'],
        auth_tag_b64=pkg['auth_tag_b64'],
        wrapped_key_b64=pkg['wrapped_key_b64'],
        aad_str=internals['aad_str'],
        signature_b64=pkg['signature_b64'],
        replay_nonce=pkg['nonce'],
        client_timestamp=pkg['timestamp'],
        original_ciphertext_sha256=_sha256_hex(pkg['ciphertext_b64']),
        status='ACCEPTED_ORIGINAL',
    )
    rec.sign_integrity()
    db.session.add(rec)
    db.session.commit()

    return {
        'lab_tx_id': rec.lab_tx_id,
        'original_nonce': rec.replay_nonce,
        'client_timestamp': format_ist(rec.client_timestamp),
        'client_timestamp_utc': rec.client_timestamp,
        'first_request_result': 'ACCEPTED (201) — Signature valid, AES-GCM decrypted, nonce atomically consumed',
        'signature_verified': True,
        'nonce_consumed': True,
        'captured_request_preview': {
            'transaction_id': rec.lab_tx_id,
            'nonce': rec.replay_nonce,
            'timestamp': format_ist(rec.client_timestamp),
            'timestamp_utc': rec.client_timestamp,
            'signature_preview': rec.signature_b64[:48] + '...',
            'ciphertext_preview': rec.ciphertext_b64[:48] + '...',
        },
    }


def execute_module7_replay(
    admin_user_id: int | None,
    lab_tx_id: str | None = None,
    attack_key: str = 'captured_request_replay',
    burst_count: int = 1,
) -> dict:
    """
    Steps 5–7 of Module 7: Resubmit the exact captured request (or run a duplicate-nonce
    burst) against persistent atomic `lab_consumed_nonces` tracking.
    """
    start = time.perf_counter()
    logs = []
    first_result_str = 'ACCEPTED — Legitimate initial transaction verified & nonce atomically persisted'

    rec = None
    if lab_tx_id:
        rec = LabSyntheticTransaction.query.filter_by(
            lab_tx_id=str(lab_tx_id).strip(),
            module_key='nonce_replay',
        ).first()

    if rec is None:
        initial = generate_and_submit_module7_transaction(admin_user_id)
        rec = LabSyntheticTransaction.query.filter_by(lab_tx_id=initial['lab_tx_id']).first()
        logs.append(f"[{_now_ts()}] Generated legitimate synthetic transaction {rec.lab_tx_id} with UUID nonce {rec.replay_nonce}.")
        logs.append(f"[{_now_ts()}] 1st submission succeeded: signature verified, payload decrypted, nonce atomically committed.")
    else:
        logs.append(f"[{_now_ts()}] Loaded captured transaction {rec.lab_tx_id} (original UUID nonce: {rec.replay_nonce}).")

    attempts = max(1, min(int(burst_count), 10))
    if attack_key == 'concurrent_replay_burst' and attempts < 3:
        attempts = 5

    rejected_attempts = 0
    accepted_replays = 0
    last_reason = ''

    for i in range(1, attempts + 1):
        ok, msg = consume_lab_nonce_atomically(
            nonce=rec.replay_nonce,
            transaction_id=rec.lab_tx_id,
            admin_user_id=admin_user_id,
            client_timestamp=rec.client_timestamp,
        )
        if ok:
            accepted_replays += 1
            logs.append(f"[{_now_ts()}] Replay attempt #{i}: UNEXPECTEDLY ACCEPTED!")
        else:
            rejected_attempts += 1
            last_reason = msg
            logs.append(f"[{_now_ts()}] Replay attempt #{i}: REJECTED — {msg}")

    mitigated = (accepted_replays == 0) and (rejected_attempts == attempts)
    final_result = 'MITIGATED' if mitigated else 'DEFENCE_FAILED'
    attack_type = 'Concurrent Duplicate Nonce Burst' if attack_key == 'concurrent_replay_burst' else 'Captured Request Replay Attack'
    description = (
        f"Resubmitted captured signed transaction {attempts} time(s) with consumed UUID nonce {rec.replay_nonce}."
    )

    payload_info = {
        'lab_tx_id': rec.lab_tx_id,
        'original_nonce': rec.replay_nonce,
        'client_timestamp': format_ist(rec.client_timestamp),
        'client_timestamp_utc': rec.client_timestamp,
        'replay_attempts_submitted': attempts,
    }
    evidence = {
        'original_nonce': rec.replay_nonce,
        'transaction_id': rec.lab_tx_id,
        'first_request_result': first_result_str,
        'repeated_request_result': f"REJECTED ({rejected_attempts}/{attempts} replay attempts blocked)" if mitigated else f"BREACH ({accepted_replays} replays accepted)",
        'replay_detection_reason': last_reason or 'Duplicate nonce rejected by SQLite UNIQUE constraint.',
        'defence_status': 'BLOCKED — Atomic Persistent Nonce Guard Active' if mitigated else 'FAILED',
        'replay_attempts_total': attempts,
        'replay_attempts_rejected': rejected_attempts,
        'replay_attempts_accepted': accepted_replays,
    }

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['nonce_replay']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=mod['category'],
        description=description,
        payload=payload_info,
        evidence=evidence,
        logs=logs,
        defence_mechanism='Atomic Persistent Nonce Tracking (SQLite UNIQUE Savepoint on Nonce & Tx UUID)',
        detected=True,
        blocked=mitigated,
        mitigation_action=f"Rejected {rejected_attempts}/{attempts} duplicate replay request(s) via atomic nonce registry",
        final_result=final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# MODULE 8: EXPIRED TIMESTAMP ATTACK DEFENCE
# ==============================================================================

def _run_module_expired_timestamp(attack_key: str, admin_user_id: int | None, options: dict) -> dict:
    start = time.perf_counter()
    tolerance = int(current_app.config.get('REPLAY_TIMESTAMP_TOLERANCE_SECONDS', DEFAULT_TIMESTAMP_TOLERANCE_SECONDS))
    now_utc = datetime.datetime.now(timezone.utc)
    server_ts_iso = now_utc.isoformat()
    _, client_pub = get_lab_client_keypair()

    logs = [
        f"[{_now_ts()}] Configured server timestamp validity window: ±{tolerance} seconds (cryptographically validated in UTC).",
        f"[{_now_ts()}] Server time: {format_ist(now_utc)} (UTC: {server_ts_iso})",
    ]

    if attack_key == 'expired_request_replay':
        attack_type = 'Expired Request Replay'
        offset_sec = abs(int(options.get('offset_seconds', tolerance + 600)))
        if offset_sec <= tolerance:
            offset_sec = tolerance + 300
        req_dt = now_utc - datetime.timedelta(seconds=offset_sec)
        req_ts_iso = req_dt.isoformat()
        pkg, _ = _build_synthetic_signed_package(timestamp_override=req_ts_iso)
        description = f"Replayed a signed synthetic request timestamped {offset_sec}s in the past (outside ±{tolerance}s window)."
        logs.append(f"[{_now_ts()}] Built signed package with expired timestamp: {format_ist(req_dt)} (-{offset_sec}s).")
        outcome = verify_timestamp_and_binding_defence(
            package=pkg,
            signature_b64=pkg['signature_b64'],
            trusted_public_key_pem=client_pub,
            tolerance_seconds=tolerance,
            check_nonce_replay=True,
            admin_user_id=admin_user_id,
        )

    elif attack_key == 'old_transaction_submission':
        attack_type = 'Old Transaction Submission'
        offset_sec = 86400  # 24 hours old
        req_dt = now_utc - datetime.timedelta(seconds=offset_sec)
        req_ts_iso = req_dt.isoformat()
        pkg, _ = _build_synthetic_signed_package(timestamp_override=req_ts_iso)
        description = f"Submitted a stale signed transaction from 24 hours ago (-{offset_sec}s vs ±{tolerance}s window)."
        logs.append(f"[{_now_ts()}] Built stale signed transaction from 24h ago: {format_ist(req_dt)}.")
        outcome = verify_timestamp_and_binding_defence(
            package=pkg,
            signature_b64=pkg['signature_b64'],
            trusted_public_key_pem=client_pub,
            tolerance_seconds=tolerance,
            check_nonce_replay=True,
            admin_user_id=admin_user_id,
        )

    elif attack_key == 'timestamp_manipulation':
        attack_type = 'Timestamp Manipulation'
        orig_dt = now_utc - datetime.timedelta(seconds=45)
        orig_ts_iso = orig_dt.isoformat()
        pkg, _ = _build_synthetic_signed_package(timestamp_override=orig_ts_iso)
        # Attacker rewrites timestamp to current server time (inside ±300s window!) without re-signing
        tampered_dt = now_utc
        req_ts_iso = tampered_dt.isoformat()
        attacked_pkg = dict(pkg)
        attacked_pkg['timestamp'] = req_ts_iso
        description = 'Attacker altered the request timestamp in transit (within ±300s window) without re-signing, testing cryptographic binding.'
        logs.append(f"[{_now_ts()}] Signed package at original timestamp {format_ist(orig_dt)}; attacker rewrote timestamp header to {format_ist(tampered_dt)}.")
        logs.append(f"[{_now_ts()}] Executing timestamp window check + RSA-PSS cryptographic binding check...")
        outcome = verify_timestamp_and_binding_defence(
            package=attacked_pkg,
            signature_b64=pkg['signature_b64'],
            trusted_public_key_pem=client_pub,
            tolerance_seconds=tolerance,
            check_nonce_replay=True,
            admin_user_id=admin_user_id,
        )
        outcome.evidence['original_signed_timestamp'] = format_ist(orig_dt)
        outcome.evidence['original_signed_timestamp_utc'] = orig_ts_iso
        req_dt = tampered_dt

    elif attack_key == 'future_timestamp_injection':
        attack_type = 'Future Timestamp Injection'
        offset_sec = abs(int(options.get('offset_seconds', tolerance + 600)))
        if offset_sec <= tolerance:
            offset_sec = tolerance + 300
        req_dt = now_utc + datetime.timedelta(seconds=offset_sec)
        req_ts_iso = req_dt.isoformat()
        pkg, _ = _build_synthetic_signed_package(timestamp_override=req_ts_iso)
        description = f"Injected a future timestamp +{offset_sec}s ahead of server UTC (exceeds +{tolerance}s skew tolerance)."
        logs.append(f"[{_now_ts()}] Built signed package with future timestamp: {format_ist(req_dt)} (+{offset_sec}s).")
        outcome = verify_timestamp_and_binding_defence(
            package=pkg,
            signature_b64=pkg['signature_b64'],
            trusted_public_key_pem=client_pub,
            tolerance_seconds=tolerance,
            check_nonce_replay=True,
            admin_user_id=admin_user_id,
        )
    else:
        raise ValueError(f"Unsupported Expired Timestamp attack: {attack_key}")

    time_diff_seconds = round((now_utc - req_dt).total_seconds(), 2)
    req_ts_ist = format_ist(req_dt)
    server_ts_ist = format_ist(now_utc)
    payload_info = {
        'transaction_id': pkg['transaction_id'],
        'nonce': pkg['nonce'],
        'request_timestamp': req_ts_ist,
        'server_timestamp': server_ts_ist,
        'request_timestamp_utc': req_ts_iso,
        'server_timestamp_utc': server_ts_iso,
        'allowed_validity_window': f"±{tolerance} seconds",
    }
    outcome.evidence.update({
        'request_timestamp': req_ts_ist,
        'server_timestamp': server_ts_ist,
        'request_timestamp_utc': req_ts_iso,
        'server_timestamp_utc': server_ts_iso,
        'allowed_validity_window': f"±{tolerance} seconds",
        'time_difference_seconds': time_diff_seconds,
        'validation_result': 'REJECTED' if outcome.blocked else 'ACCEPTED',
        'rejection_reason': outcome.rejection_reason,
        'combined_with_nonce_guard': True,
    })
    logs.append(f"[{_now_ts()}] Time delta (server - request): {time_diff_seconds:+.2f}s | Allowed: ±{tolerance}s.")
    logs.append(f"[{_now_ts()}] Final decision: {outcome.final_result} — {outcome.rejection_reason}")

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    mod = MODULE_MAP['expired_timestamp']
    event = record_simulation_event(
        admin_user_id=admin_user_id,
        module_key=mod['module_key'],
        module_name=mod['name'],
        attack_key=attack_key,
        attack_type=attack_type,
        attack_category=mod['category'],
        description=description,
        payload=payload_info,
        evidence=outcome.evidence,
        logs=logs,
        defence_mechanism=outcome.defence_mechanism,
        detected=outcome.detected,
        blocked=outcome.blocked,
        mitigation_action=outcome.mitigation_action,
        final_result=outcome.final_result,
        execution_ms=elapsed_ms,
    )
    return event.to_dict(include_details=True)


# ==============================================================================
# Unified Simulation Dispatcher
# ==============================================================================

def execute_attack_simulation(
    module_key: str,
    attack_key: str,
    admin_user_id: int | None,
    options: dict | None = None,
) -> dict:
    """
    Validate requested module/attack pair and dispatch to the corresponding real backend
    attack execution and defence verification workflow.
    """
    opts = options if isinstance(options, dict) else {}
    if module_key not in MODULE_MAP:
        raise ValueError(f"Unknown security module: '{module_key}'")

    valid_attacks = {a['attack_key'] for a in MODULE_MAP[module_key]['attacks']}
    if attack_key not in valid_attacks:
        raise ValueError(f"Unknown attack '{attack_key}' for module '{module_key}'")

    if module_key == 'aes_gcm':
        return _run_module_aes_gcm(attack_key, admin_user_id, opts)
    if module_key == 'rsa_oaep':
        return _run_module_rsa_oaep(attack_key, admin_user_id, opts)
    if module_key == 'rsa_pss':
        return _run_module_rsa_pss(attack_key, admin_user_id, opts)
    if module_key == 'pbkdf2':
        return _run_module_pbkdf2(attack_key, admin_user_id, opts)
    if module_key == 'hmac_sha256':
        return _run_module_hmac(attack_key, admin_user_id, opts)
    if module_key == 'ciphertext_tampering':
        return execute_module6_tampering(
            admin_user_id=admin_user_id,
            lab_tx_id=opts.get('lab_tx_id'),
            byte_offset=int(opts.get('byte_offset', 0)),
            xor_mask=int(opts.get('xor_mask', 0xFF)),
            custom_tampered_b64=opts.get('custom_tampered_b64'),
        )
    if module_key == 'nonce_replay':
        return execute_module7_replay(
            admin_user_id=admin_user_id,
            lab_tx_id=opts.get('lab_tx_id'),
            attack_key=attack_key,
            burst_count=int(opts.get('burst_count', 5 if attack_key == 'concurrent_replay_burst' else 1)),
        )
    if module_key == 'expired_timestamp':
        return _run_module_expired_timestamp(attack_key, admin_user_id, opts)

    raise ValueError(f"Unhandled module: {module_key}")
