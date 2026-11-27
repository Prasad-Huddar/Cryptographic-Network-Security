"""
Attack Detection & Cryptographic Defence Verification Service.

Strictly separates attack execution from attack detection and mitigation verification.
Every detection function runs the real cryptographic verification logic from
`services/crypto/*` and never hardcodes a "blocked" outcome without real backend proof.
"""
from dataclasses import dataclass, field
from sqlalchemy.exc import IntegrityError

from database.database import db
from models.security_lab import LabConsumedNonce
from services.auth_service import validate_password
from services.crypto.aes_encryption import AESEncryptionError, decrypt_aes_gcm
from services.crypto.digital_signature import verify_transaction_signature
from services.crypto.integrity import verify_hmac_sha256, verify_password_pbkdf2
from services.crypto.rsa_encryption import RSAEncryptionError, unwrap_aes_key
from services.crypto.transaction_security import (
    DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    validate_timestamp,
)
from services.security_lab.sandbox_keys import KeyAccessDeniedError, lab_key_vault


@dataclass
class DetectionOutcome:
    """Structured outcome returned by backend defence/detection verifiers."""
    detected: bool
    blocked: bool
    final_result: str  # 'MITIGATED' | 'DEFENCE_FAILED' | 'DETECTED_ONLY'
    defence_mechanism: str
    mitigation_action: str
    rejection_reason: str
    evidence: dict = field(default_factory=dict)


def verify_aes_gcm_defence(
    ciphertext_b64: str,
    key: bytes,
    nonce_b64: str,
    auth_tag_b64: str,
    associated_data: bytes | str | None = None,
    attack_label: str = 'AES-256-GCM Verification',
) -> DetectionOutcome:
    """
    Run real AES-256-GCM authenticated decryption against attacked/tampered inputs.
    Only marks the attack as MITIGATED if `decrypt_aes_gcm` genuinely raises AESEncryptionError.
    """
    try:
        decrypted = decrypt_aes_gcm(
            ciphertext=ciphertext_b64,
            key=key,
            nonce=nonce_b64,
            auth_tag=auth_tag_b64,
            associated_data=associated_data,
        )
        # If decryption unexpectedly succeeded on an attacked payload, record real defence failure!
        return DetectionOutcome(
            detected=False,
            blocked=False,
            final_result='DEFENCE_FAILED',
            defence_mechanism='AES-256-GCM Authenticated Decryption (128-bit GHASH Tag)',
            mitigation_action='Payload accepted — cryptographic integrity check did not reject input',
            rejection_reason='No authentication failure raised during AES-256-GCM decryption.',
            evidence={
                'attack_label': attack_label,
                'decryption_succeeded': True,
                'plaintext_length_bytes': len(decrypted),
                'tag_verification': 'PASSED_UNEXPECTEDLY',
            },
        )
    except AESEncryptionError as exc:
        return DetectionOutcome(
            detected=True,
            blocked=True,
            final_result='MITIGATED',
            defence_mechanism='AES-256-GCM Authenticated Decryption (128-bit GHASH Tag)',
            mitigation_action='Rejected payload and aborted decryption immediately on InvalidTag',
            rejection_reason=str(exc),
            evidence={
                'attack_label': attack_label,
                'decryption_succeeded': False,
                'exception_type': 'AESEncryptionError (InvalidTag)',
                'exception_detail': str(exc),
                'tag_verification': 'FAILED_REJECTED',
            },
        )


def verify_key_vault_access_defence(
    key_id: str,
    caller_role: str,
    caller_identity: str,
) -> DetectionOutcome:
    """
    Enforce real RBAC & non-exportable HSM key-isolation policy against unauthorized key retrieval.
    """
    try:
        _leaked = lab_key_vault.attempt_raw_key_export(key_id, caller_role, caller_identity)
        return DetectionOutcome(
            detected=False,
            blocked=False,
            final_result='DEFENCE_FAILED',
            defence_mechanism='RBAC Key-Isolation Vault & Non-Exportable Key Policy',
            mitigation_action='Raw key material was exported — policy failed',
            rejection_reason='Vault permitted unauthorized key extraction.',
            evidence={
                'key_id': key_id,
                'caller_role': caller_role,
                'caller_identity': caller_identity,
                'key_exposed': True,
                'exported_bytes_len': len(_leaked),
            },
        )
    except KeyAccessDeniedError as exc:
        return DetectionOutcome(
            detected=True,
            blocked=True,
            final_result='MITIGATED',
            defence_mechanism='RBAC Key-Isolation Vault & Non-Exportable Key Policy',
            mitigation_action='Blocked raw key export, returned HTTP 403 / KeyAccessDeniedError, exposed 0 key bytes',
            rejection_reason=str(exc),
            evidence={
                'key_id': key_id,
                'caller_role': caller_role,
                'caller_identity': caller_identity,
                'key_exposed': False,
                'exported_bytes_len': 0,
                'policy_decision': 'DENY',
                'exception_detail': str(exc),
            },
        )


def verify_rsa_oaep_unwrap_defence(
    wrapped_key_b64: str,
    private_key_pem: bytes,
    attack_label: str = 'RSA-OAEP-3072 Key Unwrap',
) -> DetectionOutcome:
    """
    Execute real RSA-OAEP-3072 (SHA-256 / MGF1-SHA256) unwrapping against an attacked
    or unauthorized key-exchange operation.
    """
    try:
        recovered = unwrap_aes_key(wrapped_key_b64, private_key_pem=private_key_pem)
        return DetectionOutcome(
            detected=False,
            blocked=False,
            final_result='DEFENCE_FAILED',
            defence_mechanism='RSA-OAEP-3072 (SHA-256 + MGF1-SHA256) Private Key Isolation',
            mitigation_action='Session key unexpectedly unwrapped',
            rejection_reason='RSA-OAEP unwrapping succeeded unexpectedly.',
            evidence={
                'attack_label': attack_label,
                'unwrap_succeeded': True,
                'recovered_key_bits': len(recovered) * 8,
            },
        )
    except RSAEncryptionError as exc:
        return DetectionOutcome(
            detected=True,
            blocked=True,
            final_result='MITIGATED',
            defence_mechanism='RSA-OAEP-3072 (SHA-256 + MGF1-SHA256) Padding & Key Validation',
            mitigation_action='Rejected invalid RSA-OAEP key-unwrap operation; session key remained protected',
            rejection_reason=str(exc),
            evidence={
                'attack_label': attack_label,
                'unwrap_succeeded': False,
                'exception_type': 'RSAEncryptionError',
                'exception_detail': str(exc),
                'private_key_exposed': False,
            },
        )


def verify_rsa_pss_signature_defence(
    package: dict | bytes | str,
    signature_b64: str,
    trusted_public_key_pem: bytes | str,
    attack_label: str = 'RSA-PSS-3072 Signature Verification',
) -> DetectionOutcome:
    """
    Execute real RSA-PSS-3072 (SHA-256 / MGF1-SHA256) verification against the legitimate
    registered public key. Rejects forged, modified, substituted, or corrupted signatures.
    """
    is_valid = verify_transaction_signature(package, signature_b64, trusted_public_key_pem)
    if is_valid:
        return DetectionOutcome(
            detected=False,
            blocked=False,
            final_result='DEFENCE_FAILED',
            defence_mechanism='RSA-PSS-3072 (SHA-256) Non-Repudiation & Registered Public Key Pinning',
            mitigation_action='Attacked signature unexpectedly verified as valid',
            rejection_reason='RSA-PSS signature verification returned True.',
            evidence={
                'attack_label': attack_label,
                'signature_valid': True,
            },
        )

    return DetectionOutcome(
        detected=True,
        blocked=True,
        final_result='MITIGATED',
        defence_mechanism='RSA-PSS-3072 (SHA-256) Signature Verification & Registered Key Pinning',
        mitigation_action='Rejected transaction — RSA-PSS signature verification failed against registered public key',
        rejection_reason='Invalid RSA-PSS signature: digest mismatch, tampered package, or untrusted signing key.',
        evidence={
            'attack_label': attack_label,
            'signature_valid': False,
            'verification_result': 'INVALID_SIGNATURE_REJECTED',
        },
    )


def verify_hmac_defence(
    message: bytes | str | dict,
    hmac_hex: str,
    secret_key: bytes,
    attack_label: str = 'HMAC-SHA256 Verification',
) -> DetectionOutcome:
    """
    Run constant-time HMAC-SHA256 verification (`cryptography.hazmat.primitives.hmac.HMAC.verify`)
    against tampered messages or forged tags.
    """
    is_valid = verify_hmac_sha256(message, hmac_hex, secret_key=secret_key)
    if is_valid:
        return DetectionOutcome(
            detected=False,
            blocked=False,
            final_result='DEFENCE_FAILED',
            defence_mechanism='HMAC-SHA256 Constant-Time Message Authentication',
            mitigation_action='Tampered or forged message unexpectedly passed HMAC verification',
            rejection_reason='Constant-time HMAC verification returned True.',
            evidence={
                'attack_label': attack_label,
                'hmac_valid': True,
                'constant_time_comparison': True,
            },
        )

    return DetectionOutcome(
        detected=True,
        blocked=True,
        final_result='MITIGATED',
        defence_mechanism='HMAC-SHA256 Constant-Time Message Authentication (hmac.HMAC.verify)',
        mitigation_action='Rejected message immediately due to HMAC-SHA256 tag mismatch',
        rejection_reason='Constant-time HMAC-SHA256 verification failed: message modified or invalid authentication code.',
        evidence={
            'attack_label': attack_label,
            'hmac_valid': False,
            'constant_time_comparison': True,
            'verification_result': 'HMAC_MISMATCH_REJECTED',
        },
    )


def verify_pbkdf2_password_defence(
    stored_hash: str,
    candidate_guesses: list[str],
    enforce_policy: bool = True,
    target_candidate_for_policy: str | None = None,
) -> DetectionOutcome:
    """
    Evaluate real PBKDF2-HMAC-SHA256 verification against candidate guesses and password policy.
    Never logs or returns plaintext passwords.
    """
    policy_rejected = False
    policy_error = ''
    if enforce_policy and target_candidate_for_policy is not None:
        is_strong, policy_error = validate_password(target_candidate_for_policy)
        if not is_strong:
            policy_rejected = True
            return DetectionOutcome(
                detected=True,
                blocked=True,
                final_result='MITIGATED',
                defence_mechanism='Strong Password Complexity Policy + PBKDF2-HMAC-SHA256 (260,000 iterations)',
                mitigation_action=f'Rejected weak synthetic credential before hashing: {policy_error}',
                rejection_reason=policy_error,
                evidence={
                    'policy_enforced': True,
                    'policy_rejected': True,
                    'guesses_tested': 0,
                    'cracked': False,
                },
            )

    cracked = False
    guesses_tested = 0
    for guess in candidate_guesses:
        guesses_tested += 1
        if verify_password_pbkdf2(stored_hash, guess):
            cracked = True
            break

    if cracked:
        # Honest backend assessment: a weak password without policy enforcement WAS cracked!
        return DetectionOutcome(
            detected=True,
            blocked=False,
            final_result='DEFENCE_FAILED',
            defence_mechanism='PBKDF2-HMAC-SHA256 (Policy Enforcement Disabled for Weak-Credential Test)',
            mitigation_action='Weak synthetic credential matched dictionary probe — strong password policy required',
            rejection_reason=(
                'Weak synthetic password was recovered by dictionary/guessing probe because '
                'complexity policy enforcement was disabled in this test scenario.'
            ),
            evidence={
                'policy_enforced': enforce_policy,
                'policy_rejected': policy_rejected,
                'guesses_tested': guesses_tested,
                'cracked': True,
            },
        )

    return DetectionOutcome(
        detected=True,
        blocked=True,
        final_result='MITIGATED',
        defence_mechanism='PBKDF2-HMAC-SHA256 (Random 128-bit Salt + 260,000 Iterations) & Password Policy',
        mitigation_action=f'All {guesses_tested} guessing attempts rejected with computational KDF slowdown',
        rejection_reason='Zero candidate guesses matched the salted PBKDF2-HMAC-SHA256 hash.',
        evidence={
            'policy_enforced': enforce_policy,
            'policy_rejected': policy_rejected,
            'guesses_tested': guesses_tested,
            'cracked': False,
        },
    )


def consume_lab_nonce_atomically(
    nonce: str,
    transaction_id: str,
    admin_user_id: int | None,
    client_timestamp: str,
) -> tuple[bool, str]:
    """
    Atomically persist a lab replay nonce in `lab_consumed_nonces` using a savepoint
    and database UNIQUE constraints on both `nonce` and `transaction_id`.
    """
    if not nonce or not isinstance(nonce, str) or len(nonce.strip()) < 16:
        return False, "Invalid or too-short replay nonce."

    nonce_clean = nonce.strip()
    tx_clean = transaction_id.strip()

    try:
        with db.session.begin_nested():
            rec = LabConsumedNonce(
                nonce=nonce_clean,
                transaction_id=tx_clean,
                admin_user_id=admin_user_id,
                client_timestamp=str(client_timestamp),
            )
            db.session.add(rec)
            db.session.flush()
        db.session.commit()
        return True, "Nonce atomically consumed and registered in persistent server-side table."
    except IntegrityError:
        db.session.rollback()
        return False, "Replay attack detected: nonce or transaction ID has already been consumed in persistent registry."
    except Exception as exc:
        db.session.rollback()
        return False, f"Atomic nonce consumption failed: {exc}"


def verify_timestamp_and_binding_defence(
    package: dict,
    signature_b64: str,
    trusted_public_key_pem: bytes | str,
    tolerance_seconds: int = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    check_nonce_replay: bool = False,
    admin_user_id: int | None = None,
) -> DetectionOutcome:
    """
    Validate request timestamp against configured window AND verify cryptographic binding
    (RSA-PSS signature over canonical fields including timestamp). Optionally combines
    atomic nonce tracking to prevent replay within the allowed time window.
    """
    ts_str = str(package.get('timestamp', '')).strip()
    ts_valid, ts_err = validate_timestamp(ts_str, tolerance_seconds=tolerance_seconds)
    sig_valid = verify_transaction_signature(package, signature_b64, trusted_public_key_pem)

    if not ts_valid:
        return DetectionOutcome(
            detected=True,
            blocked=True,
            final_result='MITIGATED',
            defence_mechanism=f'UTC Timestamp Window Guard (±{tolerance_seconds}s) + RSA-PSS Cryptographic Binding',
            mitigation_action='Rejected out-of-window transaction before decryption or order execution',
            rejection_reason=ts_err,
            evidence={
                'timestamp_valid': False,
                'timestamp_error': ts_err,
                'signature_binding_valid': sig_valid,
                'tolerance_seconds': tolerance_seconds,
            },
        )

    if not sig_valid:
        return DetectionOutcome(
            detected=True,
            blocked=True,
            final_result='MITIGATED',
            defence_mechanism=f'Cryptographic Timestamp Binding (RSA-PSS + AES-GCM AAD) & ±{tolerance_seconds}s Window',
            mitigation_action='Rejected request — timestamp modification broke RSA-PSS signature & AAD binding',
            rejection_reason=(
                'Timestamp fell within window, but cryptographic signature binding verification FAILED '
                'because the timestamp was altered after signing.'
            ),
            evidence={
                'timestamp_valid': True,
                'timestamp_error': '',
                'signature_binding_valid': False,
                'tolerance_seconds': tolerance_seconds,
            },
        )

    if check_nonce_replay:
        nonce_ok, nonce_msg = consume_lab_nonce_atomically(
            nonce=str(package.get('nonce', '')),
            transaction_id=str(package.get('transaction_id', '')),
            admin_user_id=admin_user_id,
            client_timestamp=ts_str,
        )
        if not nonce_ok:
            return DetectionOutcome(
                detected=True,
                blocked=True,
                final_result='MITIGATED',
                defence_mechanism=f'Combined Timestamp Window (±{tolerance_seconds}s) + Atomic Persistent Nonce Guard',
                mitigation_action='Rejected replay within allowed timestamp window via consumed nonce registry',
                rejection_reason=nonce_msg,
                evidence={
                    'timestamp_valid': True,
                    'signature_binding_valid': True,
                    'nonce_accepted': False,
                    'nonce_error': nonce_msg,
                    'tolerance_seconds': tolerance_seconds,
                },
            )

    return DetectionOutcome(
        detected=False,
        blocked=False,
        final_result='DEFENCE_FAILED',
        defence_mechanism=f'UTC Timestamp Window Guard (±{tolerance_seconds}s) + Cryptographic Binding',
        mitigation_action='Request passed timestamp and signature validation without rejection',
        rejection_reason='Timestamp was within tolerance and cryptographic signature matched.',
        evidence={
            'timestamp_valid': True,
            'signature_binding_valid': True,
            'tolerance_seconds': tolerance_seconds,
        },
    )
