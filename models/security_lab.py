"""
Persistent SQLAlchemy models for the Admin Cybersecurity Attack Simulation & Defence Centre.

All attack simulation data, synthetic transactions, and lab replay nonces are stored in
dedicated isolated tables so legitimate e-commerce orders, customer accounts, and real
transactions are never modified or polluted.
"""
import json
import uuid
from datetime import datetime, timezone

from database.database import db
from services.crypto.integrity import compute_hmac_sha256, verify_hmac_sha256
from services.timezone_utils import format_ist, format_utc_iso


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AttackSimulationEvent(db.Model):
    """
    Persistent audit record of every executed attack simulation in the Admin Security Lab.
    Protected with an HMAC-SHA256 integrity tag and cross-linked to SecurityLog.
    """
    __tablename__ = 'attack_simulation_events'

    id = db.Column(db.Integer, primary_key=True)
    event_uid = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )
    admin_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    module_key = db.Column(db.String(50), nullable=False, index=True)
    module_name = db.Column(db.String(120), nullable=False)
    attack_key = db.Column(db.String(80), nullable=False, index=True)
    attack_type = db.Column(db.String(120), nullable=False)
    attack_category = db.Column(db.String(80), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)

    # Sanitized JSON strings — never store private keys or plaintext passwords
    payload_summary = db.Column(db.Text, nullable=True)
    detection_evidence = db.Column(db.Text, nullable=True)
    execution_logs = db.Column(db.Text, nullable=True)

    defence_mechanism = db.Column(db.String(220), nullable=False)
    detected = db.Column(db.Boolean, nullable=False, default=False)
    blocked = db.Column(db.Boolean, nullable=False, default=False)
    mitigation_action = db.Column(db.String(255), nullable=False)
    final_result = db.Column(db.String(40), nullable=False, index=True)  # MITIGATED | DEFENCE_FAILED | DETECTED_ONLY
    execution_ms = db.Column(db.Float, nullable=False, default=0.0)

    security_log_id = db.Column(db.Integer, db.ForeignKey('security_logs.id'), nullable=True)
    integrity_hmac = db.Column(db.String(128), nullable=True)
    executed_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)

    admin_user = db.relationship('User', foreign_keys=[admin_user_id], lazy=True)

    def _hmac_payload(self) -> dict:
        ts_iso = self.executed_at.isoformat() if self.executed_at else ''
        return {
            'event_uid': str(self.event_uid or ''),
            'admin_user_id': self.admin_user_id,
            'module_key': str(self.module_key or ''),
            'attack_key': str(self.attack_key or ''),
            'detected': bool(self.detected),
            'blocked': bool(self.blocked),
            'final_result': str(self.final_result or ''),
            'mitigation_action': str(self.mitigation_action or ''),
            'executed_at': ts_iso,
        }

    def sign_integrity(self) -> str:
        """Compute and assign HMAC-SHA256 integrity tag over this event record."""
        if not self.event_uid:
            self.event_uid = str(uuid.uuid4())
        if not self.executed_at:
            self.executed_at = _utcnow()
        self.integrity_hmac = compute_hmac_sha256(self._hmac_payload())
        return self.integrity_hmac

    def verify_integrity(self) -> bool:
        """Verify the stored HMAC-SHA256 integrity tag in constant time."""
        if not self.integrity_hmac:
            return False
        return verify_hmac_sha256(self._hmac_payload(), self.integrity_hmac)

    @staticmethod
    def _safe_json_load(raw: str | None, default):
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default

    def to_dict(self, include_details: bool = False) -> dict:
        """Serialize event safely for Admin SOC API responses."""
        data = {
            'id': self.id,
            'event_id': f"EVT-{self.event_uid[:8].upper()}",
            'event_uid': self.event_uid,
            'module_key': self.module_key,
            'module_name': self.module_name,
            'attack_key': self.attack_key,
            'attack_type': self.attack_type,
            'attack_category': self.attack_category,
            'description': self.description,
            'defence_mechanism': self.defence_mechanism,
            'detected': bool(self.detected),
            'blocked': bool(self.blocked),
            'mitigation_action': self.mitigation_action,
            'final_result': self.final_result,
            'execution_ms': round(float(self.execution_ms or 0.0), 2),
            'security_log_id': self.security_log_id,
            'hmac_valid': self.verify_integrity(),
            'executed_at': format_ist(self.executed_at) if self.executed_at else '',
            'executed_at_utc': format_utc_iso(self.executed_at) if self.executed_at else '',
            'executed_at_iso': format_utc_iso(self.executed_at) if self.executed_at else '',
        }
        if include_details:
            data['payload'] = self._safe_json_load(self.payload_summary, {})
            data['evidence'] = self._safe_json_load(self.detection_evidence, {})
            data['logs'] = self._safe_json_load(self.execution_logs, [])
        return data

    def __repr__(self):
        return f'<AttackSimulationEvent {self.module_key}:{self.attack_key} [{self.final_result}]>'


class LabConsumedNonce(db.Model):
    """
    Isolated persistent atomic nonce registry for Security Lab replay simulations
    (Modules 7 & 8). Enforces database-level UNIQUE constraints on both nonce and
    transaction_id so concurrent replay attempts are atomically rejected by SQLite.
    """
    __tablename__ = 'lab_consumed_nonces'

    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(128), unique=True, nullable=False, index=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    client_timestamp = db.Column(db.String(64), nullable=False)
    consumed_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    def __repr__(self):
        return f'<LabConsumedNonce {self.nonce[:12]}...>'


class LabSyntheticTransaction(db.Model):
    """
    Isolated synthetic encrypted transaction persisted exclusively for stateful Admin
    Security Lab workflows (Module 6 Ciphertext Tampering & Module 7 Nonce Replay).
    Never interacts with real e-commerce Order or Transaction tables.
    """
    __tablename__ = 'lab_synthetic_transactions'

    id = db.Column(db.Integer, primary_key=True)
    lab_tx_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )
    module_key = db.Column(db.String(50), nullable=False, index=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    payload_preview = db.Column(db.Text, nullable=False)
    ciphertext_b64 = db.Column(db.Text, nullable=False)
    gcm_nonce_b64 = db.Column(db.String(64), nullable=False)
    auth_tag_b64 = db.Column(db.String(64), nullable=False)
    wrapped_key_b64 = db.Column(db.Text, nullable=False)
    aad_str = db.Column(db.String(256), nullable=False)
    signature_b64 = db.Column(db.Text, nullable=True)
    replay_nonce = db.Column(db.String(128), nullable=True, index=True)
    client_timestamp = db.Column(db.String(64), nullable=True)

    original_ciphertext_sha256 = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(40), nullable=False, default='GENERATED')
    integrity_hmac = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    def _hmac_payload(self) -> dict:
        return {
            'lab_tx_id': self.lab_tx_id,
            'module_key': self.module_key,
            'ciphertext_b64': self.ciphertext_b64,
            'gcm_nonce_b64': self.gcm_nonce_b64,
            'auth_tag_b64': self.auth_tag_b64,
            'wrapped_key_b64': self.wrapped_key_b64,
            'original_ciphertext_sha256': self.original_ciphertext_sha256,
        }

    def sign_integrity(self) -> str:
        if not self.lab_tx_id:
            self.lab_tx_id = str(uuid.uuid4())
        self.integrity_hmac = compute_hmac_sha256(self._hmac_payload())
        return self.integrity_hmac

    def verify_integrity(self) -> bool:
        if not self.integrity_hmac:
            return False
        return verify_hmac_sha256(self._hmac_payload(), self.integrity_hmac)

    def __repr__(self):
        return f'<LabSyntheticTransaction {self.lab_tx_id[:8]} ({self.module_key})>'
