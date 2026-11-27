"""
Transaction, ConsumedNonce, and SecurityLog models for Phase 2 Hybrid Cryptography.
"""
from database.database import db
from datetime import datetime, timezone
import uuid
from services.crypto.integrity import verify_security_log_hmac, verify_transaction_hmac


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Transaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), nullable=False, default='completed')
    payment_method = db.Column(db.String(50), default='hybrid_crypto_payment')

    # Phase 2 Hybrid Cryptography fields (Base64 encoded binary values)
    encrypted_payload = db.Column(db.Text, nullable=True)
    wrapped_aes_key = db.Column(db.Text, nullable=True)
    gcm_nonce = db.Column(db.String(64), nullable=True)
    auth_tag = db.Column(db.String(64), nullable=True)
    digital_signature = db.Column(db.Text, nullable=True)
    client_timestamp = db.Column(db.String(64), nullable=True)
    replay_nonce = db.Column(db.String(128), unique=True, nullable=True, index=True)
    verification_status = db.Column(db.String(50), nullable=False, default='VERIFIED')
    encryption_algorithm = db.Column(
        db.String(80),
        nullable=False,
        default='AES-256-GCM + RSA-OAEP-3072 + RSA-PSS-SHA256'
    )
    integrity_hmac = db.Column(db.String(128), nullable=True)

    created_at = db.Column(db.DateTime, default=_utcnow)

    @property
    def formatted_amount(self):
        return f"₹{self.amount:,.2f}"

    @property
    def is_encrypted(self) -> bool:
        return bool(self.encrypted_payload and self.wrapped_aes_key and self.gcm_nonce and self.auth_tag)

    @property
    def is_signature_verified(self) -> bool:
        return self.verification_status == 'VERIFIED'

    def verify_integrity(self) -> bool:
        """Verify HMAC-SHA256 integrity of this stored transaction record."""
        return verify_transaction_hmac(self)

    def __repr__(self):
        return f'<Transaction {self.transaction_id}>'


class ConsumedNonce(db.Model):
    """
    Server-side atomic replay protection registry.
    Database uniqueness constraints on both nonce and transaction_id prevent concurrent replay races.
    """
    __tablename__ = 'consumed_nonces'

    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(128), unique=True, nullable=False, index=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    client_timestamp = db.Column(db.String(64), nullable=False)
    consumed_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    def __repr__(self):
        return f'<ConsumedNonce {self.nonce[:12]}...>'


class SecurityLog(db.Model):
    __tablename__ = 'security_logs'

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    integrity_hmac = db.Column(db.String(128), nullable=True)
    timestamp = db.Column(db.DateTime, default=_utcnow)

    user = db.relationship('User', backref='security_logs', lazy=True)

    @property
    def event_badge(self):
        badges = {
            'LOGIN_SUCCESS': 'success',
            'LOGIN_FAILED': 'danger',
            'LOGOUT': 'info',
            'REGISTER': 'primary',
            'PASSWORD_CHANGE': 'warning',
            'ADMIN_ACTION': 'dark',
            'ACCESS_DENIED': 'danger',
            'ORDER_PLACED': 'success',
            'ORDER_STATUS_CHANGED': 'info',
            'TRANSACTION_CREATED': 'primary',
            'ENCRYPTION_SUCCESS': 'success',
            'SIGNATURE_VERIFIED': 'success',
            'INVALID_SIGNATURE': 'danger',
            'REPLAY_ATTEMPT': 'danger',
            'TAMPERING_DETECTED': 'danger',
            'TLS_ERROR': 'danger',
            'SECURITY_LAB_TEST': 'primary',
            'DEFENCE_FAILED': 'danger',
        }
        return badges.get(self.event_type, 'secondary')

    def verify_integrity(self) -> bool:
        """Verify the HMAC-SHA256 integrity tag of this security log entry."""
        return verify_security_log_hmac(self)

    def __repr__(self):
        return f'<SecurityLog {self.event_type} at {self.timestamp}>'
