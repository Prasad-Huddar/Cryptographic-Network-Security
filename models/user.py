"""
User model with secure password hashing using PBKDF2-HMAC-SHA256
and registered RSA-3072 public key for digital signature verification.
"""
from database.database import db
from flask_login import UserMixin
from datetime import datetime, timezone
from services.crypto.integrity import hash_password_pbkdf2, verify_password_pbkdf2


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='customer')
    public_key_pem = db.Column(db.Text, nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)
    is_active_user = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    orders = db.relationship('Order', backref='user', lazy=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

    def set_password(self, password, iterations: int = 260000):
        """Hash password using PBKDF2-HMAC-SHA256 with a random 128-bit salt."""
        self.password_hash = hash_password_pbkdf2(password, iterations=iterations)

    def check_password(self, password):
        """Verify password against stored PBKDF2-HMAC-SHA256 hash."""
        return verify_password_pbkdf2(self.password_hash, password)

    def ensure_client_public_key(self) -> str:
        """
        Ensure this user has a registered RSA-3072 public key for RSA-PSS verification.
        If not yet registered, provisions a client keypair and stores the public key PEM.
        """
        if not self.public_key_pem:
            from services.crypto.rsa_key_management import provision_client_keypair
            _, pub_pem = provision_client_keypair(self.email or self.id)
            self.public_key_pem = pub_pem.decode('utf-8')
        return self.public_key_pem

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_customer(self):
        return self.role == 'customer'

    def __repr__(self):
        return f'<User {self.email}>'
