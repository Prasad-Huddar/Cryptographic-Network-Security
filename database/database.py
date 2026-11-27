"""
Database initialization, management, and non-destructive Phase 2 schema migration.
"""
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()


def ensure_phase2_schema():
    """
    Non-destructively add Phase 2 columns to existing SQLite tables if upgrading
    from a Phase 1 database without dropping existing data.
    """
    migrations = {
        'users': [
            ('public_key_pem', 'TEXT'),
        ],
        'transactions': [
            ('user_id', 'INTEGER'),
            ('encrypted_payload', 'TEXT'),
            ('wrapped_aes_key', 'TEXT'),
            ('gcm_nonce', 'VARCHAR(64)'),
            ('auth_tag', 'VARCHAR(64)'),
            ('digital_signature', 'TEXT'),
            ('client_timestamp', 'VARCHAR(64)'),
            ('replay_nonce', 'VARCHAR(128)'),
            ('verification_status', "VARCHAR(50) DEFAULT 'VERIFIED'"),
            ('encryption_algorithm', "VARCHAR(80) DEFAULT 'AES-256-GCM + RSA-OAEP-3072 + RSA-PSS-SHA256'"),
            ('integrity_hmac', 'VARCHAR(128)'),
        ],
        'security_logs': [
            ('integrity_hmac', 'VARCHAR(128)'),
        ],
    }

    for table_name, columns in migrations.items():
        try:
            existing = db.session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
            existing_names = {row[1] for row in existing}
            if not existing_names:
                continue
            for col_name, col_type in columns:
                if col_name not in existing_names:
                    db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"))
            db.session.commit()
        except Exception:
            db.session.rollback()


def init_db(app):
    """Initialize the database with the Flask app."""
    db.init_app(app)
    with app.app_context():
        from models.user import User
        from models.product import Product
        from models.order import Order, OrderItem
        from models.transaction import Transaction, ConsumedNonce, SecurityLog
        from models.security_lab import AttackSimulationEvent, LabConsumedNonce, LabSyntheticTransaction
        db.create_all()
        ensure_phase2_schema()
