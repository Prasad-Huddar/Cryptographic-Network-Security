"""
Configuration for the Secure E-Commerce Application (Phase 1 & Phase 2).
Includes separate configurations for Development (local CA TLS), Testing, and Production.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

    _db_url = os.environ.get('DATABASE_URL', 'sqlite:///ecommerce.db')
    if _db_url.startswith('sqlite:///instance/'):
        _db_url = 'sqlite:///' + _db_url[len('sqlite:///instance/'):]
    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'connect_args': {'timeout': 30}}

    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload

    # Phase 2 Cryptographic & Network Security Settings
    RSA_KEY_SIZE = 3072
    AES_KEY_SIZE_BYTES = 32
    GCM_NONCE_SIZE_BYTES = 12
    PBKDF2_ITERATIONS = int(os.environ.get('PBKDF2_ITERATIONS', 260000))
    REPLAY_TIMESTAMP_TOLERANCE_SECONDS = int(os.environ.get('REPLAY_TIMESTAMP_TOLERANCE_SECONDS', 300))

    # TLS / HTTPS Configuration (outside public static directories)
    TLS_MIN_VERSION = 'TLSv1.3'
    TLS_CERT_DIR = str(BASE_DIR / 'instance' / 'certs')
    TLS_CA_CERT_PATH = os.environ.get('TLS_CA_CERT_PATH', str(BASE_DIR / 'instance' / 'certs' / 'dev_root_ca.crt'))
    TLS_SERVER_CERT_PATH = os.environ.get('TLS_SERVER_CERT_PATH', str(BASE_DIR / 'instance' / 'certs' / 'localhost_server.crt'))
    TLS_SERVER_KEY_PATH = os.environ.get('TLS_SERVER_KEY_PATH', str(BASE_DIR / 'instance' / 'certs' / 'localhost_server.key'))
    HTTPS_PORT = int(os.environ.get('HTTPS_PORT', 5443))

    # Admin defaults
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@secureshop.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Admin@12345')
    ADMIN_NAME = os.environ.get('ADMIN_NAME', 'System Administrator')


class DevelopmentConfig(Config):
    """Development configuration using local Development Root CA certificate."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    USE_LOCAL_DEV_CERT = True


class ProductionConfig(Config):
    """
    Production configuration requiring publicly trusted CA certificates (e.g. Let's Encrypt / DigiCert),
    strict HTTPS-only cookies, and HSTS headers.
    """
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    USE_LOCAL_DEV_CERT = False
    PREFERRED_URL_SCHEME = 'https'
    HSTS_MAX_AGE = 31536000  # 1 year


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
