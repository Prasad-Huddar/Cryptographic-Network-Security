"""
Authentication service for user management and HMAC-protected security logging.
"""
import re
from datetime import datetime, timezone
from database.database import db
from models.user import User
from models.transaction import SecurityLog
from flask import has_request_context, request
from services.crypto.integrity import compute_security_log_hmac


def log_security_event(event_type, description, user_id=None):
    """Log a security event protected with HMAC-SHA256."""
    ts = datetime.now(timezone.utc).replace(tzinfo=None)
    ip_addr = request.remote_addr if has_request_context() else '127.0.0.1'
    hmac_tag = compute_security_log_hmac(
        event_type=event_type,
        description=description,
        user_id=user_id,
        ip_address=ip_addr,
        timestamp_iso=ts.isoformat()
    )
    log = SecurityLog(
        event_type=event_type,
        description=description,
        user_id=user_id,
        ip_address=ip_addr,
        timestamp=ts,
        integrity_hmac=hmac_tag
    )
    db.session.add(log)
    db.session.commit()
    return log


def validate_password(password):
    """
    Validate password strength.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def register_user(name, email, password):
    """
    Register a new user and provision their registered client RSA-3072 public key.
    Returns (success, message, user).
    """
    name = name.strip()
    email = email.strip().lower()

    if not name or len(name) < 2:
        return False, "Name must be at least 2 characters long.", None

    if not validate_email(email):
        return False, "Please enter a valid email address.", None

    if User.query.filter_by(email=email).first():
        return False, "An account with this email already exists.", None

    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return False, error_msg, None

    user = User(name=name, email=email, role='customer')
    user.set_password(password)
    user.ensure_client_public_key()
    db.session.add(user)
    db.session.commit()

    log_security_event('REGISTER', f'New user registered: {email}', user.id)
    return True, "Registration successful! Please login.", user


def authenticate_user(email, password):
    """
    Authenticate a user.
    Returns (success, message, user).
    """
    email = email.strip().lower()
    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        log_security_event('LOGIN_FAILED', f'Failed login attempt for: {email}')
        return False, "Invalid email or password.", None

    if not user.is_active_user:
        log_security_event('LOGIN_FAILED', f'Disabled account login attempt: {email}')
        return False, "This account has been disabled.", None

    if not user.public_key_pem:
        user.ensure_client_public_key()
        db.session.commit()

    log_security_event('LOGIN_SUCCESS', f'User logged in: {email}', user.id)
    return True, "Login successful!", user
