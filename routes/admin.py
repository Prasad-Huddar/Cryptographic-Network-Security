"""
Admin routes: dashboard, product management, order management, user management,
security logs, and Phase 2 interactive Cryptography & Security Demonstration Lab.
"""
import base64
import hashlib
import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import current_user
from functools import wraps
from database.database import db
from models.user import User
from models.product import Product
from models.order import Order
from models.transaction import ConsumedNonce, SecurityLog, Transaction
from services.auth_service import log_security_event
from services.crypto.aes_encryption import (
    AESEncryptionError,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_gcm_nonce,
)
from services.crypto.rsa_key_management import generate_rsa_keypair
from services.crypto.rsa_encryption import wrap_aes_key, unwrap_aes_key
from services.crypto.digital_signature import sign_transaction_package, verify_transaction_signature
from services.crypto.integrity import (
    compute_hmac_sha256,
    hash_password_pbkdf2,
    verify_hmac_sha256,
    verify_password_pbkdf2,
)
from services.crypto.transaction_security import (
    consume_nonce_atomically,
    create_tls_client_context,
    create_tls_server_context,
    ensure_local_tls_certificates,
    generate_replay_nonce,
    generate_timestamp,
    generate_transaction_id,
    perform_tls_handshake_and_exchange,
    validate_timestamp,
)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Cached ephemeral demo RSA-3072 keypair used exclusively for the educational lab
# (never uses or exposes the server's production private key or HMAC secret)
_demo_rsa_keys: tuple[bytes, bytes] | None = None
_demo_pbkdf2_cache: dict | None = None


def _get_demo_rsa_keys() -> tuple[bytes, bytes]:
    global _demo_rsa_keys
    if _demo_rsa_keys is None:
        _demo_rsa_keys = generate_rsa_keypair(3072)
    return _demo_rsa_keys


def _get_demo_pbkdf2(force_refresh: bool = False) -> dict:
    global _demo_pbkdf2_cache
    if _demo_pbkdf2_cache is None or force_refresh:
        demo_pw = "DemoPass@2026!"
        derived = hash_password_pbkdf2(demo_pw, iterations=260000)
        parts = derived.split('$')
        _demo_pbkdf2_cache = {
            'algorithm': 'PBKDF2-HMAC-SHA256',
            'iterations': 260000,
            'salt_hex': parts[1] if len(parts) == 3 else '',
            'hash_preview': (parts[2][:40] + '...') if len(parts) == 3 else derived[:40],
            'valid_password_verified': verify_password_pbkdf2(derived, demo_pw),
            'wrong_password_rejected': not verify_password_pbkdf2(derived, 'WrongPassword!'),
        }
    return _demo_pbkdf2_cache


def admin_required(f):
    """Decorator to restrict access to admin users only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please login first.', 'warning')
            return redirect(url_for('auth.login'))
        if not current_user.is_admin:
            log_security_event('ACCESS_DENIED', f'Non-admin user {current_user.email} tried to access {request.path}', current_user.id)
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def _compute_security_dashboard_metrics() -> dict:
    """Compute real-time cryptographic and security telemetry from SQLite."""
    successful_tx = Transaction.query.filter_by(status='completed').count()
    failed_tx_records = Transaction.query.filter(Transaction.status != 'completed').count()

    tampering_attempts = SecurityLog.query.filter_by(event_type='TAMPERING_DETECTED').count()
    replay_attempts = SecurityLog.query.filter_by(event_type='REPLAY_ATTEMPT').count()
    invalid_signatures = SecurityLog.query.filter_by(event_type='INVALID_SIGNATURE').count()
    unauthorized_attempts = SecurityLog.query.filter_by(event_type='ACCESS_DENIED').count()
    failed_logins = SecurityLog.query.filter_by(event_type='LOGIN_FAILED').count()
    verified_sig_logs = SecurityLog.query.filter_by(event_type='SIGNATURE_VERIFIED').count()

    verified_tx_count = Transaction.query.filter_by(verification_status='VERIFIED').count()
    rejected_tx_count = failed_tx_records + tampering_attempts + replay_attempts + invalid_signatures
    total_tx_attempts = successful_tx + rejected_tx_count
    consumed_nonces_count = ConsumedNonce.query.count()

    # Verify HMAC-SHA256 integrity across recent security logs
    recent_logs_sample = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(100).all()
    hmac_verified_count = sum(1 for l in recent_logs_sample if l.integrity_hmac and l.verify_integrity())
    hmac_tampered_count = sum(1 for l in recent_logs_sample if l.integrity_hmac and not l.verify_integrity())

    return {
        'total_transactions': total_tx_attempts,
        'recorded_transactions': Transaction.query.count(),
        'successful_transactions': successful_tx,
        'rejected_transactions': rejected_tx_count,
        'tampering_attempts': tampering_attempts,
        'replay_attempts': replay_attempts,
        'unauthorized_attempts': unauthorized_attempts,
        'failed_logins': failed_logins,
        'verified_signatures': max(verified_tx_count, verified_sig_logs),
        'invalid_signatures': invalid_signatures,
        'consumed_nonces': consumed_nonces_count,
        'hmac_verified_logs': hmac_verified_count,
        'hmac_tampered_logs': hmac_tampered_count,
    }


@admin_bp.route('/')
@admin_required
def dashboard():
    """Admin dashboard with store and real-time security stats."""
    total_users = User.query.count()
    total_products = Product.query.count()
    total_orders = Order.query.count()
    total_transactions = Transaction.query.count()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    recent_transactions = Transaction.query.order_by(Transaction.created_at.desc()).limit(8).all()
    recent_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(10).all()
    security_metrics = _compute_security_dashboard_metrics()

    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_products=total_products,
        total_orders=total_orders,
        total_transactions=total_transactions,
        recent_orders=recent_orders,
        recent_transactions=recent_transactions,
        recent_logs=recent_logs,
        security_metrics=security_metrics,
    )


@admin_bp.route('/security-dashboard')
@admin_required
def security_dashboard():
    """Dedicated Security Monitoring Dashboard with real database telemetry."""
    metrics = _compute_security_dashboard_metrics()
    recent_transactions = Transaction.query.order_by(Transaction.created_at.desc()).limit(15).all()
    security_incidents = SecurityLog.query.filter(
        SecurityLog.event_type.in_([
            'TAMPERING_DETECTED',
            'REPLAY_ATTEMPT',
            'INVALID_SIGNATURE',
            'ACCESS_DENIED',
            'LOGIN_FAILED',
            'TLS_ERROR',
        ])
    ).order_by(SecurityLog.timestamp.desc()).limit(25).all()
    recent_nonces = ConsumedNonce.query.order_by(ConsumedNonce.consumed_at.desc()).limit(15).all()

    return render_template(
        'admin_security_dashboard.html',
        metrics=metrics,
        recent_transactions=recent_transactions,
        security_incidents=security_incidents,
        recent_nonces=recent_nonces,
    )


@admin_bp.route('/products')
@admin_required
def manage_products():
    """View and manage products."""
    products = Product.query.order_by(Product.name).all()
    return render_template('admin_products.html', products=products)


@admin_bp.route('/products/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    """Add a new product."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', 0, type=float)
        category = request.form.get('category', '').strip()
        image_url = request.form.get('image_url', '').strip()
        stock = request.form.get('stock', 0, type=int)

        if not name or not description or price is None or price <= 0 or not category or stock is None or stock < 0:
            flash('Please fill in all required fields.', 'danger')
            return render_template('admin_product_form.html', action='Add')

        product = Product(
            name=name,
            description=description,
            price=price,
            category=category,
            image_url=image_url,
            stock=stock
        )
        db.session.add(product)
        db.session.commit()

        log_security_event('ADMIN_ACTION', f'Product added: {name}', current_user.id)
        flash(f'Product "{name}" added successfully!', 'success')
        return redirect(url_for('admin.manage_products'))

    return render_template('admin_product_form.html', action='Add')


@admin_bp.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    """Edit an existing product."""
    product = db.get_or_404(Product, product_id)

    if request.method == 'POST':
        product.name = request.form.get('name', '').strip()
        product.description = request.form.get('description', '').strip()
        product.price = request.form.get('price', 0, type=float)
        product.category = request.form.get('category', '').strip()
        product.image_url = request.form.get('image_url', '').strip()
        product.stock = request.form.get('stock', 0, type=int)
        product.is_active = 'is_active' in request.form

        if (
            not product.name
            or not product.description
            or product.price is None
            or product.price <= 0
            or not product.category
            or product.stock is None
            or product.stock < 0
        ):
            flash('Please fill in all required fields.', 'danger')
            return render_template('admin_product_form.html', action='Edit', product=product)

        db.session.commit()
        log_security_event('ADMIN_ACTION', f'Product updated: {product.name}', current_user.id)
        flash(f'Product "{product.name}" updated successfully!', 'success')
        return redirect(url_for('admin.manage_products'))

    return render_template('admin_product_form.html', action='Edit', product=product)


@admin_bp.route('/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    """Delete a product."""
    product = db.get_or_404(Product, product_id)
    product_name = product.name
    product.is_active = False
    db.session.commit()

    log_security_event('ADMIN_ACTION', f'Product deactivated: {product_name}', current_user.id)
    flash(f'Product "{product_name}" has been deactivated.', 'success')
    return redirect(url_for('admin.manage_products'))


@admin_bp.route('/orders')
@admin_required
def manage_orders():
    """View all orders."""
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin_orders.html', orders=orders)


@admin_bp.route('/orders/<int:order_id>/status', methods=['POST'])
@admin_required
def update_order_status(order_id):
    """Update order status."""
    order = db.get_or_404(Order, order_id)
    new_status = request.form.get('status', '')

    valid_statuses = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled']
    if new_status not in valid_statuses:
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin.manage_orders'))

    old_status = order.status
    order.status = new_status
    db.session.commit()

    log_security_event(
        'ORDER_STATUS_CHANGED',
        f'Order {order.order_number} status changed: {old_status} → {new_status}',
        current_user.id
    )
    flash(f'Order {order.order_number} status updated to {new_status}.', 'success')
    return redirect(url_for('admin.manage_orders'))


@admin_bp.route('/users')
@admin_required
def manage_users():
    """View all users."""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@admin_bp.route('/users/<int:user_id>/role', methods=['POST'])
@admin_required
def update_user_role(user_id):
    """Update a user's role."""
    user = db.get_or_404(User, user_id)
    new_role = request.form.get('role', '')

    if new_role not in ['customer', 'admin']:
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin.manage_users'))

    if user.id == current_user.id:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('admin.manage_users'))

    old_role = user.role
    user.role = new_role
    db.session.commit()

    log_security_event(
        'ADMIN_ACTION',
        f'User {user.email} role changed: {old_role} → {new_role}',
        current_user.id
    )
    flash(f'User {user.email} role updated to {new_role}.', 'success')
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/security-logs')
@admin_required
def security_logs():
    """View security logs with HMAC-SHA256 integrity status."""
    page = request.args.get('page', 1, type=int)
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)
    return render_template('admin_security_logs.html', logs=logs)


@admin_bp.route('/crypto-demo', methods=['GET', 'POST'])
@admin_required
def crypto_demo():
    """
    Admin-only Interactive Security & Hybrid Cryptography Demonstration Lab.
    Demonstrates:
    1. AES-256-GCM encryption & decryption
    2. RSA-OAEP (3072-bit, SHA-256) key wrapping & unwrapping
    3. RSA-PSS (3072-bit, SHA-256) digital signature generation & verification
    4. HMAC-SHA256 generation & verification
    5. Ciphertext & signature tampering detection
    6. Replay attack rejection (duplicate nonce & expired timestamp)
    Uses isolated ephemeral keys and never exposes production secret keys.
    """
    sample_payload = request.form.get(
        'sample_payload',
        json.dumps({
            'order_item': 'Wireless Bluetooth Headphones',
            'quantity': 1,
            'price_inr': 2999.00,
            'customer': 'demo_customer@secureshop.com',
        })
    ).strip()

    demo_priv_pem, demo_pub_pem = _get_demo_rsa_keys()

    # 1. AES-256-GCM Demo
    ephemeral_aes_key = generate_aes_key()
    ephemeral_nonce = generate_gcm_nonce(ephemeral_aes_key)
    aes_key_fingerprint = hashlib.sha256(ephemeral_aes_key).hexdigest()[:24]
    aes_enc = encrypt_aes_gcm(sample_payload, key=ephemeral_aes_key, nonce=ephemeral_nonce)
    decrypted_text = decrypt_aes_gcm(
        ciphertext=aes_enc['ciphertext_b64'],
        key=ephemeral_aes_key,
        nonce=aes_enc['nonce_b64'],
        auth_tag=aes_enc['auth_tag_b64'],
    ).decode('utf-8')

    # 2. RSA-OAEP Key Wrapping Demo
    wrapped_res = wrap_aes_key(ephemeral_aes_key, public_key_pem=demo_pub_pem)
    unwrapped_key = unwrap_aes_key(wrapped_res['wrapped_key_b64'], private_key_pem=demo_priv_pem)
    unwrapped_fingerprint = hashlib.sha256(unwrapped_key).hexdigest()[:24]

    # 3. RSA-PSS Digital Signature Demo
    tx_id = generate_transaction_id()
    ts_now = generate_timestamp()
    replay_nonce = generate_replay_nonce()
    demo_package = {
        'transaction_id': tx_id,
        'user_id': current_user.id,
        'timestamp': ts_now,
        'nonce': replay_nonce,
        'ciphertext_b64': aes_enc['ciphertext_b64'],
        'gcm_nonce_b64': aes_enc['nonce_b64'],
        'auth_tag_b64': aes_enc['auth_tag_b64'],
        'wrapped_key_b64': wrapped_res['wrapped_key_b64'],
    }
    sig_res = sign_transaction_package(demo_package, demo_priv_pem)
    sig_verified = verify_transaction_signature(demo_package, sig_res['signature_b64'], demo_pub_pem)

    # 4. HMAC-SHA256 Demo (using ephemeral demo secret)
    ephemeral_hmac_key = b'ephemeral-demo-hmac-key-not-production-secret'
    demo_log_entry = f"ORDER_PLACED|tx={tx_id}|amount=2999.00|ts={ts_now}"
    hmac_digest = compute_hmac_sha256(demo_log_entry, secret_key=ephemeral_hmac_key)
    hmac_valid = verify_hmac_sha256(demo_log_entry, hmac_digest, secret_key=ephemeral_hmac_key)
    hmac_tampered_valid = verify_hmac_sha256(
        demo_log_entry.replace('2999.00', '1.00'),
        hmac_digest,
        secret_key=ephemeral_hmac_key,
    )

    # 5. Tampering Detection Demo (AES-GCM & RSA-PSS)
    raw_ct = bytearray(aes_enc['ciphertext'])
    raw_ct[0] ^= 0xFF
    tampered_ct_b64 = base64.b64encode(bytes(raw_ct)).decode('ascii')
    tamper_detected = False
    try:
        decrypt_aes_gcm(
            ciphertext=tampered_ct_b64,
            key=ephemeral_aes_key,
            nonce=aes_enc['nonce_b64'],
            auth_tag=aes_enc['auth_tag_b64'],
        )
        aes_tamper_result = "UNEXPECTED: Decryption succeeded"
    except AESEncryptionError as exc:
        tamper_detected = True
        aes_tamper_result = f"REJECTED — {exc}"

    tampered_package = dict(demo_package)
    tampered_package['ciphertext_b64'] = tampered_ct_b64
    pss_tamper_valid = verify_transaction_signature(tampered_package, sig_res['signature_b64'], demo_pub_pem)

    # 6. Replay Protection Demo (Real Database Atomic Nonce Consumption & Expired Timestamp Validation)
    first_nonce_ok, _ = consume_nonce_atomically(
        nonce=replay_nonce,
        transaction_id=tx_id,
        user_id=current_user.id,
        client_timestamp=ts_now,
    )
    second_nonce_ok, duplicate_nonce_err = consume_nonce_atomically(
        nonce=replay_nonce,
        transaction_id=generate_transaction_id(),
        user_id=current_user.id,
        client_timestamp=ts_now,
    )
    duplicate_nonce_rejected = first_nonce_ok and (not second_nonce_ok)
    expired_ts = "2020-01-01T00:00:00+00:00"
    ts_ok, ts_err_msg = validate_timestamp(expired_ts, tolerance_seconds=300)

    active_action = request.form.get('demo_action', 'all')
    if request.method == 'POST':
        flash(f'Executed live cryptography demonstration: {active_action.upper()}', 'info')

    # 7. PBKDF2-HMAC-SHA256 & TLS 1.3 Live Handshake Verification
    pbkdf2_info = _get_demo_pbkdf2(force_refresh=(active_action == 'pbkdf2'))
    ensure_local_tls_certificates()
    tls_srv_ctx = create_tls_server_context(require_tls13=True)
    tls_cli_ctx = create_tls_client_context(require_tls13=True)
    tls_res = perform_tls_handshake_and_exchange(
        server_ctx=tls_srv_ctx,
        client_ctx=tls_cli_ctx,
        message=b"ADMIN_LAB_TLS13_CHECK",
        server_hostname="localhost",
    )

    demo_results = {
        'active_action': active_action,
        'sample_payload': sample_payload,
        'aes': {
            'algorithm': 'AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag)',
            'key_fingerprint_sha256': f"{aes_key_fingerprint}... (secret key hidden)",
            'nonce_b64': aes_enc['nonce_b64'],
            'ciphertext_b64': aes_enc['ciphertext_b64'],
            'auth_tag_b64': aes_enc['auth_tag_b64'],
            'decrypted_payload': decrypted_text,
            'verified': decrypted_text == sample_payload,
        },
        'rsa_oaep': {
            'algorithm': 'RSA-OAEP-3072 (SHA-256, MGF1-SHA256)',
            'wrapped_key_b64_preview': wrapped_res['wrapped_key_b64'][:80] + '...',
            'wrapped_key_bytes': len(wrapped_res['wrapped_key']),
            'original_fingerprint': aes_key_fingerprint,
            'unwrapped_fingerprint': unwrapped_fingerprint,
            'match': (unwrapped_key == ephemeral_aes_key) and (aes_key_fingerprint == unwrapped_fingerprint),
        },
        'rsa_pss': {
            'algorithm': 'RSA-PSS-3072 (SHA-256, MGF1-SHA256)',
            'transaction_id': tx_id,
            'signature_b64_preview': sig_res['signature_b64'][:80] + '...',
            'signature_bytes': len(sig_res['signature']),
            'verified': sig_verified,
        },
        'pbkdf2': pbkdf2_info,
        'hmac': {
            'algorithm': 'HMAC-SHA256',
            'log_entry': demo_log_entry,
            'hmac_hex': hmac_digest,
            'valid_verification': hmac_valid,
            'tampered_verification': hmac_tampered_valid,
        },
        'tampering': {
            'tampered_ciphertext_b64': tampered_ct_b64,
            'aes_gcm_result': aes_tamper_result,
            'tamper_detected': tamper_detected,
            'rsa_pss_tampered_verified': pss_tamper_valid,
        },
        'replay': {
            'original_nonce': replay_nonce,
            'first_nonce_accepted': first_nonce_ok,
            'duplicate_nonce_rejected': duplicate_nonce_rejected,
            'duplicate_nonce_error': duplicate_nonce_err,
            'expired_timestamp': expired_ts,
            'expired_timestamp_valid': ts_ok,
            'expired_timestamp_error': ts_err_msg,
        },
        'tls13': {
            'protocol_version': tls_res['protocol_version'],
            'cipher_suite': tls_res['cipher'][0] if tls_res.get('cipher') else 'TLS_AES_256_GCM_SHA384',
            'cipher_bits': tls_res['cipher'][2] if tls_res.get('cipher') else 256,
            'server_hostname': 'localhost (SAN: DNS:localhost, IP:127.0.0.1)',
            'ca_issuer': 'SecureShop Local Dev Root CA',
            'verified': tls_res['protocol_version'] == 'TLSv1.3',
        },
    }

    return render_template('admin_crypto_demo.html', demo=demo_results)
