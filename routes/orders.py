"""
Order & Secure Transaction routes: checkout, order history, order details, transaction details, and crypto APIs.
"""
import json
from flask import Blueprint, jsonify, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
from database.database import db
from services.order_service import create_order, get_cart, get_cart_total
from services.crypto.rsa_key_management import get_server_public_key_pem, load_public_key, RSAKeyManagementError
from services.crypto.transaction_security import verify_and_process_transaction_package
from models.order import Order
from models.transaction import Transaction

orders_bp = Blueprint('orders', __name__)


@orders_bp.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    """Checkout page using Hybrid Cryptographic Transaction Workflow."""
    cart = get_cart(session)
    if not cart:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('products.product_list'))

    total = get_cart_total(session)

    if request.method == 'POST':
        shipping_address = request.form.get('shipping_address', '')
        raw_package = request.form.get('encrypted_package', '').strip()
        encrypted_package = None
        if raw_package:
            try:
                encrypted_package = json.loads(raw_package)
            except ValueError:
                flash('Malformed encrypted transaction package.', 'danger')
                return render_template('checkout.html', cart=cart, total=total, shipping_address=shipping_address)

        success, message, order = create_order(
            current_user.id,
            session,
            shipping_address,
            encrypted_package=encrypted_package
        )
        if success:
            flash(message, 'success')
            return redirect(url_for('orders.order_detail', order_id=order.id))
        else:
            flash(message, 'danger')
            return render_template('checkout.html', cart=cart, total=total, shipping_address=shipping_address)

    return render_template(
        'checkout.html',
        cart=cart,
        total=total,
        server_public_key_pem=get_server_public_key_pem(),
    )


@orders_bp.route('/api/crypto/public-key', methods=['GET'])
@login_required
def get_public_key():
    """Distribute ONLY the server's RSA-3072 public key to authenticated clients."""
    return jsonify({
        'algorithm': 'RSA-OAEP-3072-SHA256',
        'public_key_pem': get_server_public_key_pem(),
    })


@orders_bp.route('/api/crypto/register-key', methods=['POST'])
@login_required
def register_client_key():
    """Register an authenticated user's client RSA-3072 public key for RSA-PSS verification."""
    data = request.get_json(silent=True) or {}
    pub_pem = data.get('public_key_pem', '').strip()
    if not pub_pem:
        return jsonify({'success': False, 'error': 'Missing public_key_pem.'}), 400
    try:
        pub_key = load_public_key(pub_pem)
        if pub_key.key_size < 3072:
            return jsonify({'success': False, 'error': 'RSA public key must be at least 3072 bits.'}), 400
    except RSAKeyManagementError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    current_user.public_key_pem = pub_pem
    db.session.commit()
    return jsonify({'success': True, 'message': 'Client public key registered successfully.'})


@orders_bp.route('/api/transactions/secure-checkout', methods=['POST'])
@login_required
def api_secure_checkout():
    """
    Direct API endpoint for submitting an encrypted + RSA-PSS signed transaction package.
    Validates replay nonce, timestamp, transaction ID, RSA-PSS signature, RSA-OAEP wrapped key,
    AES-256-GCM payload, and recomputes prices from the database.
    """
    package = request.get_json(silent=True)
    if not package:
        return jsonify({'success': False, 'error': 'Missing JSON transaction package.'}), 400

    success, message, order, transaction = verify_and_process_transaction_package(
        package=package,
        authenticated_user=current_user,
    )
    if not success:
        return jsonify({'success': False, 'error': message}), 400

    session.pop('cart', None)
    session.modified = True
    return jsonify({
        'success': True,
        'message': message,
        'order_id': order.id,
        'order_number': order.order_number,
        'transaction_id': transaction.transaction_id,
        'verification_status': transaction.verification_status,
        'amount': transaction.amount,
    }), 201


@orders_bp.route('/orders')
@login_required
def order_history():
    """View order history."""
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=orders)


@orders_bp.route('/order/<int:order_id>')
@login_required
def order_detail(order_id):
    """View order details."""
    order = db.get_or_404(Order, order_id)
    if order.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('orders.order_history'))
    return render_template('order_detail.html', order=order)


@orders_bp.route('/transaction/<string:transaction_id>')
@login_required
def transaction_detail(transaction_id):
    """
    View cryptographic transaction verification details:
    - Transaction ID
    - Encryption status
    - Signature verification status
    - Timestamp & Replay Nonce
    - Transaction status & HMAC integrity status
    Never exposes private or secret keys.
    """
    transaction = Transaction.query.filter_by(transaction_id=transaction_id).first_or_404()
    order = db.session.get(Order, transaction.order_id)
    if transaction.user_id != current_user.id and (not order or order.user_id != current_user.id) and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('orders.order_history'))

    hmac_valid = transaction.verify_integrity()
    return render_template(
        'transaction_detail.html',
        transaction=transaction,
        order=order,
        hmac_valid=hmac_valid,
    )
