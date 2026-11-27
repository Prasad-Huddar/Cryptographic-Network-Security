"""
Cart routes: add, update, remove, view cart.
"""
from urllib.parse import urlsplit
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_required
from services.order_service import add_to_cart, update_cart_quantity, remove_from_cart, get_cart, get_cart_total, get_cart_count

cart_bp = Blueprint('cart', __name__)


def _safe_next_url(target: str | None, fallback: str) -> str:
    if not target:
        return fallback
    parsed = urlsplit(target)
    if not parsed.scheme and not parsed.netloc and target.startswith('/') and not target.startswith('//'):
        return target
    if parsed.netloc == request.host and parsed.path.startswith('/'):
        return parsed.path + (f'?{parsed.query}' if parsed.query else '')
    return fallback


@cart_bp.route('/cart')
@login_required
def view_cart():
    """View the shopping cart."""
    cart = get_cart(session)
    total = get_cart_total(session)
    return render_template('cart.html', cart=cart, total=total)


@cart_bp.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_item(product_id):
    """Add a product to the cart."""
    quantity = request.form.get('quantity', 1, type=int)
    if quantity is None or quantity < 1:
        quantity = 1

    success, message = add_to_cart(session, product_id, quantity)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')

    next_url = _safe_next_url(request.form.get('next'), url_for('products.product_list'))
    return redirect(next_url)


@cart_bp.route('/cart/update/<int:product_id>', methods=['POST'])
@login_required
def update_item(product_id):
    """Update quantity of a cart item."""
    quantity = request.form.get('quantity', 1, type=int)
    if quantity is None:
        flash('Invalid quantity.', 'danger')
        return redirect(url_for('cart.view_cart'))

    success, message = update_cart_quantity(session, product_id, quantity)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(url_for('cart.view_cart'))


@cart_bp.route('/cart/remove/<int:product_id>', methods=['POST'])
@login_required
def remove_item(product_id):
    """Remove a product from the cart."""
    success, message = remove_from_cart(session, product_id)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(url_for('cart.view_cart'))


@cart_bp.route('/cart/count')
def cart_count():
    """Get cart item count (for AJAX)."""
    count = get_cart_count(session)
    return jsonify({'count': count})
