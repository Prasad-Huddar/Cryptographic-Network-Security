"""
Order service for managing orders, cart operations, and hybrid cryptographic checkout.
"""
from database.database import db
from models.order import Order
from models.product import Product
from models.user import User
from services.crypto.transaction_security import (
    build_client_transaction_package,
    verify_and_process_transaction_package,
)


def get_cart(session):
    """Get the cart from the session."""
    return session.get('cart', {})


def add_to_cart(session, product_id, quantity=1):
    """Add a product to the cart."""
    product = db.session.get(Product, product_id)
    if not product or not product.is_active:
        return False, "Product not found."

    if not product.in_stock:
        return False, "Product is out of stock."

    cart = session.get('cart', {})
    str_id = str(product_id)

    if str_id in cart:
        new_qty = cart[str_id]['quantity'] + quantity
        if new_qty > product.stock:
            return False, f"Only {product.stock} items available in stock."
        cart[str_id]['quantity'] = new_qty
    else:
        if quantity > product.stock:
            return False, f"Only {product.stock} items available in stock."
        cart[str_id] = {
            'product_id': product.id,
            'name': product.name,
            'price': product.price,
            'quantity': quantity,
            'image_url': product.image_url
        }

    session['cart'] = cart
    session.modified = True
    return True, f"{product.name} added to cart."


def update_cart_quantity(session, product_id, quantity):
    """Update the quantity of a product in the cart."""
    cart = session.get('cart', {})
    str_id = str(product_id)

    if str_id not in cart:
        return False, "Product not in cart."

    if quantity <= 0:
        del cart[str_id]
        session['cart'] = cart
        session.modified = True
        return True, "Product removed from cart."

    product = db.session.get(Product, product_id)
    if product and quantity > product.stock:
        return False, f"Only {product.stock} items available in stock."

    cart[str_id]['quantity'] = quantity
    session['cart'] = cart
    session.modified = True
    return True, "Cart updated."


def remove_from_cart(session, product_id):
    """Remove a product from the cart."""
    cart = session.get('cart', {})
    str_id = str(product_id)

    if str_id in cart:
        del cart[str_id]
        session['cart'] = cart
        session.modified = True
        return True, "Product removed from cart."
    return False, "Product not in cart."


def get_cart_total(session):
    """Calculate the cart total."""
    cart = session.get('cart', {})
    total = sum(item['price'] * item['quantity'] for item in cart.values())
    return total


def get_cart_count(session):
    """Get the total number of items in the cart."""
    cart = session.get('cart', {})
    return sum(item['quantity'] for item in cart.values())


def create_order(user_id, session, shipping_address, encrypted_package=None):
    """
    Create an order from the cart using the Phase 2 Hybrid Cryptographic Transaction Workflow:
    - AES-256-GCM payload encryption with fresh 256-bit key and 96-bit nonce
    - RSA-OAEP (3072-bit, SHA-256) session key wrapping
    - RSA-PSS (3072-bit, SHA-256) digital signature verification
    - Replay protection (UUIDv4 transaction ID, UTC timestamp window, atomic nonce consumption)
    - Server-side price recomputation from trusted database product prices

    Returns (success, message, order).
    """
    cart = session.get('cart', {})
    if not cart and encrypted_package is None:
        return False, "Cart is empty.", None

    if encrypted_package is None:
        if not shipping_address or len(shipping_address.strip()) < 10:
            return False, "Please enter a valid shipping address (at least 10 characters).", None

        # Pre-check stock and availability before building encrypted package
        items_list = []
        for str_id, item in cart.items():
            product = db.session.get(Product, item['product_id'])
            if not product or not product.is_active:
                return False, f"Product '{item['name']}' is no longer available.", None
            if product.stock < item['quantity']:
                return False, f"Insufficient stock for '{product.name}'. Only {product.stock} available.", None
            items_list.append({
                'product_id': item['product_id'],
                'name': item['name'],
                'price': item['price'],
                'quantity': item['quantity'],
            })

        encrypted_package = build_client_transaction_package(
            user_id=user_id,
            items=items_list,
            shipping_address=shipping_address.strip(),
            payment_method='hybrid_crypto_payment',
        )

    user = db.session.get(User, user_id)
    if not user:
        return False, "Authenticated user not found.", None

    success, message, order, _tx = verify_and_process_transaction_package(
        package=encrypted_package,
        authenticated_user=user,
    )
    if success:
        session.pop('cart', None)
        session.modified = True

    return success, message, order
