"""
Secure E-Commerce Transaction System (Phase 1 & Phase 2 Hybrid Cryptography + TLS 1.3)
Main Application Entry Point
"""
import os
import sys
import threading
from flask import Flask, render_template, request, session
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

from config import config
from database.database import db, ensure_phase2_schema
from models.user import User

load_dotenv()


def create_app(config_name=None):
    """Application factory."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config.get(config_name, config['default']))

    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    csrf = CSRFProtect(app)

    # Login manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please login to access this page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register blueprints
    from routes.auth import auth_bp
    from routes.products import products_bp
    from routes.cart import cart_bp
    from routes.orders import orders_bp
    from routes.admin import admin_bp
    from routes.security_lab import security_lab_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(cart_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(security_lab_bp)

    # Context processor for cart count
    @app.context_processor
    def inject_cart_count():
        cart = session.get('cart', {})
        cart_count = sum(item['quantity'] for item in cart.values())
        return dict(cart_count=cart_count)

    # Jinja2 timezone display filters (UTC storage -> Asia/Kolkata IST presentation)
    from services.timezone_utils import format_ist, format_utc_iso
    app.jinja_env.filters['format_ist'] = format_ist
    app.jinja_env.filters['format_utc_iso'] = format_utc_iso

    # Security headers middleware
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        if request.is_secure or app.config.get('PREFERRED_URL_SCHEME') == 'https':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    # Error handlers
    @app.route('/favicon.ico')
    def favicon():
        return '', 204

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('access_denied.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('500.html'), 500

    # Create tables, upgrade Phase 2 schema, and seed data
    with app.app_context():
        from models.product import Product
        from models.order import Order, OrderItem
        from models.transaction import Transaction, ConsumedNonce, SecurityLog
        from models.security_lab import AttackSimulationEvent, LabConsumedNonce, LabSyntheticTransaction
        db.create_all()
        ensure_phase2_schema()
        if not app.config.get('TESTING'):
            seed_data(app)

    return app


def seed_data(app):
    """Seed the database with initial data."""
    from models.product import Product

    # Create admin user if not exists
    admin_email = app.config['ADMIN_EMAIL']
    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin = User(
            name=app.config['ADMIN_NAME'],
            email=admin_email,
            role='admin',
            must_change_password=True
        )
        admin.set_password(app.config['ADMIN_PASSWORD'])
        admin.ensure_client_public_key()
        db.session.add(admin)
        db.session.commit()
        print(f"[SEED] Admin user created: {admin_email}")
    elif not existing_admin.public_key_pem:
        existing_admin.ensure_client_public_key()
        db.session.commit()

    # Seed products if none exist
    if Product.query.count() == 0:
        products = [
            Product(
                name="Wireless Bluetooth Headphones",
                description="Premium noise-cancelling wireless headphones with 30-hour battery life. Features active noise cancellation, comfortable over-ear design, and Hi-Res Audio support. Perfect for music lovers and professionals.",
                price=2999.00,
                category="Electronics",
                image_url="https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400",
                stock=50
            ),
            Product(
                name="Smart Watch Pro",
                description="Advanced fitness tracking smartwatch with heart rate monitoring, GPS, sleep tracking, and 7-day battery life. Water-resistant up to 50m. Compatible with Android and iOS.",
                price=4999.00,
                category="Electronics",
                image_url="https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=400",
                stock=30
            ),
            Product(
                name="USB-C Fast Charger",
                description="65W GaN fast charger with USB-C PD 3.0 support. Compact design suitable for laptops, tablets, and smartphones. Multi-device charging capability.",
                price=1499.00,
                category="Electronics",
                image_url="https://images.unsplash.com/photo-1583863788434-e58a36330cf0?w=400",
                stock=100
            ),
            Product(
                name="Mechanical Keyboard RGB",
                description="Full-size mechanical gaming keyboard with RGB backlighting, Cherry MX switches, and programmable macro keys. Aircraft-grade aluminium frame.",
                price=3499.00,
                category="Electronics",
                image_url="https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=400",
                stock=40
            ),
            Product(
                name="Cotton Casual T-Shirt",
                description="Premium 100% organic cotton t-shirt. Comfortable regular fit with reinforced seams. Available in multiple colours. Machine washable.",
                price=699.00,
                category="Clothing",
                image_url="https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400",
                stock=200
            ),
            Product(
                name="Denim Jacket Classic",
                description="Classic fit denim jacket made from premium washed denim. Features button closure, chest pockets, and adjustable waist tabs. Timeless style for all seasons.",
                price=2499.00,
                category="Clothing",
                image_url="https://images.unsplash.com/photo-1551028719-00167b16eac5?w=400",
                stock=60
            ),
            Product(
                name="Running Shoes Ultralight",
                description="Lightweight running shoes with responsive cushioning and breathable mesh upper. Engineered for comfort during long runs. Anti-slip rubber outsole.",
                price=3999.00,
                category="Footwear",
                image_url="https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=400",
                stock=80
            ),
            Product(
                name="Leather Wallet Premium",
                description="Handcrafted genuine leather bi-fold wallet with RFID blocking technology. Features 8 card slots, 2 note compartments, and a coin pocket.",
                price=1299.00,
                category="Accessories",
                image_url="https://images.unsplash.com/photo-1627123424574-724758594e93?w=400",
                stock=120
            ),
            Product(
                name="Stainless Steel Water Bottle",
                description="Double-wall vacuum insulated water bottle. Keeps drinks cold for 24 hours or hot for 12 hours. BPA-free, leak-proof lid. 750ml capacity.",
                price=899.00,
                category="Accessories",
                image_url="https://images.unsplash.com/photo-1602143407151-7111542de6e8?w=400",
                stock=150
            ),
            Product(
                name="Backpack Laptop Bag",
                description="Professional laptop backpack with padded 15.6-inch laptop compartment. Water-resistant fabric, USB charging port, and anti-theft design. Multiple organizer pockets.",
                price=1899.00,
                category="Accessories",
                image_url="https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=400",
                stock=70
            ),
            Product(
                name="Wireless Mouse Ergonomic",
                description="Ergonomic vertical wireless mouse designed to reduce wrist strain. 2.4GHz wireless connectivity, adjustable DPI, and silent click buttons. USB-C rechargeable.",
                price=999.00,
                category="Electronics",
                image_url="https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=400",
                stock=90
            ),
            Product(
                name="Sunglasses Polarized UV400",
                description="Premium polarized sunglasses with UV400 protection. Lightweight metal frame with spring hinges. Includes protective case and cleaning cloth.",
                price=1599.00,
                category="Accessories",
                image_url="https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=400",
                stock=110
            ),
            Product(
                name="Yoga Mat Premium",
                description="Extra thick 6mm yoga mat with non-slip texture on both sides. Eco-friendly TPE material. Includes carrying strap. Perfect for yoga, pilates, and floor exercises.",
                price=1199.00,
                category="Sports",
                image_url="https://images.unsplash.com/photo-1601925260368-ae2f83cf8b7f?w=400",
                stock=85
            ),
            Product(
                name="Novel: The Midnight Library",
                description="Bestselling fiction novel by Matt Haig. A dazzling story about all the choices that go into a life well lived. Paperback edition, 304 pages.",
                price=399.00,
                category="Books",
                image_url="https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=400",
                stock=200
            ),
            Product(
                name="Ceramic Coffee Mug Set",
                description="Set of 4 handcrafted ceramic coffee mugs. 350ml capacity each. Microwave and dishwasher safe. Beautiful matte finish in assorted earth tones.",
                price=799.00,
                category="Home & Kitchen",
                image_url="https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?w=400",
                stock=95
            ),
            Product(
                name="Portable Bluetooth Speaker",
                description="Compact waterproof Bluetooth 5.0 speaker with 360° surround sound. 12-hour playtime, built-in microphone, and TWS pairing. IPX7 rated.",
                price=1999.00,
                category="Electronics",
                image_url="https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?w=400",
                stock=65
            ),
        ]
        db.session.add_all(products)
        db.session.commit()
        print(f"[SEED] {len(products)} demo products added.")


def _start_https_background_listener(app, https_port: int = 5443):
    """Start a concurrent TLS 1.3 HTTPS server on https_port in a daemon thread."""
    try:
        from werkzeug.serving import make_server
        from services.crypto.transaction_security import create_tls_server_context

        ssl_ctx = create_tls_server_context(require_tls13=False)
        https_srv = make_server('0.0.0.0', https_port, app, ssl_context=ssl_ctx, threaded=True)
        t = threading.Thread(target=https_srv.serve_forever, daemon=True)
        t.start()
        print(f" * [TLS 1.3 / HTTPS] Running on https://127.0.0.1:{https_port}")
    except Exception as exc:
        print(f" * [TLS 1.3] Could not bind secondary HTTPS port {https_port}: {exc}")


# Create and run the application instance
if __name__ == '__main__':
    from services.crypto.rsa_key_management import get_or_create_server_keypair
    from services.crypto.transaction_security import create_tls_server_context, ensure_local_tls_certificates

    app = create_app()
    get_or_create_server_keypair()
    ensure_local_tls_certificates()

    if '--https' in sys.argv or os.environ.get('ENABLE_HTTPS') == '1':
        tls_ctx = create_tls_server_context(require_tls13=False)
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False, ssl_context=tls_ctx)
    else:
        _start_https_background_listener(app, app.config.get('HTTPS_PORT', 5443))
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
