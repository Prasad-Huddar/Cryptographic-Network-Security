"""
Test suite for the Secure E-Commerce Application.
"""
import sys
import os
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from database.database import db
from models.user import User
from models.product import Product
from models.order import Order


class BaseTestCase(unittest.TestCase):
    """Base test case with app setup and teardown."""

    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self._seed_test_data()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _seed_test_data(self):
        """Create test data."""
        # Create admin user
        admin = User(name='Test Admin', email='admin@test.com', role='admin')
        admin.set_password('Admin@12345')
        db.session.add(admin)

        # Create customer user
        customer = User(name='Test Customer', email='customer@test.com', role='customer')
        customer.set_password('Customer@123')
        db.session.add(customer)

        # Create test products
        p1 = Product(name='Test Product 1', description='A test product description.', price=999.00, category='Electronics', stock=10)
        p2 = Product(name='Test Product 2', description='Another test product description.', price=499.00, category='Clothing', stock=5)
        db.session.add_all([p1, p2])
        db.session.commit()

    def login(self, email, password):
        """Helper to login a user."""
        return self.client.post('/login', data={
            'email': email,
            'password': password
        }, follow_redirects=True)

    def logout(self):
        """Helper to logout."""
        return self.client.get('/logout', follow_redirects=True)


class TestRegistration(BaseTestCase):
    """Test user registration."""

    def test_register_page_loads(self):
        response = self.client.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Create Account', response.data)

    def test_successful_registration(self):
        response = self.client.post('/register', data={
            'name': 'New User',
            'email': 'newuser@test.com',
            'password': 'NewUser@123',
            'confirm_password': 'NewUser@123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Registration successful', response.data)

        # Verify user exists in database
        user = User.query.filter_by(email='newuser@test.com').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.role, 'customer')

    def test_duplicate_registration(self):
        response = self.client.post('/register', data={
            'name': 'Duplicate User',
            'email': 'customer@test.com',
            'password': 'Customer@123',
            'confirm_password': 'Customer@123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'already exists', response.data)

    def test_password_mismatch(self):
        response = self.client.post('/register', data={
            'name': 'New User',
            'email': 'mismatch@test.com',
            'password': 'NewUser@123',
            'confirm_password': 'WrongPass@123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Passwords do not match', response.data)

    def test_weak_password(self):
        response = self.client.post('/register', data={
            'name': 'New User',
            'email': 'weak@test.com',
            'password': '123',
            'confirm_password': '123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'at least 8 characters', response.data)


class TestLogin(BaseTestCase):
    """Test user login."""

    def test_login_page_loads(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome Back', response.data)

    def test_valid_login(self):
        response = self.login('customer@test.com', 'Customer@123')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login successful', response.data)

    def test_invalid_login(self):
        response = self.login('customer@test.com', 'WrongPassword@1')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid email or password', response.data)

    def test_nonexistent_user_login(self):
        response = self.login('noone@test.com', 'Whatever@123')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid email or password', response.data)

    def test_logout(self):
        self.login('customer@test.com', 'Customer@123')
        response = self.logout()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'logged out', response.data)


class TestProductListing(BaseTestCase):
    """Test product listing and search."""

    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SecureShop', response.data)

    def test_product_list(self):
        response = self.client.get('/products')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test Product 1', response.data)
        self.assertIn(b'Test Product 2', response.data)

    def test_product_detail(self):
        product = Product.query.first()
        response = self.client.get(f'/product/{product.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(product.name.encode(), response.data)

    def test_product_search(self):
        response = self.client.get('/products?search=Electronics')
        self.assertEqual(response.status_code, 200)

    def test_category_filter(self):
        response = self.client.get('/products?category=Electronics')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test Product 1', response.data)


class TestCart(BaseTestCase):
    """Test shopping cart functionality."""

    def test_add_to_cart(self):
        self.login('customer@test.com', 'Customer@123')
        product = Product.query.first()
        response = self.client.post(f'/cart/add/{product.id}', data={
            'quantity': 1
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'added to cart', response.data)

    def test_view_cart(self):
        self.login('customer@test.com', 'Customer@123')
        product = Product.query.first()
        self.client.post(f'/cart/add/{product.id}', data={'quantity': 1}, follow_redirects=True)

        response = self.client.get('/cart')
        self.assertEqual(response.status_code, 200)
        self.assertIn(product.name.encode(), response.data)

    def test_remove_from_cart(self):
        self.login('customer@test.com', 'Customer@123')
        product = Product.query.first()
        self.client.post(f'/cart/add/{product.id}', data={'quantity': 1}, follow_redirects=True)

        response = self.client.post(f'/cart/remove/{product.id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'removed from cart', response.data)

    def test_cart_requires_login(self):
        response = self.client.get('/cart', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'login', response.data.lower())


class TestCheckoutAndOrders(BaseTestCase):
    """Test checkout and order creation."""

    def test_checkout_page(self):
        self.login('customer@test.com', 'Customer@123')
        product = Product.query.first()
        self.client.post(f'/cart/add/{product.id}', data={'quantity': 2}, follow_redirects=True)

        response = self.client.get('/checkout')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Checkout', response.data)

    def test_place_order(self):
        self.login('customer@test.com', 'Customer@123')
        product = Product.query.first()
        self.client.post(f'/cart/add/{product.id}', data={'quantity': 1}, follow_redirects=True)

        response = self.client.post('/checkout', data={
            'shipping_address': '123 Test Street, Test City, Test State, 123456'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'placed successfully', response.data)

        # Verify order in database
        orders = Order.query.filter_by(user_id=2).all()  # customer is user 2
        self.assertEqual(len(orders), 1)

    def test_order_history(self):
        self.login('customer@test.com', 'Customer@123')
        response = self.client.get('/orders')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'My Orders', response.data)

    def test_empty_cart_checkout(self):
        self.login('customer@test.com', 'Customer@123')
        response = self.client.get('/checkout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'cart is empty', response.data)


class TestAccessControl(BaseTestCase):
    """Test role-based access control."""

    def test_customer_cannot_access_admin(self):
        self.login('customer@test.com', 'Customer@123')
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 403)

    def test_admin_can_access_dashboard(self):
        self.login('admin@test.com', 'Admin@12345')
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)

    def test_guest_cannot_access_cart(self):
        response = self.client.get('/cart', follow_redirects=True)
        self.assertIn(b'login', response.data.lower())

    def test_guest_cannot_checkout(self):
        response = self.client.get('/checkout', follow_redirects=True)
        self.assertIn(b'login', response.data.lower())

    def test_admin_manage_products(self):
        self.login('admin@test.com', 'Admin@12345')
        response = self.client.get('/admin/products')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Manage Products', response.data)

    def test_admin_manage_orders(self):
        self.login('admin@test.com', 'Admin@12345')
        response = self.client.get('/admin/orders')
        self.assertEqual(response.status_code, 200)

    def test_admin_manage_users(self):
        self.login('admin@test.com', 'Admin@12345')
        response = self.client.get('/admin/users')
        self.assertEqual(response.status_code, 200)

    def test_customer_cannot_access_admin_products(self):
        self.login('customer@test.com', 'Customer@123')
        response = self.client.get('/admin/products')
        self.assertEqual(response.status_code, 403)

    def test_customer_cannot_access_admin_orders(self):
        self.login('customer@test.com', 'Customer@123')
        response = self.client.get('/admin/orders')
        self.assertEqual(response.status_code, 403)


class TestPasswordSecurity(BaseTestCase):
    """Test password hashing and security."""

    def test_password_is_hashed(self):
        user = User.query.filter_by(email='customer@test.com').first()
        self.assertNotEqual(user.password_hash, 'Customer@123')
        self.assertTrue(user.password_hash.startswith('pbkdf2:sha256'))

    def test_password_verification(self):
        user = User.query.filter_by(email='customer@test.com').first()
        self.assertTrue(user.check_password('Customer@123'))
        self.assertFalse(user.check_password('WrongPassword'))

    def test_different_users_different_hashes(self):
        """Each user gets a unique salt, so even same passwords produce different hashes."""
        user1 = User(name='Test1', email='test1@test.com')
        user1.set_password('SamePass@123')
        user2 = User(name='Test2', email='test2@test.com')
        user2.set_password('SamePass@123')
        self.assertNotEqual(user1.password_hash, user2.password_hash)


if __name__ == '__main__':
    unittest.main(verbosity=2)
