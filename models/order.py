"""
Order and OrderItem models.
"""
from database.database import db
from datetime import datetime, timezone
import uuid


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())[:8].upper())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(30), nullable=False, default='pending')
    total_amount = db.Column(db.Float, nullable=False, default=0.0)
    shipping_address = db.Column(db.Text, nullable=False)
    payment_method = db.Column(db.String(50), default='demo_payment')
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')
    transaction = db.relationship('Transaction', backref='order', uselist=False, lazy=True)

    @property
    def formatted_total(self):
        return f"₹{self.total_amount:,.2f}"

    @property
    def status_badge(self):
        badges = {
            'pending': 'warning',
            'confirmed': 'info',
            'processing': 'primary',
            'shipped': 'info',
            'delivered': 'success',
            'cancelled': 'danger'
        }
        return badges.get(self.status, 'secondary')

    def __repr__(self):
        return f'<Order {self.order_number}>'


class OrderItem(db.Model):
    __tablename__ = 'order_items'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    price = db.Column(db.Float, nullable=False)

    @property
    def subtotal(self):
        return self.price * self.quantity

    @property
    def formatted_subtotal(self):
        return f"₹{self.subtotal:,.2f}"

    def __repr__(self):
        return f'<OrderItem {self.product_name} x{self.quantity}>'
