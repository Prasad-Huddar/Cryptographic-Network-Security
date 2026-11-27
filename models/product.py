"""
Product model for the e-commerce catalogue.
"""
from database.database import db
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False, index=True)
    image_url = db.Column(db.String(500), default='')
    stock = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    order_items = db.relationship('OrderItem', backref='product', lazy=True)

    @property
    def formatted_price(self):
        return f"₹{self.price:,.2f}"

    @property
    def in_stock(self):
        return self.stock > 0

    def __repr__(self):
        return f'<Product {self.name}>'
