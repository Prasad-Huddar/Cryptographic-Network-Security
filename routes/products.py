"""
Product routes: catalogue, search, details.
"""
from flask import Blueprint, render_template, request
from database.database import db
from models.product import Product

products_bp = Blueprint('products', __name__)


@products_bp.route('/')
def index():
    """Home page with featured products."""
    featured = Product.query.filter_by(is_active=True).order_by(Product.created_at.desc()).limit(8).all()
    categories = db_get_categories()
    return render_template('index.html', featured_products=featured, categories=categories)


@products_bp.route('/products')
def product_list():
    """Product catalogue with search, category filter, and sorting."""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str).strip()
    category = request.args.get('category', '', type=str).strip()
    sort = request.args.get('sort', 'name', type=str).strip()

    query = Product.query.filter_by(is_active=True)

    if search:
        query = query.filter(
            (Product.name.ilike(f'%{search}%')) |
            (Product.description.ilike(f'%{search}%'))
        )

    if category:
        query = query.filter_by(category=category)

    if sort == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort == 'price_desc':
        query = query.order_by(Product.price.desc())
    elif sort == 'newest':
        query = query.order_by(Product.created_at.desc())
    else:
        sort = 'name'
        query = query.order_by(Product.name.asc())

    products = query.paginate(page=page, per_page=12, error_out=False)
    categories = db_get_categories()

    return render_template('products.html',
                         products=products,
                         search=search,
                         current_category=category,
                         current_sort=sort,
                         categories=categories)


@products_bp.route('/product/<int:product_id>')
def product_detail(product_id):
    """Product details page."""
    product = db.get_or_404(Product, product_id)
    related = Product.query.filter(
        Product.category == product.category,
        Product.id != product.id,
        Product.is_active == True
    ).limit(4).all()
    return render_template('product_details.html', product=product, related_products=related)


def db_get_categories():
    """Get all unique product categories."""
    results = Product.query.with_entities(Product.category).distinct().order_by(Product.category).all()
    return [r[0] for r in results]
