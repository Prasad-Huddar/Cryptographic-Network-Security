"""
Authentication routes: login, register, logout, password change.
"""
from urllib.parse import urlsplit
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from services.auth_service import register_user, authenticate_user, log_security_event, validate_password
from database.database import db

auth_bp = Blueprint('auth', __name__)


def _is_safe_redirect_url(target: str | None) -> bool:
    if not target:
        return False
    parsed = urlsplit(target)
    return not parsed.scheme and not parsed.netloc and target.startswith('/') and not target.startswith('//')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('products.product_list'))

    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', name=name, email=email)

        success, message, user = register_user(name, email, password)
        if success:
            flash(message, 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
            return render_template('register.html', name=name, email=email)

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.must_change_password:
            return redirect(url_for('auth.change_password'))
        return redirect(url_for('products.product_list'))

    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        success, message, user = authenticate_user(email, password)
        if success:
            login_user(user, remember=bool(remember))
            flash(message, 'success')
            if user.must_change_password:
                flash('Please change your default password.', 'warning')
                return redirect(url_for('auth.change_password'))
            next_page = request.args.get('next')
            if _is_safe_redirect_url(next_page):
                return redirect(next_page)
            return redirect(url_for('products.product_list'))
        else:
            flash(message, 'danger')
            return render_template('login.html', email=email)

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    log_security_event('LOGOUT', f'User logged out: {current_user.email}', current_user.id)
    logout_user()
    session.pop('cart', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')

        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            flash(error_msg, 'danger')
            return render_template('change_password.html')

        current_user.set_password(new_password)
        current_user.must_change_password = False
        db.session.commit()

        log_security_event('PASSWORD_CHANGE', f'Password changed for: {current_user.email}', current_user.id)
        flash('Password changed successfully!', 'success')
        return redirect(url_for('products.product_list'))

    return render_template('change_password.html')
