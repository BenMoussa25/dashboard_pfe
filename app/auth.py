from datetime import timedelta
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session, flash
from flask_jwt_extended import (
    create_access_token, 
    set_access_cookies, 
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app.models import User

auth_bp = Blueprint('auth', __name__)

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role != 'admin' and current_user.role != required_role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('auth.login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(get_redirect_url(current_user.role))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Log in with Flask-Login
            login_user(user)
            
            # Create JWT token
            access_token = create_access_token(
                identity=user.id,
                additional_claims={'role': user.role}
            )

            response = redirect(get_redirect_url(user.role))
            set_access_cookies(response, access_token)
            return response
        
        flash('Invalid username or password', 'danger')
        return render_template('auth/login.html')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    response = redirect(url_for('auth.login'))
    response.delete_cookie('access_token_cookie')
    return response

def get_redirect_url(role):
    """Return the appropriate redirect URL based on user role"""
    if role == 'admin':
        return url_for('main.ml_models')
    elif role == 'manager':
        return url_for('main.analytics')
    else:
        return url_for('main.dashboard')