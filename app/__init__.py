from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from datetime import timedelta
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
jwt = JWTManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)

    # JWT configuration
    app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = False
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['WTF_CSRF_ENABLED'] = False

    from app.models import User
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)

    # Login manager config
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    # Register blueprints
    from app.auth import auth_bp
    from app.routes import main_routes
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_routes)

    # Initialize database within app context
    with app.app_context():
        db.create_all()
        # Initialize default settings if needed
        from app.models import SystemSetting
        if not SystemSetting.query.first():  # Only init if no settings exist
            from app.utils.settings import init_default_settings
            init_default_settings(app)

    return app