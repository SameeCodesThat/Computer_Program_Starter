import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from app import db, bcrypt
from app.models import User
from app.forms import LoginForm, RegisterForm, ChangePasswordForm
import bleach
from flask_login import login_user, logout_user, login_required, current_user
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import text

load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    bcrypt.init_app(app)
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "main.login"

    PEPPER = app.config.get("PASSWORD_PEPPER")
    BIO_KEY = app.config.get("BIO_ENCRYPTION_KEY")
    if not BIO_KEY:
        BIO_KEY = Fernet.generate_key().decode()
    fernet = Fernet(BIO_KEY.encode())
    app.PEPPER = PEPPER
    app.fernet = fernet

    handler = RotatingFileHandler("app.log", maxBytes=1_000_000, backupCount=5)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(levelname)s  %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    app.logger.addHandler(handler)

    env = os.environ.get("FLASK_ENV", "development")

    if env == "production":
        app.config.from_object(ProductionConfig)
    else:
        app.config.from_object(DevelopmentConfig)

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User
        db.drop_all()
        db.create_all()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for user in users:
            pepper = user["password"] + str(PEPPER)
            hashed_pw = bcrypt.generate_password_hash(pepper).decode('utf-8')
            encrypted_bio = fernet.encrypt(user["bio"].encode()).decode('utf-8')
            user = User(username=user["username"], password=hashed_pw, role=user["role"], bio=encrypted_bio)
            db.session.add(user)
            db.session.commit()

    return app

@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))
