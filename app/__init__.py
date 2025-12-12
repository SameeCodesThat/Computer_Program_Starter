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

    db.init_app(app)

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
            user = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"])
            db.session.add(user)
            db.session.commit()

    return app

