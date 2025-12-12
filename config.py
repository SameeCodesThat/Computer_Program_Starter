from datetime import timedelta
from flask import Flask
import os

app = Flask(__name__)
#-------------------- secure session management (CWE-614) -------------------

class Config:
    DEBUG = True
    SECRET_KEY = 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER")
    BIO_KEY = os.getenv("BIO_ENCRYPTION_KEY")

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = "development"

class ProductionConfig(Config):
    DEBUG = False
    ENV = "production"
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")