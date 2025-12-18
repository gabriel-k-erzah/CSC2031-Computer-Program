import os
from datetime import timedelta

class Config:
    DEBUG = True
    SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///site.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JS cannot read session cookie
    SESSION_COOKIE_HTTPONLY = True
    # Mitigates CSRF
    SESSION_COOKIE_SAMESITE = "Lax"
    # Set True if HTTPS
    SESSION_COOKIE_SECURE = False

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)