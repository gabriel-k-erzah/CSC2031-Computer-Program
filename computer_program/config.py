import os
from datetime import timedelta


class Config:
    # ----------------------------
    # Core Flask configuration
    # ----------------------------

    # Debug must be OFF for production / submission
    # Prevents stack traces and sensitive info leaking to users
    DEBUG = False

    # Secret key used to:
    # - sign session cookies
    # - protect CSRF tokens
    # Loaded from environment if available (best practice)
    SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")

    # ----------------------------
    # Database configuration
    # ----------------------------

    # Database URI (defaults to local SQLite for development)
    # Can be overridden with DATABASE_URL in deployment
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///site.db"
    )

    # Disable modification tracking (saves memory, avoids warnings)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ----------------------------
    # Session & cookie security
    # ----------------------------

    # Prevent JavaScript from accessing session cookies
    # Protects against XSS-based session theft
    SESSION_COOKIE_HTTPONLY = True

    # Controls when cookies are sent with cross-site requests
    # "Lax" balances usability with CSRF protection
    SESSION_COOKIE_SAMESITE = "Lax"

    # Ensures cookies are only sent over HTTPS
    # Set to True in production with HTTPS enabled
    SESSION_COOKIE_SECURE = False

    # ----------------------------
    # Session lifetime
    # ----------------------------

    # Automatically logs users out after inactivity
    # Reduces risk from abandoned or hijacked sessions
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)