from flask import Flask, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from config import Config
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect

from app.security.logger import security_logger


# ----------------------------
# Extensions
# ----------------------------

# Database ORM
db = SQLAlchemy()

# CSRF protection for all POST requests
csrf = CSRFProtect()


def create_app():
    """
    Application factory.
    Responsible for initialising Flask, extensions,
    security configuration, routes, and error handling.
    """

    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialise extensions
    db.init_app(app)
    csrf.init_app(app)

    # Security-focused logger (authentication, access control, errors)
    logger = security_logger()

    # ============================================================
    # HTTP Security Headers (Section E)
    # Applied to every response
    # ============================================================
    @app.after_request
    def add_security_headers(response):
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Limit referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Disable unused browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # Content Security Policy
        # Restricts scripts, styles, images, and fonts to trusted sources
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "img-src 'self' data:; "
            "script-src 'self' https: 'unsafe-inline'; "
            "style-src 'self' https: 'unsafe-inline'; "
            "font-src 'self' https: data:;"
        )

        # Enforce HTTPS in production
        if not app.debug:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response

    # ============================================================
    # Error Handling & Secure Logging (Section I)
    # ============================================================

    @app.errorhandler(403)
    def forbidden(e):
        # Log unauthorised access attempts with context
        logger.warning(
            f"403_FORBIDDEN | path={request.path} | "
            f"ip={request.remote_addr} | "
            f"user={session.get('user')} | "
            f"role={session.get('role')}"
        )
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        # Log invalid route access
        logger.warning(
            f"404_NOT_FOUND | path={request.path} | ip={request.remote_addr}"
        )
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        # Log unexpected server errors without exposing details to users
        logger.error(
            f"500_SERVER_ERROR | path={request.path} | ip={request.remote_addr}"
        )
        return render_template("500.html"), 500

    # ============================================================
    # Blueprints
    # ============================================================

    from app.main.routes import main
    app.register_blueprint(main)

    # ============================================================
    # Database initialisation & seed data
    # ============================================================

    with app.app_context():
        from app.models import User

        # Create tables if they do not exist
        db.create_all()

        # Seed test users only if database is empty
        if User.query.count() == 0:
            users = [
                {
                    "username": "user1@email.com",
                    "password": "Userpass!23",
                    "role": "user",
                    "bio": "I'm a basic user",
                },
                {
                    "username": "mod1@email.com",
                    "password": "Modpass!23",
                    "role": "moderator",
                    "bio": "I'm a moderator",
                },
                {
                    "username": "admin1@email.com",
                    "password": "Adminpass!23",
                    "role": "admin",
                    "bio": "I'm an administrator",
                },
            ]

            # Passwords are hashed before storage
            db.session.bulk_save_objects([
                User(
                    username=u["username"],
                    password=generate_password_hash(u["password"]),
                    role=u["role"],
                    bio=u["bio"],
                )
                for u in users
            ])
            db.session.commit()

    return app