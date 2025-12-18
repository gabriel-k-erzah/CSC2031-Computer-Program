from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    csrf.init_app(app)

    # ---------- HTTP Security Headers (Section E) ----------
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline';"
        )

        if not app.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response
    # -----------------------------------------------------

    from app.main.routes import main
    from app.security.routes import security

    app.register_blueprint(main)
    app.register_blueprint(security)

    with app.app_context():
        from app.models import User
        db.create_all()

        if User.query.count() == 0:
            users = [
                {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
                {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
                {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"},
            ]

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