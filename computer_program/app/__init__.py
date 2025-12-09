from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize Flask-SQLAlchemy
    db.init_app(app)

    from app.security.routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User
        # Create tables if they don't exist
        db.create_all()

        # Seed temporary credentials only if the users table is empty
        if User.query.count() == 0:
            users = [
                {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
                {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
                {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
            ]

            db.session.bulk_save_objects([
                User(username=u["username"], password=u["password"], role=u["role"], bio=u["bio"]) for u in users
            ])
            db.session.commit()

    return app

