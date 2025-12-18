# ----------------------------
# User repository functions
# ----------------------------
# Centralises database access logic related to users.
# This helps prevent SQL injection by ensuring all queries
# go through SQLAlchemy ORM in one controlled place.

from app.models import User


def get_user_by_username(username: str):
    """
    Fetch a user record by username.

    Used during:
    - login authentication
    - session validation
    - password changes

    Returns:
        User object if found, otherwise None
    """
    return User.query.filter_by(username=username).first()


def username_taken(username: str) -> bool:
    """
    Check whether a username already exists.

    Used during:
    - registration validation
    - account creation checks

    Returns:
        True if username exists, False otherwise
    """
    return User.query.filter_by(username=username).first() is not None