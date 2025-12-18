from app import db


class User(db.Model):
    """
    User model representing authenticated users of the application.
    Designed using a simple relational structure with role-based access.
    """

    # ----------------------------
    # Primary key
    # ----------------------------
    id = db.Column(db.Integer, primary_key=True)

    # ----------------------------
    # Authentication fields
    # ----------------------------

    # Username is used as a login identifier (email format enforced elsewhere)
    # Must be unique to prevent account collisions
    username = db.Column(db.String(80), unique=True, nullable=False)

    # Stores a securely hashed password (never plaintext)
    # Length allows for modern hashing algorithms (e.g. PBKDF2)
    password = db.Column(db.String(255), nullable=False)

    # ----------------------------
    # Authorisation
    # ----------------------------

    # Role determines access level (user / moderator / admin)
    # Enforced via decorators at the route level
    role = db.Column(db.String(50), default="user", nullable=False)

    # ----------------------------
    # User profile data
    # ----------------------------

    # Short biography text
    # Sanitised and length-limited at the form level
    bio = db.Column(db.String(500), nullable=False)

    # ----------------------------
    # Initialiser
    # ----------------------------

    def __init__(self, username, password, role, bio):
        # All validation and sanitisation is handled before model creation
        self.username = username
        self.password = password
        self.role = role
        self.bio = bio