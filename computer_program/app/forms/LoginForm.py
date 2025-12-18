from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    """
    Login form for existing users.

    Uses WTForms to:
    - enforce required fields
    - constrain input length
    - automatically protect against CSRF
    """

    # Username (email) field
    # Length limits prevent abuse and overly large payloads
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
        ],
    )

    # Password field
    # No format validation here to avoid leaking password rules
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(min=8, max=128, message="Password length is invalid."),
        ],
    )

    submit = SubmitField("Login")