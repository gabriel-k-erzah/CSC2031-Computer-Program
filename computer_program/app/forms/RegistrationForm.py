import re
import bleach

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError

from app.models import User

# XSS prevention
def sanitise_text(value: str) -> str:
    return bleach.clean(value or "", tags=[], attributes={}, strip=True).strip()


class RegistrationForm(FlaskForm):
    username = StringField(
        "Email",
        validators=[
            DataRequired(),
            Email(message="Enter a valid email address."),
            Length(max=254),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
            Regexp(r".*[A-Z].*", message="Password must include an uppercase letter."),
            Regexp(r".*[a-z].*", message="Password must include a lowercase letter."),
            Regexp(r".*\d.*", message="Password must include a number."),
            Regexp(r".*[^A-Za-z0-9].*", message="Password must include a symbol."),
        ],
    )

    bio = TextAreaField(
        "Biography",
        validators=[Length(max=500)],
    )

    role = SelectField(
        "Role",
        choices=[("user", "User"), ("moderator", "Moderator"), ("admin", "Admin")],
        default="user",
    )

    submit = SubmitField("Register")

    # ---------- Field-level logical checks ----------
    def validate_username(self, field):
        field.data = sanitise_text(field.data).lower()

        # Extra defensive rule: reject whitespace
        if " " in field.data:
            raise ValidationError("Email must not contain spaces.")

        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username is already taken.")

    def validate_bio(self, field):
        field.data = sanitise_text(field.data)

        # Prevent “empty but huge whitespace”
        if len(field.data) == 0:
            return
        # Block obvious script-like substrings (defense-in-depth)
        if re.search(r"<\s*script", field.data, flags=re.IGNORECASE):
            raise ValidationError("Biography contains unsafe content.")