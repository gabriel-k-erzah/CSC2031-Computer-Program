import re
import bleach

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError

from app.models import User


# ============================================================
# Input sanitisation helper (Section A)
# ============================================================
# We sanitise free-text fields to reduce XSS risk:
# - strip all HTML tags
# - strip attributes
# - trim whitespace
# Note: Jinja auto-escapes by default, this is defense-in-depth.
# ============================================================
def sanitise_text(value: str) -> str:
    return bleach.clean(value or "", tags=[], attributes={}, strip=True).strip()


class RegistrationForm(FlaskForm):
    """
    Registration form with strong validation:
    - email format enforced
    - password strength enforced
    - bio length limited and sanitised
    - role selectable (for coursework testing)
    """

    # Username is treated as email (validated by Email())
    username = StringField(
        "Email",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Enter a valid email address."),
            Length(max=254, message="Email must be 254 characters or fewer."),
        ],
    )

    # Password rules enforce complexity (OWASP-ish baseline)
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(min=12, max=128, message="Password must be 12–128 characters."),
            Regexp(r".*[A-Z].*", message="Password must include an uppercase letter."),
            Regexp(r".*[a-z].*", message="Password must include a lowercase letter."),
            Regexp(r".*\d.*", message="Password must include a number."),
            Regexp(r".*[^A-Za-z0-9].*", message="Password must include a symbol."),
        ],
    )

    # Biography is optional but must be sane length
    bio = TextAreaField(
        "Biography",
        validators=[Length(max=500, message="Biography must be 500 characters or fewer.")],
    )

    # Role exists for testing RBAC in coursework
    role = SelectField(
        "Role",
        choices=[("user", "User"), ("moderator", "Moderator"), ("admin", "Admin")],
        default="user",
    )

    submit = SubmitField("Register")

    # ============================================================
    # Field-level logical validation
    # WTForms automatically calls validate_<fieldname>()
    # ============================================================

    def validate_username(self, field):
        """
        Normalise + validate email, then enforce uniqueness.
        """
        # Sanitise and normalise (consistent storage and comparison)
        field.data = sanitise_text(field.data).lower()

        # Defensive check: email should never contain spaces
        if " " in field.data:
            raise ValidationError("Email must not contain spaces.")

        # Uniqueness check (prevents duplicate accounts)
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username is already taken.")

    def validate_bio(self, field):
        """
        Sanitise biography text to prevent XSS payload storage.
        """
        field.data = sanitise_text(field.data)

        # Allow empty bio (optional field)
        if len(field.data) == 0:
            return

        # Defense-in-depth: block obvious script-like patterns
        # (bleach already strips tags, this is just monitoring-grade filtering)
        if re.search(r"<\s*script", field.data, flags=re.IGNORECASE):
            raise ValidationError("Biography contains unsafe content.")