from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length


class ChangePasswordForm(FlaskForm):
    """
    Form used for changing an existing user's password.

    Security notes:
    - Requires the current password for verification
    - Enforces length limits on the new password
    - CSRF protection is automatically applied via FlaskForm
    """

    # Current password is required to confirm user identity
    # No format validation to avoid leaking password policy
    current_password = PasswordField(
        "Current password",
        validators=[
            DataRequired(message="Current password is required."),
        ],
    )

    # New password must meet minimum length requirements
    # Full complexity rules are enforced at registration;
    # reuse prevention is handled in route logic
    new_password = PasswordField(
        "New password",
        validators=[
            DataRequired(message="New password is required."),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters."),
        ],
    )

    submit = SubmitField("Change password")