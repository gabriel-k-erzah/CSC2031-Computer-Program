class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Current password",
        validators=[DataRequired()],
    )
    new_password = PasswordField(
        "New password",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    submit = SubmitField("Change password")
