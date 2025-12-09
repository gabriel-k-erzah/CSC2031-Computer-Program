class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=50)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    bio = TextAreaField("Biography", validators=[Length(max=500)])
    # For testing roles; you can hide this in UI if needed
    role = SelectField(
        "Role",
        choices=[("user", "User"), ("moderator", "Moderator"), ("admin", "Admin")],
        default="user",
    )
    submit = SubmitField("Register")



