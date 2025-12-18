# ----------------------------
# Forms package exports
# ----------------------------
# Centralises form imports so routes can access all forms
# from a single location (app.forms).
#
# This improves readability and avoids long import chains
# in route files.
# ----------------------------

from .LoginForm import LoginForm
from .RegistrationForm import RegistrationForm
from .ChangePasswordForm import ChangePasswordForm