from werkzeug.security import check_password_hash

# ============================================================
# Security check helpers
# ============================================================
# Small, focused functions used to centralise common security
# checks related to authentication, authorisation, passwords,
# and session state.
#
# Keeping these checks here avoids duplicated logic in routes
# and makes security decisions easy to audit.
# ============================================================


# ----------------------------
# Authentication
# ----------------------------
def credentials_valid(user, password: str) -> bool:
    """
    Validate supplied login credentials.

    Checks:
    - User exists
    - Password hash matches stored hash

    Returns:
        True if credentials are valid
    """
    return bool(user) and check_password_hash(user.password, password)


# ----------------------------
# Authorisation
# ----------------------------
def role_allowed(session_role: str, *allowed_roles) -> bool:
    """
    Check whether the user's role is permitted.

    Args:
        session_role: Role stored in the session
        allowed_roles: One or more allowed roles

    Returns:
        True if role is authorised
    """
    return session_role in allowed_roles


# ----------------------------
# Account / Password
# ----------------------------
def password_is_new(user, new_password: str) -> bool:
    """
    Ensure the new password is different from the current one.

    Used during password change to prevent password reuse.

    Returns:
        True if the password is different
    """
    return not check_password_hash(user.password, new_password)


# ----------------------------
# Session
# ----------------------------
def is_logged_in(session) -> bool:
    """
    Check whether a valid login session exists.

    Returns:
        True if user session key is present
    """
    return "user" in session