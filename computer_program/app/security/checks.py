from werkzeug.security import check_password_hash

# ---------- Authentication ----------
def credentials_valid(user, password: str) -> bool:
    return bool(user) and check_password_hash(user.password, password)


# ---------- Authorisation ----------
def role_allowed(session_role: str, *allowed_roles) -> bool:
    return session_role in allowed_roles


# ---------- Account / Password ----------
def password_is_new(user, new_password: str) -> bool:
    return not check_password_hash(user.password, new_password)


# ---------- Session ----------
def is_logged_in(session) -> bool:
    return "user" in session