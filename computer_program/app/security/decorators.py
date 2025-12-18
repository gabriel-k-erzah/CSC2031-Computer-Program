from functools import wraps
from flask import session, abort

# ============================================================
# Access control decorators
# ============================================================
# Enforce authentication and role-based authorisation at the
# route level. These checks run server-side and cannot be
# bypassed via client manipulation.
# ============================================================


def login_required(view_func):
    """
    Ensure the user is authenticated before accessing a route.

    Checks:
    - A valid user session exists

    Used for:
    - dashboards
    - account actions
    - protected pages
    """
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user" not in session:
            # Abort with 403 to avoid revealing route existence
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped_view


def roles_required(*allowed_roles):
    """
    Ensure the authenticated user has one of the required roles.

    Args:
        allowed_roles: Tuple of permitted roles (e.g. "admin", "moderator")

    Used for:
    - admin-only routes
    - moderator functionality
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            role = session.get("role")

            # Require both authentication and correct role
            if "user" not in session or role not in allowed_roles:
                abort(403)

            return view_func(*args, **kwargs)

        return wrapped_view

    return decorator