def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user" not in session:
            # Generic error: no stack traces to user
            abort(403, description="Access denied.")
        return view_func(*args, **kwargs)

    return wrapped_view


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            role = session.get("role")
            if "user" not in session or role not in allowed_roles:
                abort(403, description="Access denied.")
            return view_func(*args, **kwargs)

        return wrapped_view

    return decorator
