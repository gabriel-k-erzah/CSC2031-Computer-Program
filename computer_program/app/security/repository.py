#clear seperation
from app.models import User
def get_user_by_username(username: str):
    return User.query.filter_by(username=username).first()
def username_taken(username: str) -> bool:
    return User.query.filter_by(username=username).first() is not None