# auth.py — handles user and admin authentication logic

from flask import session, redirect, url_for, flash
from werkzeug.security import check_password_hash
from functools import wraps
from bson.objectid import ObjectId

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You must be logged in to access this page.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            flash("Admin access only.")
            return redirect(url_for('admin'))
        return f(*args, **kwargs)
    return decorated_function


def authenticate_user(mongo, username, password):
    user = mongo.db.users.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        return user
    return None


def get_user_by_id(mongo, user_id):
    return mongo.db.users.find_one({'_id': ObjectId(user_id)})
