# models.py — MongoDB schema representation (optional helper structure)

# Note: MongoDB (with Flask-PyMongo) is schemaless, but we can define model structure
# for reference or validation if desired. This is optional for basic apps.

# If you want schema validation, use MongoEngine or manually validate in routes.

from bson.objectid import ObjectId

def user_schema(user_doc):
    return {
        "_id": str(user_doc.get("_id", "")),
        "username": user_doc.get("username"),
        "password": user_doc.get("password")  # hashed
    }


def entry_schema(entry_doc):
    return {
        "_id": str(entry_doc.get("_id", "")),
        "user_id": str(entry_doc.get("user_id")),
        "token": entry_doc.get("token"),
        "key": entry_doc.get("key")
    }

# Optional: Create user or entry objects before insert

def create_user(username, password_hash):
    return {
        "username": username,
        "password": password_hash
    }


def create_entry(user_id, token, key):
    return {
        "user_id": ObjectId(user_id),
        "token": token,
        "key": key
    }
