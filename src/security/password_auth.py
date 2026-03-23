"""Local password hashing/verification for privileged CLI commands."""

import bcrypt
import json
from pathlib import Path

CONFIG_PATH = Path("config/auth.json")

def set_password(password: str):
    """Hash and store a new password."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps({"password_hash": hashed.decode("utf-8")}))

def verify_password(password: str):
    """Check an entered password against the stored hash."""
    if not CONFIG_PATH.exists():
        return False
    data = json.loads(CONFIG_PATH.read_text())
    stored_hash = data["password_hash"].encode("utf-8")
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)

def is_password_set():
    return CONFIG_PATH.exists()