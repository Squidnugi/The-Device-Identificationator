"""Local password hashing/verification for privileged CLI commands."""
import json
from pathlib import Path

import bcrypt


CONFIG_PATH = Path("config/auth.json")


def set_password(password: str) -> None:
    """Hash and store a new password in the auth config file.

    Parameters
    ----------
    password : str
        Plaintext password to hash and persist.
    """
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps({"password_hash": hashed.decode("utf-8")}))


def verify_password(password: str) -> bool:
    """Check an entered password against the stored hash.

    Parameters
    ----------
    password : str
        Plaintext password supplied by the user.

    Returns
    -------
    bool
        True when the password matches the stored hash, False otherwise.
    """
    if not CONFIG_PATH.exists():
        return False
    data = json.loads(CONFIG_PATH.read_text())
    stored_hash = data.get("password_hash")
    if not stored_hash:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))


def is_password_set() -> bool:
    """Return True when a password hash has been saved to the auth config file."""
    return CONFIG_PATH.exists()
