"""Settings the system administrator can change without touching the code."""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Password policy -------------------------------------------------------
PASSWORD_POLICY = {
    "min_length": 10,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_special": True,
    "history": 3,                      # last N passwords that cannot be reused
    "dictionary_file": os.path.join(BASE_DIR, "forbidden_passwords.txt"),
}

# --- Login protection ------------------------------------------------------
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_MINUTES = 15

# --- Password reset --------------------------------------------------------
RESET_CODE_TTL_MINUTES = 15

# --- Database --------------------------------------------------------------
# "sqlite" works out of the box. Set DB_BACKEND=mysql to use MySQL.
DB_BACKEND = os.environ.get("DB_BACKEND", "sqlite")
SQLITE_PATH = os.path.join(BASE_DIR, "comunication.db")
MYSQL = {
    "host": os.environ.get("MYSQL_HOST", "localhost"),
    "user": os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD", ""),
    "database": os.environ.get("MYSQL_DATABASE", "comunication_ltd"),
}

# --- Mail ------------------------------------------------------------------
# Without SMTP_HOST the message is printed and appended to outbox.log.
SMTP = {
    "host": os.environ.get("SMTP_HOST", ""),
    "port": int(os.environ.get("SMTP_PORT", "587")),
    "user": os.environ.get("SMTP_USER", ""),
    "password": os.environ.get("SMTP_PASSWORD", ""),
    "sender": os.environ.get("SMTP_SENDER", "no-reply@comunication-ltd.example"),
}
OUTBOX_PATH = os.path.join(BASE_DIR, "outbox.log")


def load_secret_key():
    """Session signing key: from the environment, else a file created once."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()
