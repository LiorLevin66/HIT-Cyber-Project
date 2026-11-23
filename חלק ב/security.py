"""Password hashing, password policy and reset codes."""
import hashlib
import hmac
import secrets
import string

import config

_dictionary_cache = None


def new_salt():
    return secrets.token_hex(16)


def hash_password(password, salt):
    """HMAC-SHA256 with the per-user salt as the key."""
    return hmac.new(bytes.fromhex(salt), password.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_password(password, salt, stored_hash):
    return hmac.compare_digest(hash_password(password, salt), stored_hash)


def _dictionary():
    global _dictionary_cache
    if _dictionary_cache is None:
        try:
            with open(config.PASSWORD_POLICY["dictionary_file"], encoding="utf-8") as f:
                _dictionary_cache = {line.strip().lower() for line in f if line.strip()}
        except FileNotFoundError:
            _dictionary_cache = set()
    return _dictionary_cache


def check_policy(password, username=""):
    """Return a list of problems. An empty list means the password is acceptable."""
    p = config.PASSWORD_POLICY
    problems = []
    if len(password) < p["min_length"]:
        problems.append(f"Use at least {p['min_length']} characters.")
    if p["require_upper"] and not any(c.isupper() for c in password):
        problems.append("Add an uppercase letter.")
    if p["require_lower"] and not any(c.islower() for c in password):
        problems.append("Add a lowercase letter.")
    if p["require_digit"] and not any(c.isdigit() for c in password):
        problems.append("Add a digit.")
    if p["require_special"] and not any(c in string.punctuation for c in password):
        problems.append("Add a special character, such as ! or #.")

    lowered = password.lower()
    if any(word == lowered or (len(word) >= 4 and word in lowered) for word in _dictionary()):
        problems.append("That password contains a common word. Choose something less guessable.")
    if username and username.lower() in lowered:
        problems.append("Don't include your username in the password.")
    return problems


def generate_reset_code():
    """Random value run through SHA-1, as the assignment specifies."""
    return hashlib.sha1(secrets.token_bytes(32)).hexdigest()
