"""PART B - INTENTIONALLY VULNERABLE BUILD. For the course assignment only.

Same interface as part A's db.py, but queries are built by string
concatenation instead of `?` parameters, so user input is part of the SQL
(SQL injection). Run it on localhost only and never deploy it.
"""
import sqlite3
import time

import config

_MYSQL = config.DB_BACKEND == "mysql"


def _connect():
    if _MYSQL:
        import pymysql
        return pymysql.connect(cursorclass=pymysql.cursors.DictCursor, charset="utf8mb4", **config.MYSQL)
    conn = sqlite3.connect(config.SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _run(sql, params=(), fetch=None):
    if _MYSQL:
        sql = sql.replace("?", "%s")
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        if fetch == "one":
            row = cur.fetchone()
            result = dict(row) if row else None
        elif fetch == "all":
            result = [dict(r) for r in cur.fetchall()]
        else:
            result = cur.lastrowid
        conn.commit()
        return result
    finally:
        conn.close()


def init_db():
    pk = "INT AUTO_INCREMENT PRIMARY KEY" if _MYSQL else "INTEGER PRIMARY KEY AUTOINCREMENT"
    tail = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" if _MYSQL else ""
    statements = [
        f"""CREATE TABLE IF NOT EXISTS users (
            id {pk},
            username VARCHAR(30) NOT NULL UNIQUE,
            email VARCHAR(120) NOT NULL UNIQUE,
            password_hash VARCHAR(64) NOT NULL,
            salt VARCHAR(32) NOT NULL,
            failed_attempts INT NOT NULL DEFAULT 0,
            locked_until BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL
        ){tail}""",
        f"""CREATE TABLE IF NOT EXISTS password_history (
            id {pk},
            user_id INT NOT NULL,
            password_hash VARCHAR(64) NOT NULL,
            salt VARCHAR(32) NOT NULL,
            created_at BIGINT NOT NULL
        ){tail}""",
        f"""CREATE TABLE IF NOT EXISTS reset_codes (
            id {pk},
            user_id INT NOT NULL,
            code VARCHAR(40) NOT NULL,
            expires_at BIGINT NOT NULL,
            used INT NOT NULL DEFAULT 0
        ){tail}""",
        f"""CREATE TABLE IF NOT EXISTS customers (
            id {pk},
            name VARCHAR(120) NOT NULL,
            email VARCHAR(120),
            phone VARCHAR(40),
            address VARCHAR(255),
            created_by INT NOT NULL,
            created_at BIGINT NOT NULL
        ){tail}""",
    ]
    for stmt in statements:
        _run(stmt)


# --- users -----------------------------------------------------------------
def create_user(username, email, password_hash, salt):
    # VULNERABLE: string concatenation (SQL injection)
    user_id = _run(
        "INSERT INTO users (username, email, password_hash, salt, created_at) VALUES ('"
        + username + "', '" + email + "', '" + password_hash + "', '" + salt + "', "
        + str(int(time.time())) + ")"
    )
    add_history(user_id, password_hash, salt)
    return user_id


def get_user_by_username(username):
    # VULNERABLE: string concatenation (SQL injection)
    return _run("SELECT * FROM users WHERE username = '" + username + "'", (), "one")


def get_user_by_email(email):
    # VULNERABLE: string concatenation (SQL injection)
    return _run("SELECT * FROM users WHERE email = '" + email + "'", (), "one")


def get_user_by_id(user_id):
    return _run("SELECT * FROM users WHERE id = " + str(int(user_id)), (), "one")


def set_login_state(user_id, failed_attempts, locked_until):
    _run(
        "UPDATE users SET failed_attempts = " + str(int(failed_attempts))
        + ", locked_until = " + str(int(locked_until)) + " WHERE id = " + str(int(user_id))
    )


# --- passwords -------------------------------------------------------------
def add_history(user_id, password_hash, salt):
    _run(
        "INSERT INTO password_history (user_id, password_hash, salt, created_at) VALUES ("
        + str(int(user_id)) + ", '" + password_hash + "', '" + salt + "', " + str(int(time.time())) + ")"
    )


def get_history(user_id, limit):
    return _run(
        "SELECT password_hash, salt FROM password_history WHERE user_id = " + str(int(user_id))
        + " ORDER BY id DESC LIMIT " + str(int(limit)),
        (),
        "all",
    )


def update_password(user_id, password_hash, salt):
    _run(
        "UPDATE users SET password_hash = '" + password_hash + "', salt = '" + salt
        + "', failed_attempts = 0, locked_until = 0 WHERE id = " + str(int(user_id))
    )
    add_history(user_id, password_hash, salt)


# --- reset codes -----------------------------------------------------------
def save_reset_code(user_id, code, expires_at):
    _run("UPDATE reset_codes SET used = 1 WHERE user_id = " + str(int(user_id)))
    _run(
        "INSERT INTO reset_codes (user_id, code, expires_at) VALUES ("
        + str(int(user_id)) + ", '" + code + "', " + str(int(expires_at)) + ")"
    )


def find_valid_reset_code(user_id, code):
    # VULNERABLE: string concatenation (SQL injection)
    return _run(
        "SELECT * FROM reset_codes WHERE user_id = " + str(int(user_id)) + " AND code = '" + code
        + "' AND used = 0 AND expires_at > " + str(int(time.time())),
        (),
        "one",
    )


def use_reset_code(code_id):
    _run("UPDATE reset_codes SET used = 1 WHERE id = " + str(int(code_id)))


# --- customers -------------------------------------------------------------
def add_customer(name, email, phone, address, created_by):
    # VULNERABLE: string concatenation (SQL injection)
    return _run(
        "INSERT INTO customers (name, email, phone, address, created_by, created_at) VALUES ('"
        + name + "', '" + email + "', '" + phone + "', '" + address + "', "
        + str(int(created_by)) + ", " + str(int(time.time())) + ")"
    )


def list_customers():
    return _run("SELECT * FROM customers ORDER BY id DESC", (), "all")
