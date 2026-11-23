# Comunication_LTD, part A (INTENTIONALLY VULNERABLE version)

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5001. The database (`comunication.db`, SQLite) is created on first run.

Password reset emails are written to `outbox.log` until SMTP is configured
(`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_SENDER`).

## MySQL

Create the database, then set the environment variables before running:

```sql
CREATE DATABASE comunication_ltd CHARACTER SET utf8mb4;
```

```bash
set DB_BACKEND=mysql
set MYSQL_USER=root
set MYSQL_PASSWORD=...
python app.py
```

## Where things live

| File | Purpose |
|---|---|
| `config.py` | Password policy, login attempts, lockout, DB and mail settings |
| `security.py` | HMAC+Salt hashing, policy check, SHA-1 reset code |
| `db.py` | The only file that runs SQL. Part B's vulnerable build changes only this |
| `app.py` | Routes: register, login, system, change password, forgot password |
| `templates/`, `static/` | The five screens and their design |
| `forbidden_passwords.txt` | Dictionary of banned passwords |

## Part B

Copy this folder to make the vulnerable version. In the copy:

- `db.py`: build queries with string concatenation instead of `?` parameters (SQL injection).
- `templates/system.html`: print customer fields with `|safe` (Stored XSS).
