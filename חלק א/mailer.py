"""Sends mail over SMTP, or writes it to outbox.log when SMTP isn't configured."""
import smtplib
import time
from email.message import EmailMessage

import config


def is_configured():
    return bool(config.SMTP["host"])


def send_mail(to, subject, body):
    if not is_configured():
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{stamp}] To: {to}\nSubject: {subject}\n\n{body}\n{'-' * 60}\n"
        print(entry)
        with open(config.OUTBOX_PATH, "a", encoding="utf-8") as f:
            f.write(entry)
        return

    msg = EmailMessage()
    msg["From"] = config.SMTP["sender"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(config.SMTP["host"], config.SMTP["port"]) as server:
        server.starttls()
        if config.SMTP["user"]:
            server.login(config.SMTP["user"], config.SMTP["password"])
        server.send_message(msg)
