import random
import smtplib
from email.message import EmailMessage

def generate_otp():
    return str(random.randint(100000, 999999))


def send_email(app, to_email, subject, body):
    host = app.config.get("SMTP_HOST")
    user = app.config.get("SMTP_USER")
    password = app.config.get("SMTP_PASS")
    port = app.config.get("SMTP_PORT", 587)
    from_email = app.config.get("SMTP_FROM") or user

    if not host or not user or not password or not from_email:
        return False

    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=5) as smtp:
        smtp.starttls()
        smtp.login(user, password)
        smtp.send_message(msg)
    return True
