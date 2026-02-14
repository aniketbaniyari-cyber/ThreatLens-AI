import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

    _db_url = os.getenv("DATABASE_URL") or os.getenv("SQLALCHEMY_DATABASE_URI") or ""
    # Kuch providers postgres:// use karte hain; SQLAlchemy ko postgresql:// chahiye hota hai
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = _db_url or "sqlite:///database.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Local dev me False rakho; production me HTTPS ke saath True karo
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)

    # Env me comma-separated list dekar override kar sakte ho, warna defaults use honge
    NEWS_FEEDS = [
        u.strip()
        for u in (os.getenv("NEWS_FEEDS", "") or "").split(",")
        if u.strip()
    ] or [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://www.securityweek.com/feed/",
        "https://www.cisa.gov/uscert/ncas/alerts.xml",
    ]
