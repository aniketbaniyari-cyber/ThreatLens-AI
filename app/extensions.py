from flask_sqlalchemy import SQLAlchemy

try:
    from authlib.integrations.flask_client import OAuth
except Exception as exc:
    # Render/production me agar authlib import fail ho raha ho, logs me exact reason chahiye hota hai.
    # Secret/config leak nahi hota, sirf ImportError reason print hota hai.
    import sys
    print(f"[ThreatLens-AI] Authlib import failed: {exc}", file=sys.stderr)
    OAuth = None

db = SQLAlchemy()
oauth = OAuth() if OAuth else None
