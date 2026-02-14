from flask_sqlalchemy import SQLAlchemy

try:
    from authlib.integrations.flask_client import OAuth
except ImportError:
    OAuth = None

db = SQLAlchemy()
oauth = OAuth() if OAuth else None
