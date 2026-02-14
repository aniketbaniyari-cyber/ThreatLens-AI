from ..extensions import db
from datetime import datetime


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    result = db.Column(db.String(50), nullable=False, default="pending")

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
