import time
from flask import Blueprint, current_app, request, redirect, session
from ..models.scan_model import Scan
from ..extensions import db
from ..services.email_service import send_email
from urllib.parse import urlparse
import ipaddress
import re

scan = Blueprint("scan", __name__)

_scan_events = {}
_SCAN_LIMIT = 10
_SCAN_WINDOW_SEC = 60


def rate_limit_ok(user_id):
    now = time.time()
    key = str(user_id)
    events = _scan_events.get(key, [])
    events = [t for t in events if now - t < _SCAN_WINDOW_SEC]
    if len(events) >= _SCAN_LIMIT:
        _scan_events[key] = events
        return False, int(_SCAN_WINDOW_SEC - (now - events[0]))
    events.append(now)
    _scan_events[key] = events
    return True, 0


def normalize_url(url):
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not re.match(r"^https?://", cleaned, re.IGNORECASE):
        cleaned = f"https://{cleaned}"
    return cleaned


def calculate_risk(url, raw_input=""):
    risk = 0
    reasons = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    raw = (raw_input or "").strip().lower()

    if raw and not re.match(r"^https?://", raw, re.IGNORECASE):
        risk += 10
        reasons.append("URL entered without http/https scheme")

    # Length check (URL lamba hai to risk badhta hai)
    if len(url) > 50:
        risk += 10
        reasons.append("Long URL length")
    if len(url) > 100:
        risk += 20
        reasons.append("Very long URL length")

    # @ symbol (at-sign ka use)
    if "@" in url:
        risk += 25
        reasons.append("@ symbol found in URL")

    # Suspicious keywords (phishing/scam hints)
    suspicious_keywords = [
        "login",
        "verify",
        "update",
        "bank",
        "secure",
        "account",
        "reset",
        "wallet",
        "signin",
        "confirm",
    ]
    keyword_hits = 0
    for word in suspicious_keywords:
        if word in url.lower():
            keyword_hits += 1
    risk += min(keyword_hits * 15, 45)
    if keyword_hits:
        reasons.append(f"Suspicious keywords detected ({keyword_hits})")

    # Too many dots (zyada subdomains)
    if host.count(".") > 3:
        risk += 10
        reasons.append("Too many subdomains/dots in hostname")

    # Raw IP host (domain ki jagah direct IP)
    try:
        ipaddress.ip_address(host)
        risk += 45
        reasons.append("IP address used instead of domain")
    except ValueError:
        pass

    # Punycode domains often homograph attacks me use hote hain
    if "xn--" in host:
        risk += 30
        reasons.append("Punycode domain detected")

    # Unusual port aur bahut lambi query string risk badhati hai
    if parsed.port and parsed.port not in (80, 443):
        risk += 15
        reasons.append("Unusual port in URL")
    if len(query) > 80:
        risk += 10
        reasons.append("Very long query string")

    # URL shorteners destination hide kar dete hain
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
    if host.lower() in shorteners:
        risk += 20
        reasons.append("URL shortener domain used")

    # Encoded characters aur suspicious path tokens (phishing ka hint ho sakta hai)
    if "%40" in url.lower() or "%2f" in url.lower():
        risk += 10
        reasons.append("Encoded characters found in URL")
    if any(token in path.lower() for token in ["/wp-admin", "/signin", "/verify", "/update"]):
        risk += 10
        reasons.append("Sensitive path pattern detected")

    # Host-level extra risk signals
    if host.count("-") >= 2:
        risk += 10
        reasons.append("Hostname contains many hyphens")
    digit_count = sum(1 for c in host if c.isdigit())
    if digit_count >= 6:
        risk += 10
        reasons.append("Hostname contains many digits")

    risky_tlds = (".xyz", ".top", ".click", ".gq", ".tk", ".work", ".zip", ".rest")
    if any(host.lower().endswith(tld) for tld in risky_tlds):
        risk += 15
        reasons.append("Risky top-level domain detected")

    # HTTPS nahi hai to risk
    if parsed.scheme == "http":
        risk += 25
        reasons.append("Uses HTTP instead of HTTPS")
    elif parsed.scheme != "https":
        risk += 15
        reasons.append("Non-standard URL scheme")

    return min(risk, 100), reasons


def get_result(risk):
    if risk < 25:
        return "Safe"
    elif risk < 60:
        return "Suspicious"
    else:
        return "Dangerous"


def build_scan_details(url, raw_input, risk_score, result, reasons):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    query = parsed.query or ""
    is_ip_host = False
    try:
        ipaddress.ip_address(host)
        is_ip_host = True
    except ValueError:
        pass

    tld = ""
    if "." in host and not is_ip_host:
        tld = "." + host.split(".")[-1]

    key_reasons = reasons[:4] if reasons else ["No suspicious pattern detected"]
    voice_text = (
        f"Scan completed. Result is {result}. Risk score is {risk_score} percent. "
        f"Domain is {host or 'unknown'}. "
        f"Top risk signals: {', '.join(key_reasons)}."
    )

    return {
        "raw_input": (raw_input or "").strip(),
        "normalized_url": url,
        "scheme": parsed.scheme or "unknown",
        "domain": host or "unknown",
        "tld": tld or "unknown",
        "path": path,
        "query_length": len(query),
        "has_query": bool(query),
        "port": parsed.port or "default",
        "uses_https": parsed.scheme == "https",
        "is_ip_host": is_ip_host,
        "url_length": len(url),
        "risk_reasons": key_reasons,
        "voice_text": voice_text,
    }


@scan.route("/scan", methods=["POST"])
def scan_url():
    if "user_id" not in session:
        return redirect("/auth/login")

    ok, retry_after = rate_limit_ok(session["user_id"])
    if not ok:
        return f"Rate limit exceeded. Try again in {retry_after} seconds."

    raw_url = request.form.get("url", "")
    url = normalize_url(raw_url)
    if not url:
        return redirect("/dashboard")

    risk_score, reasons = calculate_risk(url, raw_url)
    result = get_result(risk_score)
    details = build_scan_details(url, raw_url, risk_score, result, reasons)

    new_scan = Scan(
        url=url,
        risk_score=risk_score,
        result=result,
        user_id=session["user_id"]
    )

    db.session.add(new_scan)
    db.session.commit()

    session["last_scan_url"] = url
    session["last_scan_result"] = result
    session["last_scan_risk"] = risk_score
    session["last_scan_details"] = details

    # Optional email alert: Dangerous scans pe (SMTP_* config required)
    if result == "Dangerous":
        subject = "ThreatLens Alert: Dangerous URL detected"
        body = f"URL: {url}\nRisk: {risk_score}%\nSignals: {', '.join(details.get('risk_reasons', []))}\n"
        try:
            send_email(current_app, session.get("username", ""), subject, body)
        except Exception:
            pass

    return redirect("/dashboard")
