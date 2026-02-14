import csv
import io
from datetime import datetime
from flask import Blueprint, Response, jsonify, render_template, request, session, redirect
from ..models.scan_model import Scan
from ..services.ip_service import get_url_location
from ..services.news_service import get_cyber_news
from ..routes.scan_routes import normalize_url, calculate_risk, get_result, build_scan_details
from ..services.chat_service import get_faq_reply
import re


dashboard = Blueprint("dashboard", __name__)


@dashboard.route("/news")
def news():
    # Public endpoint theek hai; yeh sirf pre-configured RSS/Atom feeds hi fetch karta hai
    try:
        from flask import current_app
        feeds = current_app.config.get("NEWS_FEEDS", [])
    except Exception:
        feeds = []

    items = get_cyber_news(feeds, limit=25)
    return jsonify({"items": items})


@dashboard.route("/chat", methods=["POST"])
def chat():
    if "user_id" not in session:
        return jsonify({"error": "login_required"}), 401

    payload = request.get_json(silent=True) or {}
    msg = (payload.get("message") or "").strip()
    if not msg:
        return jsonify({"reply": "Send a message or paste a URL to analyze."})

    # Message me se URL-like token extract karne ki koshish
    url_match = re.search(r"(https?://\S+)|([A-Za-z0-9.-]+\.[A-Za-z]{2,}\S*)", msg)
    if url_match:
        raw = url_match.group(0).strip().strip(").,;\"'")
        url = normalize_url(raw)
        risk_score, reasons = calculate_risk(url, raw)
        result = get_result(risk_score)
        details = build_scan_details(url, raw, risk_score, result, reasons)

        tip = {
            "Safe": "Looks relatively safe, but still verify the domain before logging in.",
            "Suspicious": "Be cautious. Avoid logging in, downloading files, or entering OTP/passwords.",
            "Dangerous": "Do not open this link in your main browser. Never enter OTP/password/card details.",
        }.get(result, "Be cautious and verify the domain.")

        reply = (
            f"Result: {result} ({risk_score}%)\n"
            f"Domain: {details.get('domain')} | Scheme: {details.get('scheme')}\n"
            f"Top signals: {', '.join(details.get('risk_reasons', []))}\n"
            f"Advice: {tip}"
        )
        return jsonify({"reply": reply, "analysis": details})

    faq = get_faq_reply(msg)
    if faq:
        return jsonify({"reply": faq})

    return jsonify({"reply": "I can answer questions about the app and analyze URLs. Ask a question or paste a URL."})


@dashboard.route("/dashboard/export.csv")
def export_csv():
    if "user_id" not in session:
        return redirect("/auth/login")

    scans = Scan.query.filter_by(user_id=session["user_id"]).order_by(Scan.created_at.desc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["created_at", "url", "ip", "location", "risk_score", "result"])
    for scan in scans:
        ip_address, location = get_url_location(scan.url)
        writer.writerow([
            scan.created_at.isoformat() if scan.created_at else "",
            scan.url,
            ip_address,
            location,
            scan.risk_score,
            scan.result,
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatlens_scans.csv"},
    )


@dashboard.route("/dashboard")
def dashboard_home():
    if "user_id" not in session:
        return redirect("/auth/login")

    q = (request.args.get("q") or "").strip()
    result_filter = (request.args.get("result") or "").strip()
    try:
        min_risk = int(request.args.get("min_risk") or 0)
    except ValueError:
        min_risk = 0
    try:
        max_risk = int(request.args.get("max_risk") or 100)
    except ValueError:
        max_risk = 100

    query = Scan.query.filter_by(user_id=session["user_id"])
    if q:
        query = query.filter(Scan.url.ilike(f"%{q}%"))
    if result_filter in ("Safe", "Suspicious", "Dangerous"):
        query = query.filter(Scan.result == result_filter)
    query = query.filter(Scan.risk_score >= min_risk, Scan.risk_score <= max_risk)

    scans = query.order_by(Scan.created_at.desc()).all()
    scan_rows = []
    for scan in scans:
        ip_address, location = get_url_location(scan.url)
        scan_rows.append({
            "scan": scan,
            "ip_address": ip_address,
            "location": location,
        })

    total_scans = len(scans)
    safe_count = len([s for s in scans if s.result == "Safe"])
    suspicious_count = total_scans - safe_count

    # Charts ke liye simple daily trend data
    daily = {}
    for s in scans:
        if not s.created_at:
            continue
        day = s.created_at.strftime("%Y-%m-%d")
        daily.setdefault(day, {"count": 0, "avg_risk_sum": 0})
        daily[day]["count"] += 1
        daily[day]["avg_risk_sum"] += int(s.risk_score or 0)

    trend_labels = sorted(daily.keys())
    trend_counts = [daily[d]["count"] for d in trend_labels]
    trend_avg_risk = [
        int(daily[d]["avg_risk_sum"] / daily[d]["count"]) if daily[d]["count"] else 0
        for d in trend_labels
    ]

    last_scan = None
    if "last_scan_result" in session:
        last_url = session.pop("last_scan_url", "")
        last_ip, last_location = get_url_location(last_url)
        details = session.pop("last_scan_details", {})
        last_scan = {
            "url": last_url,
            "result": session.pop("last_scan_result", ""),
            "risk": session.pop("last_scan_risk", 0),
            "ip_address": last_ip,
            "location": last_location,
            "details": details,
        }

    return render_template(
        "dashboard/dashboard.html",
        scans=scans,
        scan_rows=scan_rows,
        total_scans=total_scans,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        username=session.get("username", "User"),
        last_scan=last_scan,
        filters={
            "q": q,
            "result": result_filter,
            "min_risk": min_risk,
            "max_risk": max_risk,
        },
        trend_labels=trend_labels,
        trend_counts=trend_counts,
        trend_avg_risk=trend_avg_risk,
    )
