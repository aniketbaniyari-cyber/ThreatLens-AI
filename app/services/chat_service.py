import re


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def get_faq_reply(message: str) -> str | None:
    """
    Lightweight Q/A bot (koi external API nahi). Reply string return karta hai, warna None.
    """
    m = _norm(message)
    if not m:
        return "Ask a question or paste a URL to analyze."

    # Common intents (common user questions)
    if any(k in m for k in ["how to use", "how do i use", "use this", "kaise use", "kaise", "help"]):
        return (
            "How to use ThreatLens:\n"
            "1) Login (email/password or Google)\n"
            "2) Go to Dashboard\n"
            "3) Paste a URL and click Scan\n"
            "4) Check Risk Score + Security Tips\n"
            "5) Use 'Play AI Voice' for the spoken summary"
        )

    if any(k in m for k in ["voice", "audio", "sound", "bol", "awaaz", "awaz", "speech"]):
        return (
            "Voice troubleshooting:\n"
            "- Use Chrome/Edge\n"
            "- Click the page once (some browsers block auto-play)\n"
            "- Check system volume\n"
            "- Use the 'Voice: EN/HI' toggle on the dashboard"
        )

    if any(k in m for k in ["google login", "gmail", "oauth", "redirect uri", "invalid_client"]):
        return (
            "Google login quick checklist:\n"
            "- OAuth Client type: Web application\n"
            "- Authorized redirect URI:\n"
            "  http://127.0.0.1:5050/auth/google/callback\n"
            "- Use same host everywhere (127.0.0.1 OR localhost)\n"
            "- Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the same terminal before running the server"
        )

    if any(k in m for k in ["dangerous", "suspicious", "safe", "result meaning", "what does it mean"]):
        return (
            "Result meaning:\n"
            "- Safe: low-risk signals (still verify the domain)\n"
            "- Suspicious: some phishing/scam signals (avoid login/OTP)\n"
            "- Dangerous: strong scam/phishing signals (do not open / do not enter credentials)"
        )

    if any(k in m for k in ["location", "ip", "where is this url", "kaha ka", "country"]):
        return (
            "IP/Location info:\n"
            "- We resolve the domain to an IP and fetch approximate geo location.\n"
            "- Sometimes it shows 'Unknown' if the lookup fails or the host is private."
        )

    if any(k in m for k in ["export", "csv", "download history"]):
        return "To export history, click 'Export CSV' on the dashboard (or open /dashboard/export.csv)."

    if any(k in m for k in ["news", "cyber news", "live update"]):
        return "Cyber News Live auto-refreshes every 5 minutes. You can also press Refresh in that section."

    return None
