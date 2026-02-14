import socket
import json
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

def get_ip_from_url(url):
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.netloc or parsed.path
    domain = (domain or "").strip()
    if not domain:
        return None
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_location_from_ip(ip_address):
    if not ip_address:
        return "Unknown"

    # Basic geolocation ke liye public endpoint (API key ki zaroorat nahi)
    url = f"https://ipapi.co/{ip_address}/json/"
    req = Request(url, headers={"User-Agent": "ThreatLens-AI/1.0"})
    try:
        with urlopen(req, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            city = payload.get("city") or ""
            region = payload.get("region") or ""
            country = payload.get("country_name") or ""
            parts = [part for part in [city, region, country] if part]
            return ", ".join(parts) if parts else "Unknown"
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
        return "Unknown"


def get_url_location(url):
    ip_address = get_ip_from_url(url)
    location = get_location_from_ip(ip_address)
    return ip_address or "N/A", location
