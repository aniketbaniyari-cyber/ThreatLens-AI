import time
import xml.etree.ElementTree as ET
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


_CACHE = {"ts": 0.0, "items": []}
_TTL_SEC = 300  # 5 minutes


def _text(node, default=""):
    if node is None:
        return default
    if node.text is None:
        return default
    return node.text.strip()


def _first(el, tags):
    for t in tags:
        found = el.find(t)
        if found is not None:
            return found
    return None


def _parse_rss(root):
    items = []
    channel = root.find("channel")
    source = _text(_first(channel, ["title"]), "RSS") if channel is not None else "RSS"
    if channel is None:
        return items

    for it in channel.findall("item"):
        title = _text(_first(it, ["title"]))
        link = _text(_first(it, ["link"]))
        pub = _text(_first(it, ["pubDate"]), "")
        if title and link:
            items.append({"title": title, "link": link, "published": pub, "source": source})
    return items


def _parse_atom(root):
    items = []
    # Atom me kabhi-kabhi namespaces hote hain; suffix match karke ignore/handle kar rahe hain
    def tag_endswith(el, suffix):
        return el.tag.lower().endswith(suffix)

    source = "Atom"
    for child in list(root):
        if tag_endswith(child, "title"):
            source = _text(child, "Atom")
            break

    for entry in list(root):
        if not tag_endswith(entry, "entry"):
            continue
        title = ""
        link = ""
        published = ""

        for c in list(entry):
            if tag_endswith(c, "title"):
                title = _text(c)
            elif tag_endswith(c, "link"):
                href = c.attrib.get("href", "").strip()
                rel = (c.attrib.get("rel", "") or "").strip().lower()
                if href and (not rel or rel == "alternate") and not link:
                    link = href
            elif tag_endswith(c, "published") or tag_endswith(c, "updated"):
                if not published:
                    published = _text(c)

        if title and link:
            items.append({"title": title, "link": link, "published": published, "source": source})
    return items


def _fetch_feed(url, timeout=4):
    req = Request(url, headers={"User-Agent": "ThreatLens-AI/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return data


def get_cyber_news(feed_urls, limit=20):
    now = time.time()
    if _CACHE["items"] and (now - _CACHE["ts"] < _TTL_SEC):
        return _CACHE["items"][:limit]

    items = []
    for url in feed_urls:
        try:
            data = _fetch_feed(url)
            root = ET.fromstring(data)
            tag = root.tag.lower()
            if tag.endswith("rss"):
                items.extend(_parse_rss(root))
            elif tag.endswith("feed"):
                items.extend(_parse_atom(root))
            else:
                # Fallback me RSS try kar rahe hain
                items.extend(_parse_rss(root))
        except (URLError, HTTPError, TimeoutError, ET.ParseError, ValueError):
            continue

    # Link ke basis par basic de-dupe
    seen = set()
    deduped = []
    for it in items:
        link = it.get("link")
        if not link or link in seen:
            continue
        seen.add(link)
        deduped.append(it)

    _CACHE["ts"] = now
    _CACHE["items"] = deduped
    return deduped[:limit]
