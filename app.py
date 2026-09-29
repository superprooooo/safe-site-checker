"""SafeSite - checks a website against public threat databases and warns the user."""
import ipaddress
import os
import re
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

load_dotenv()
app = Flask(__name__)

GOOGLE_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
URLHAUS_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
TIMEOUT = 8
_feed = {"time": 0, "urls": set(), "hosts": set()}  # cached OpenPhish feed


# ---------- Rate limit: protects your free API quota on a public site ----------
RATE_LIMIT, RATE_WINDOW, GLOBAL_LIMIT = 10, 60, 300  # 10 checks/min per visitor, 300/hour overall
_hits, _all = defaultdict(deque), deque()


def rate_limited():
    now = time.time()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    while _all and now - _all[0] > 3600:
        _all.popleft()
    if len(q) >= RATE_LIMIT or len(_all) >= GLOBAL_LIMIT:
        return True
    q.append(now)
    _all.append(now)
    if len(_hits) > 5000:  # tidy memory
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > RATE_WINDOW]:
            del _hits[k]
    return False


def normalize(raw):
    raw = raw.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
    return raw


def host_of(url):
    return (urlparse(url).hostname or "").lower()


# ---------- Database 1: Google Safe Browsing (needs free API key) ----------
def check_google(url):
    if not GOOGLE_KEY:
        return "skipped", "No API key set (optional)"
    body = {
        "client": {"clientId": "safesite", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                      params={"key": GOOGLE_KEY}, json=body, timeout=TIMEOUT)
    r.raise_for_status()
    matches = r.json().get("matches", [])
    if matches:
        kinds = sorted({m["threatType"].replace("_", " ").title() for m in matches})
        return "flagged", "Listed as: " + ", ".join(kinds)
    return "clean", "Not listed"


# ---------- Database 2: URLhaus by abuse.ch (needs free Auth-Key) ----------
def check_urlhaus(url):
    if not URLHAUS_KEY:
        return "skipped", "No API key set (optional)"
    r = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host_of(url)},
                      headers={"Auth-Key": URLHAUS_KEY}, timeout=TIMEOUT)
    r.raise_for_status()
    d = r.json()
    if d.get("query_status") == "ok" and int(d.get("url_count", 0)) > 0:
        return "flagged", f"Host has {d['url_count']} malware URL(s) on record"
    return "clean", "Not listed"


# ---------- Database 3: OpenPhish community feed (no key needed) ----------
def check_openphish(url):
    if time.time() - _feed["time"] > 3600:  # refresh hourly
        r = requests.get("https://openphish.com/feed.txt", timeout=TIMEOUT)
        r.raise_for_status()
        urls = {u.strip().lower().rstrip("/") for u in r.text.splitlines() if u.strip()}
        _feed.update(time=time.time(), urls=urls, hosts={host_of(u) for u in urls})
    bare = urlparse(url).path in ("", "/")
    if url.lower().rstrip("/") in _feed["urls"] or (bare and host_of(url) in _feed["hosts"]):
        return "flagged", "Listed in the OpenPhish phishing feed"
    return "clean", "Not listed"


# ---------- Look-alike brand detection (e.g. "g00gle.com", "paypa1.com") ----------
KNOWN_BRANDS = [
    "google", "youtube", "gmail", "facebook", "instagram", "whatsapp", "amazon",
    "apple", "icloud", "microsoft", "outlook", "office365", "netflix", "paypal",
    "ebay", "linkedin", "twitter", "x", "tiktok", "spotify", "adobe", "dropbox",
    "bankofamerica", "chase", "wellsfargo", "hdfcbank", "icicibank", "sbi",
    "paytm", "phonepe", "irs", "dhl", "fedex", "ups",
]
LOOKALIKE_SUBS = [("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a"), ("$", "s"), ("rn", "m"), ("vv", "w")]


def deleetspeak(s):
    for fake, real in LOOKALIKE_SUBS:
        s = s.replace(fake, real)
    return s


def brand_lookalike(host):
    label = host.split(".")[0]
    if label in KNOWN_BRANDS:
        return None  # it's the real domain's first label; full check below still applies
    plain = re.sub(r"[^a-z0-9]", "", label)
    despoofed = deleetspeak(plain)
    for brand in KNOWN_BRANDS:
        if despoofed == brand and plain != brand:
            return brand
        if brand in despoofed and brand not in plain and len(brand) >= 4:
            return brand
    return None


# ---------- Built-in look-alike / scam heuristics ----------
def heuristics(url):
    host, score, why = host_of(url), 0, []
    fake_brand = brand_lookalike(host)
    if fake_brand:
        score += 4
        why.append(f"Looks like it's imitating \"{fake_brand}\" using look-alike characters")
    try:
        ipaddress.ip_address(host)
        score += 2; why.append("Uses a raw IP address instead of a domain name")
    except ValueError:
        pass
    if urlparse(url).scheme != "https":
        score += 1; why.append("Does not use HTTPS encryption")
    if "@" in url:
        score += 2; why.append("Contains '@', a trick used to hide the real destination")
    if "xn--" in host:
        score += 2; why.append("Uses look-alike (punycode) characters")
    if host.count(".") >= 4:
        score += 1; why.append("Has an unusually long chain of subdomains")
    if len(url) > 100:
        score += 1; why.append("Very long address")
    if host.rsplit(".", 1)[-1] in {"zip", "mov", "tk", "top", "xyz", "click", "gq", "ml", "cf"}:
        score += 1; why.append("Uses a domain ending often abused by scammers")
    if "-" in host and re.search(r"login|verify|secure|account|update|banking|wallet", host):
        score += 1; why.append("Domain mixes hyphens with words like 'login' or 'verify'")
    return score, why


CHECKS = [("Google Safe Browsing", check_google),
          ("URLhaus (malware)", check_urlhaus),
          ("OpenPhish (phishing)", check_openphish)]


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/check")
def api_check():
    if rate_limited():
        return jsonify(error="Too many checks right now. Wait a minute and try again."), 429
    raw = (request.get_json(silent=True) or {}).get("url", "")
    if not raw.strip() or len(raw) > 2000:
        return jsonify(error="Enter a website address, like example.com."), 400
    url = normalize(raw)
    if "." not in host_of(url):
        return jsonify(error="That doesn't look like a valid website address."), 400

    results = []
    for name, fn in CHECKS:
        try:
            status, detail = fn(url)
        except Exception as exc:  # network down, bad key, rate limit...
            status, detail = "error", f"Could not check ({type(exc).__name__})"
        results.append({"name": name, "status": status, "detail": detail})

    score, reasons = heuristics(url)
    flagged = [r for r in results if r["status"] == "flagged"]
    verdict = "dangerous" if flagged else "suspicious" if score >= 3 else "safe"
    return jsonify(url=url, verdict=verdict, checks=results, reasons=reasons,
                   checked=sum(r["status"] in ("clean", "flagged") for r in results))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
