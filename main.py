from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import re
import math
from urllib.parse import urlparse
from collections import Counter

app = FastAPI(title="Fake URL Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Suspicious signal lists ──────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "paypal", "amazon", "google", "apple", "microsoft", "netflix", "ebay",
    "password", "credential", "confirm", "wallet", "free", "lucky", "winner",
    "click", "urgent", "alert", "suspended", "limited", "offer", "prize",
]

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "reddit.com", "netflix.com",
    "paypal.com", "ebay.com", "stackoverflow.com", "openai.com",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club", ".work",
    ".click", ".link", ".online", ".site", ".website", ".info", ".biz",
    ".pw", ".men", ".loan", ".win", ".download", ".racing",
]

SAFE_TLDS = [".com", ".org", ".edu", ".gov", ".net", ".io", ".co.uk"]

IP_PATTERN = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
PUNYCODE_PATTERN = re.compile(r"xn--")
HEX_URL_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


# ── Helper functions ─────────────────────────────────────────────────────────

def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def extract_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()

    # Remove port from domain for TLD checks
    domain_no_port = domain.split(":")[0]
    parts = domain_no_port.split(".")
    tld = "." + ".".join(parts[-2:]) if len(parts) >= 2 else ""

    subdomain_count = max(0, len(parts) - 2)

    return {
        "domain": domain_no_port,
        "tld": tld,
        "path": path,
        "full": full,
        "subdomain_count": subdomain_count,
        "url_length": len(url),
        "domain_length": len(domain_no_port),
        "digit_count": sum(c.isdigit() for c in domain_no_port),
        "hyphen_count": domain_no_port.count("-"),
        "dot_count": full.count("."),
        "has_ip": bool(IP_PATTERN.search(domain)),
        "has_at": "@" in url,
        "has_double_slash": "//" in path,
        "has_punycode": bool(PUNYCODE_PATTERN.search(domain)),
        "has_hex": bool(HEX_URL_PATTERN.search(url)),
        "entropy": entropy(domain_no_port),
        "suspicious_kw": [kw for kw in SUSPICIOUS_KEYWORDS if kw in full],
        "is_trusted": any(domain_no_port == td or domain_no_port.endswith("." + td)
                          for td in TRUSTED_DOMAINS),
        "suspicious_tld": any(tld.endswith(st) for st in SUSPICIOUS_TLDS),
        "safe_tld": any(tld.endswith(st) for st in SAFE_TLDS),
    }


# ── Scoring engine ───────────────────────────────────────────────────────────

def score_url(f: dict) -> tuple[int, list[dict]]:
    """Returns (risk_score 0-100, list of signal dicts)."""
    score = 0
    signals = []

    def add(label, detail, pts, positive=False):
        nonlocal score
        score += pts
        signals.append({"label": label, "detail": detail,
                         "points": pts, "positive": positive})

    # Positive signals
    if f["is_trusted"]:
        add("Trusted Domain", f"'{f['domain']}' is a well-known domain", -30, True)
    if f["safe_tld"] and not f["suspicious_tld"]:
        add("Common TLD", f"TLD '{f['tld']}' is common and trusted", -5, True)

    # Negative signals
    if f["has_ip"]:
        add("IP Address Used", "URLs with raw IPs often hide their identity", 25)
    if f["has_at"]:
        add("@ Symbol in URL", "The '@' tricks browsers into ignoring the real domain", 20)
    if f["has_punycode"]:
        add("Punycode / IDN", "Punycode can disguise look-alike characters", 20)
    if f["suspicious_tld"]:
        add("Suspicious TLD", f"'{f['tld']}' is a high-risk top-level domain", 20)
    if f["has_double_slash"]:
        add("Double Slash in Path", "Unusual path structure used in redirects", 15)
    if f["has_hex"]:
        add("Hex Encoding", "Percent-encoding hides URL contents", 10)
    if f["url_length"] > 100:
        add("Very Long URL", f"{f['url_length']} characters — phishing URLs are often inflated", 10)
    elif f["url_length"] > 75:
        add("Long URL", f"{f['url_length']} characters", 5)
    if f["hyphen_count"] >= 3:
        add("Many Hyphens", f"{f['hyphen_count']} hyphens — common in spoofed domains", 10)
    elif f["hyphen_count"] == 2:
        add("Multiple Hyphens", f"{f['hyphen_count']} hyphens in domain", 5)
    if f["digit_count"] >= 4:
        add("High Digit Count", f"{f['digit_count']} digits in domain", 8)
    if f["subdomain_count"] >= 3:
        add("Excessive Subdomains", f"{f['subdomain_count']} subdomain levels", 12)
    elif f["subdomain_count"] == 2:
        add("Multiple Subdomains", f"{f['subdomain_count']} subdomain levels", 6)
    if f["entropy"] > 3.8:
        add("High Entropy Domain", f"Entropy {f['entropy']:.2f} — looks randomly generated", 12)
    if f["suspicious_kw"]:
        kw_list = ", ".join(f["suspicious_kw"][:5])
        add("Suspicious Keywords", f"Found: {kw_list}", min(15, 5 * len(f["suspicious_kw"])))
    if f["dot_count"] > 5:
        add("Too Many Dots", f"{f['dot_count']} dots in URL", 8)

    return max(0, min(100, score)), signals


# ── API models & routes ───────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str


@app.post("/analyze")
def analyze_url(body: URLRequest):
    url = body.url.strip()
    if not url:
        return {"error": "URL cannot be empty"}

    features = extract_features(url)
    risk_score, signals = score_url(features)

    if risk_score <= 15:
        verdict = "Safe"
        verdict_color = "safe"
    elif risk_score <= 40:
        verdict = "Suspicious"
        verdict_color = "suspicious"
    elif risk_score <= 65:
        verdict = "Likely Fake"
        verdict_color = "likely_fake"
    else:
        verdict = "Dangerous"
        verdict_color = "dangerous"

    return {
        "url": url,
        "domain": features["domain"],
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "signals": signals,
        "stats": {
            "url_length": features["url_length"],
            "subdomain_count": features["subdomain_count"],
            "entropy": round(features["entropy"], 2),
            "tld": features["tld"],
        },
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# Serve frontend
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def root():
    return FileResponse("static/index.html")