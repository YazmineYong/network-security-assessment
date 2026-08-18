# enrichment.py - Enrich IPs via AbuseIPDB and ipinfo

import requests
import time
import json
import os
import config

CACHE_FILE = "ip_cache.json"

# ── Cache helpers ────────────────────────────────────────────────────────────
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


# ── AbuseIPDB ────────────────────────────────────────────────────────────────
def query_abuseipdb(ip):
    """
    Returns abuse score and report categories.
    Org/ISP info comes from OpenSearch (source.as.full) so we don't waste
    AbuseIPDB quota on data we already have.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()["data"]

        category_map = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
            4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
            7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
            10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
            13: "VPN IP", 14: "Port Scan", 15: "Hacking",
            16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
            19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
            22: "SSH", 23: "IoT Targeted"
        }

        category_ids = set()
        for report in data.get("reports", []):
            for cat_id in report.get("categories", []):
                category_ids.add(cat_id)

        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "usage_type": data.get("usageType", "Unknown"),
            "abuse_categories": [category_map.get(c, f"Category {c}") for c in category_ids],
            "total_reports": data.get("totalReports", 0),
            "source": "abuseipdb"
        }

    except Exception as e:
        print(f"  [AbuseIPDB error for {ip}]: {e}")
        return None


# ── ipinfo fallback ──────────────────────────────────────────────────────────
def query_ipinfo(ip):
    """Fallback to get usage_type when AbuseIPDB quota is exhausted."""
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": config.IPINFO_TOKEN} if config.IPINFO_TOKEN else {}

    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()

        return {
            "abuse_score": None,
            "usage_type": data.get("type", "Unknown"),  # "isp", "hosting", "education" etc.
            "abuse_categories": [],
            "total_reports": None,
            "source": "ipinfo"
        }

    except Exception as e:
        print(f"  [ipinfo error for {ip}]: {e}")
        return None


# ── Classifier ───────────────────────────────────────────────────────────────
def classify_org(org, usage_type):
    """
    Classify an IP into a category using org name (from source.as.full)
    and usage type (from AbuseIPDB or ipinfo).
    Organization keywords used for high-level network classification.
    """
    if not org:
        return "Unknown"

    org_lower = org.lower()
    usage_lower = (usage_type or "").lower()

    if any(k in org_lower for k in ["university", "college", "edu", "academia",
                                     "research", "institute", "school"]):
        return "University / Education"

    if any(k in org_lower for k in ["government", "gov", "ministry",
                                     "federal", "state dept", "department of"]):
        return "Government"

    if any(k in org_lower for k in ["amazon", "aws", "google cloud", "azure",
                                     "digitalocean", "linode", "vultr", "cloudflare",
                                     "fastly", "hetzner", "ovh", "leaseweb",
                                     "choopa", "vultr", "m247"]):
        return "Cloud / Hosting Provider"

    if any(k in usage_lower for k in ["residential", "fixed line"]):
        return "Residential / Home ISP"

    if any(k in usage_lower for k in ["data center", "hosting"]):
        return "Data Center / Hosting"

    if any(k in usage_lower for k in ["mobile", "cellular"]):
        return "Mobile / Cellular"

    if any(k in org_lower for k in ["telecom", "telenet", "proximus", "orange",
                                     "comcast", "at&t", "verizon", "spectrum",
                                     "kpn", "tele2", "ziggo", "xs4all"]):
        return "ISP / Telecom"

    return "Business / Commercial"


# ── Main enrichment entry point ──────────────────────────────────────────────
def enrich_ip(ip_record, cache, abuseipdb_calls_today):
    """
    Enrich a single IP record (dict from opensearch_query).
    Merges AbuseIPDB/ipinfo data with org info already pulled from OpenSearch.
    """
    ip = ip_record["ip"]

    # Return cached result if available
    if ip in cache:
        result = cache[ip]
        result.update({
            "ip": ip,
            "packet_count": ip_record["packet_count"],
            "country_code": ip_record["country_code"],
            "country_name": ip_record["country_name"],
            "blocklist_tags": ip_record["blocklist_tags"]
        })
        return result, abuseipdb_calls_today

    api_result = None

    # Use AbuseIPDB if under daily limit
    if abuseipdb_calls_today < config.ABUSEIPDB_DAILY_LIMIT:
        api_result = query_abuseipdb(ip)
        abuseipdb_calls_today += 1
        time.sleep(0.3)

    # Fallback to ipinfo
    if api_result is None:
        api_result = query_ipinfo(ip)
        time.sleep(0.2)

    if api_result is None:
        api_result = {"abuse_score": None, "usage_type": "Unknown",
                      "abuse_categories": [], "total_reports": None, "source": "none"}

    # Merge with org data already in OpenSearch
    org = ip_record.get("org", "Unknown")
    result = {
        "ip": ip,
        "packet_count": ip_record["packet_count"],
        "country_code": ip_record["country_code"],
        "country_name": ip_record["country_name"],
        "org": org,
        "blocklist_tags": ip_record["blocklist_tags"],
        "abuse_score": api_result["abuse_score"],
        "usage_type": api_result["usage_type"],
        "abuse_categories": api_result["abuse_categories"],
        "total_reports": api_result["total_reports"],
        "source": api_result["source"],
        "category": classify_org(org, api_result["usage_type"])
    }

    # Cache just the API portion (not the per-run packet counts)
    cache[ip] = {k: v for k, v in result.items()
                 if k not in ("packet_count", "ip", "blocklist_tags")}

    return result, abuseipdb_calls_today
