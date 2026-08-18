# opensearch_query.py
# Parse exported OpenSearch network traffic data for analysis.
#
# Expected input: opensearch_export.json
# The export should contain source/destination network information,
# geographic metadata, tags, and timestamps.

import json
import os
from collections import defaultdict

EXPORT_FILE = "opensearch_export.json"


def get_top_talker_ips(country_code=None, limit=500):
    """
    Read raw documents from exported OpenSearch JSON.
    Groups records by source IP, counting occurrences as packet_count.
    Also collects source/dest ports and timestamps per IP.
    """
    if not os.path.exists(EXPORT_FILE):
        print(f"\n  ❌ File not found: {EXPORT_FILE}")
        print("  Please provide an OpenSearch JSON export named opensearch_export.json")
        return []

    with open(EXPORT_FILE, "r") as f:
        data = json.load(f)

    hits = data.get("hits", {}).get("hits", [])

    # Group by source IP
    ip_data = defaultdict(lambda: {
        "packet_count": 0,
        "org": "Unknown",
        "country_code": "",
        "country_name": "",
        "blocklist_tags": set(),
        "src_ports": set(),
        "dst_ips": set(),
        "dst_ports": set(),
        "timestamps": [],
        "index": ""
    })

    for hit in hits:
        src = hit.get("_source", {})
        index = hit.get("_index", "")

        src_ip   = src.get("source", {}).get("ip", "")
        flow     = src.get("suricata", {}).get("flow", {})
        src_port = (src.get("source", {}).get("port", "") or
                    flow.get("src_port", ""))
        dst_ip   = (src.get("destination", {}).get("ip", "") or
                    flow.get("dest_ip", ""))
        dst_port = (src.get("destination", {}).get("port", "") or
                    flow.get("dest_port", ""))
        timestamp = src.get("@timestamp", "")
        tags      = src.get("tags", [])
        org       = src.get("source", {}).get("as", {}).get("full", "Unknown")
        geo       = src.get("source", {}).get("geo", {})
        country_code_val = geo.get("country_iso_code", "")
        country_name     = geo.get("country_name", "")

        if not src_ip:
            continue

        # Filter by country if specified
        if country_code and country_code_val.upper() != country_code.upper():
            continue

        entry = ip_data[src_ip]
        entry["packet_count"] += 1
        entry["org"] = org
        entry["country_code"] = country_code_val
        entry["country_name"] = country_name
        entry["index"] = index
        if src_port:
            entry["src_ports"].add(str(src_port))
        if dst_ip:
            entry["dst_ips"].add(dst_ip)
        if dst_port:
            entry["dst_ports"].add(str(dst_port))
        if timestamp:
            entry["timestamps"].append(timestamp)
        for tag in (tags if isinstance(tags, list) else []):
            entry["blocklist_tags"].add(tag)

    # Convert sets to sorted lists and pick first/last timestamp
    results = []
    for ip, entry in ip_data.items():
        timestamps = sorted(entry["timestamps"])
        results.append({
            "ip": ip,
            "packet_count": entry["packet_count"],
            "org": entry["org"],
            "country_code": entry["country_code"],
            "country_name": entry["country_name"],
            "blocklist_tags": sorted(entry["blocklist_tags"]),
            "src_ports": sorted(entry["src_ports"]),
            "dst_ips": sorted(entry["dst_ips"]),
            "dst_ports": sorted(entry["dst_ports"]),
            "first_seen": timestamps[0] if timestamps else "",
            "last_seen": timestamps[-1] if timestamps else "",
            "index": entry["index"]
        })

    # Sort by packet count descending
    results.sort(key=lambda x: x["packet_count"], reverse=True)
    return results[:limit]


def get_country_summary():
    """
    Derive country summary from the same export file.
    No separate query needed.
    """
    if not os.path.exists(EXPORT_FILE):
        return []

    with open(EXPORT_FILE, "r") as f:
        data = json.load(f)

    hits = data.get("hits", {}).get("hits", [])
    counts = defaultdict(lambda: {"name": "", "count": 0})

    for hit in hits:
        src = hit.get("_source", {})
        geo = src.get("source", {}).get("geo", {})
        code = geo.get("country_iso_code", "Unknown")
        name = geo.get("country_name", code)
        counts[code]["name"] = name
        counts[code]["count"] += 1

    results = [(code, v["name"], v["count"]) for code, v in counts.items()]
    results.sort(key=lambda x: x[2], reverse=True)
    return results
