# flags_and_report.py - Flag bad IPs and generate the report
import matplotlib.pyplot as plt
from collections import defaultdict
import config

def flag_bad_ips(enriched_results, target_country=None):
    flagged = []

    for entry in enriched_results:
        score = entry.get("abuse_score")
        tags = entry.get("blocklist_tags", [])

        if target_country and entry.get("country_code", "").upper() != target_country.upper():
            continue

        score_flagged = score is not None and score >= config.ABUSE_SCORE_THRESHOLD
        blocklist_flagged = any(t in tags for t in ["Dshield", "CINS", "Spamhaus"])

        if score_flagged or blocklist_flagged:
            entry["flag_reasons"] = []
            if score_flagged:
                entry["flag_reasons"].append(f"AbuseIPDB score {score}/100")
            if blocklist_flagged:
                entry["flag_reasons"].append(f"Blocklist tags: {', '.join(tags)}")
            flagged.append(entry)

    flagged.sort(key=lambda x: x.get("abuse_score") or 0, reverse=True)
    return flagged


def build_category_breakdown(enriched_results, country_code=None):
    counts = defaultdict(int)
    for entry in enriched_results:
        if country_code and entry.get("country_code", "").upper() != country_code.upper():
            continue
        cat = entry.get("category", "Unknown")
        counts[cat] += entry.get("packet_count", 1)
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def print_report(enriched_results, flagged, country_code=None):
    country_name = ""
    for e in enriched_results:
        if e.get("country_name"):
            country_name = e["country_name"]
            break
    label = f" ({country_name} / {country_code})" if country_code else ""

    print("\n" + "="*60)
    print(f"  IP TRAFFIC ANALYSIS REPORT{label}")
    print("="*60)

    print(f"\n📊 CATEGORY BREAKDOWN{label}")
    print("-"*40)
    breakdown = build_category_breakdown(enriched_results, country_code)
    total_packets = sum(breakdown.values())
    for cat, count in breakdown.items():
        pct = (count / total_packets * 100) if total_packets else 0
        bar = "█" * int(pct / 2)
        print(f"  {cat:<30} {count:>8} pkts  ({pct:.1f}%) {bar}")

    print(f"\n🚨 FLAGGED IPs (score >= {config.ABUSE_SCORE_THRESHOLD} or on blocklist)")
    print("-"*40)

    if not flagged:
        print("  No flagged IPs found.")
    else:
        for entry in flagged:
            print(f"\n  IP:             {entry['ip']}")
            print(f"  Country:        {entry.get('country_name', '')} ({entry.get('country_code', 'N/A')})")
            print(f"  Score:          {entry.get('abuse_score', 'N/A')}/100")
            print(f"  Org/ASN:        {entry.get('org', 'Unknown')}")
            print(f"  Usage type:     {entry.get('usage_type', 'Unknown')}")
            print(f"  Category:       {entry.get('category', 'Unknown')}")
            print(f"  Packets:        {entry.get('packet_count', 'N/A')}")
            print(f"  Source ports:   {', '.join(entry.get('src_ports', [])) or 'N/A'}")
            print(f"  Dest IPs:       {', '.join(entry.get('dst_ips', [])) or 'N/A'}")
            print(f"  Dest ports:     {', '.join(entry.get('dst_ports', [])) or 'N/A'}")
            print(f"  First seen:     {entry.get('first_seen', 'N/A')}")
            print(f"  Last seen:      {entry.get('last_seen', 'N/A')}")
            print(f"  Index:          {entry.get('index', 'N/A')}")
            reasons = entry.get("abuse_categories", [])
            if reasons:
                print(f"  Reported for:   {', '.join(reasons)}")
            flag_reasons = entry.get("flag_reasons", [])
            if flag_reasons:
                print(f"  Flagged by:     {' | '.join(flag_reasons)}")

    print("\n" + "="*60 + "\n")


def export_to_csv(enriched_results, flagged, filename="report.csv"):
    import csv

    flagged_ips = {e["ip"] for e in flagged}

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "ip", "packet_count", "country_code", "country_name",
            "org", "abuse_score", "usage_type", "category",
            "abuse_categories", "total_reports", "blocklist_tags",
            "src_ports", "dst_ips", "dst_ports",
            "first_seen", "last_seen", "index",
            "source", "flagged", "flag_reasons"
        ])
        writer.writeheader()
        for entry in enriched_results:
            row = dict(entry)
            row["abuse_categories"] = " | ".join(entry.get("abuse_categories", []))
            row["blocklist_tags"]   = " | ".join(entry.get("blocklist_tags", []))
            row["src_ports"]        = " | ".join(entry.get("src_ports", []))
            row["dst_ips"]          = " | ".join(entry.get("dst_ips", []))
            row["dst_ports"]        = " | ".join(entry.get("dst_ports", []))
            row["flag_reasons"]     = " | ".join(entry.get("flag_reasons", []))
            row["flagged"]          = "YES" if entry["ip"] in flagged_ips else ""
            writer.writerow(row)

    print(f"  ✅ Report exported to {filename}")

def create_visualizations(enriched_results, country_code=None):
    """Generates and saves a clean horizontal bar chart of traffic categories."""
    print("\n📊 Generating chart visualizations...")
    
    # Leveraging your existing breakdown helper!
    breakdown = build_category_breakdown(enriched_results, country_code)
    
    if not breakdown:
        print("  ⚠️ No category data found to visualize.")
        return

    # Extract categories and packet counts
    categories = list(breakdown.keys())
    counts = list(breakdown.values())

    # Truncate overly long category names so they don't clip off the image edges
    categories = [cat if len(cat) <= 25 else cat[:22] + "..." for cat in categories]

    # Set up a clean, modern aesthetic style
    plt.style.use('ggplot')
    fig, ax = plt.subplots(figsize=(10, 6))

    # Create a horizontal bar chart (highest volumes at the top)
    # Using a professional dark red/crimson color palette fitting for threat intel
    bars = ax.barh(categories, counts, color='#bc3b3b')
    ax.invert_yaxis()  

    # Titles and axis labeling
    ax.set_title(f"Network Traffic Volume by Traffic Category ({country_code or 'Global'})", fontsize=14, pad=15, weight='bold')
    ax.set_xlabel("Total Packet Count", fontsize=12, labelpad=10)
    ax.set_ylabel("Threat Context / Category", fontsize=12, labelpad=10)

    # Automatically add precise numeric labels to the end of each bar
    for bar in bars:
        width = bar.get_width()
        ax.text(width + (width * 0.01), bar.get_y() + bar.get_height()/2,
                f'{int(width):,}',
                va='center', ha='left', fontsize=9, weight='bold', color='#333333')

    plt.tight_layout()
    
    # Save chart to disk
    output_image = f"abuse_breakdown_{country_code or 'global'}.png"
    plt.savefig(output_image, dpi=300)
    plt.close()
    
    print(f"  ✅ Visual chart saved successfully as: {output_image}")
