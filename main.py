# main.py - Run the full pipeline
from flags_and_report import flag_bad_ips, print_report, export_to_csv, create_visualizations
from opensearch_query import get_top_talker_ips, get_country_summary
from enrichment import enrich_ip, load_cache, save_cache
import config

def main():
    print("\n🔍 Starting IP Traffic Analyzer...")

    # ── Step 1: Display countries with the highest source-IP traffic ───────────────────
    print("\n📡 Top countries by packet count (source IPs only):")
    country_summary = get_country_summary()
    for iso, name, count in country_summary[:10]:
        print(f"  {iso} ({name}): {count:,} packets")

    # ── Step 2: Pull top IPs for target country ──────────────────────────────
    print(f"\n📥 Pulling top {config.TOP_TALKER_LIMIT} IPs for: "
          f"{config.TARGET_COUNTRY}...")
    ip_list = get_top_talker_ips(
        country_code=config.TARGET_COUNTRY,
        limit=config.TOP_TALKER_LIMIT
    )
    print(f"  Found {len(ip_list)} unique IPs")

    # ── Step 3: Enrich each IP ───────────────────────────────────────────────
    cache = load_cache()
    enriched_results = []
    abuseipdb_calls = 0

    print(f"\n🔎 Enriching IPs "
          f"(AbuseIPDB quota remaining: {config.ABUSEIPDB_DAILY_LIMIT})...")

    for i, ip_record in enumerate(ip_list):
        ip = ip_record["ip"]
        count = ip_record["packet_count"]
        print(f"  [{i+1}/{len(ip_list)}] {ip} ({count} pkts)...", end=" ")

        result, abuseipdb_calls = enrich_ip(ip_record, cache, abuseipdb_calls)
        enriched_results.append(result)

        score_str = str(result.get("abuse_score", "N/A"))
        tags_str = ""
        if result.get("blocklist_tags"):
            tags_str = f" | Tags: {', '.join(result['blocklist_tags'])}"
        print(f"✓ Score: {score_str} | {result.get('category', 'Unknown')}{tags_str}")

        # Save cache every 50 IPs
        if (i + 1) % 50 == 0:
            save_cache(cache)
            print(f"  💾 Cache saved ({i+1} IPs processed)")

    save_cache(cache)
    print(f"\n  Done. AbuseIPDB calls used today: {abuseipdb_calls}")

    # ── Step 4: Flag bad IPs ─────────────────────────────────────────────────
    flagged = flag_bad_ips(enriched_results, target_country=config.TARGET_COUNTRY)
    print(f"\n🚨 {len(flagged)} IPs flagged (score >= {config.ABUSE_SCORE_THRESHOLD})")

    # ── Step 5: Print report + export CSV ────────────────────────────────────
    print_report(enriched_results, flagged, country_code=config.TARGET_COUNTRY)
    export_to_csv(enriched_results, flagged, filename="report.csv")

    # ── Step 6: Generate visualizations ──────────────────────────────────────
    create_visualizations(enriched_results, country_code=config.TARGET_COUNTRY)
    
if __name__ == "__main__":
    main()
