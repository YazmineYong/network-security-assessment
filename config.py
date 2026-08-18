# config.py - All your settings in one place
# Centralized configuration for the network security assessment tools.

import os

# --- API credentials ---
# Credentials are loaded from environment variables and are not stored
# in the repository.

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


# --- Enrichment thresholds ---
ABUSE_SCORE_THRESHOLD = 25             # flag if score >= this (0-100)
TOP_TALKER_LIMIT = 500                 # how many unique IPs to enrich per run

# --- Country of interest (your "top talker" focus) ---
TARGET_COUNTRY = os.getenv("TARGET_COUNTRY", "US")                 # ISO 2-letter code, e.g. BE = Belgium

# --- Rate limiting ---
ABUSEIPDB_DAILY_LIMIT = 1000           # free tier cap
IPINFO_MONTHLY_LIMIT = 50000
