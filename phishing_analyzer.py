"""
Phishing Investigation Tool
----------------------------
What this script does, step by step:

1. Opens a real phishing-email dataset (an .mbox file -- a plain-text file
   that can hold many emails one after another) and reads each email out of it.
2. For each email, pulls out the headers that matter for an investigation:
   who it claims to be from, the Return-Path, the Received chain (the
   "breadcrumb trail" showing which mail servers actually handled the
   message -- this is how you spot a spoofed sender).
3. Extracts Indicators of Compromise (IOCs) from the email body and
   attachments: URLs, the domains/IPs those URLs point to, and SHA-256
   hashes of any attached files.
4. Sends each *unique* IOC to VirusTotal's free API, which checks it against
   dozens of antivirus/security vendors and tells us how many flagged it
   as malicious. Domains and raw IP addresses use different VirusTotal API
   endpoints, so the script detects which kind each one is and routes it
   correctly.
5. Turns those results into a simple risk score per email.
6. Writes a human-readable Markdown report, one section per email, plus a
   CSV of every IOC found -- the kind of output a SOC analyst would
   actually hand to someone else.

Why it's built this way:
- VirusTotal's free tier only allows 4 requests per minute. The script
  respects that by de-duplicating IOCs (never looking the same thing up
  twice) and sleeping between calls, instead of hammering the API and
  getting rate-limited.
- Nothing here guesses at malice from "looks weird" -- the risk score is
  entirely built from VirusTotal's own vendor detection counts, so every
  number in the report can be traced back to a real, external source.
"""

import csv
import hashlib
import ipaddress
import mailbox
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# CONFIGURATION -- edit these for your setup
# ---------------------------------------------------------------------------

# Path to the .mbox file you downloaded from the Nazario Phishing Corpus
MBOX_PATH = "phishing1.mbox"

# How many emails from the mbox file to actually process. VirusTotal's free
# tier is rate-limited (4 requests/minute, 500/day), so start small while
# you're testing, then raise this once you've confirmed it works.
MAX_EMAILS = 20

# ---------------------------------------------------------------------------
# Load the API key from .env (format: VT_API_KEY=your_key_here)
# ---------------------------------------------------------------------------

def load_api_key() -> str:
    env_path = Path(".env")
    if not env_path.exists():
        print("ERROR: .env file not found. Create one with a line like:\nVT_API_KEY=your_key_here")
        sys.exit(1)
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("VT_API_KEY="):
            return line.split("=", 1)[1].strip()
    print("ERROR: VT_API_KEY not found inside .env")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Step 1 & 2: Read the mbox file and pull out header fields
# ---------------------------------------------------------------------------

def extract_headers(msg) -> dict:
    """Pull the fields a SOC analyst actually checks when tracing a sender."""
    received_chain = msg.get_all("Received", [])
    return {
        "subject": msg.get("Subject", "(no subject)"),
        "from": msg.get("From", "(unknown)"),
        "return_path": msg.get("Return-Path", "(none)"),
        "reply_to": msg.get("Reply-To", "(none)"),
        "message_id": msg.get("Message-ID", "(none)"),
        "date": msg.get("Date", "(none)"),
        # The Received chain is listed newest-first by convention; the LAST
        # entry is closest to the true originating server. This is the
        # single most useful field for catching a spoofed "From" address.
        "received_chain": received_chain,
    }


# ---------------------------------------------------------------------------
# Step 3: Extract IOCs -- URLs, domains/IPs, and attachment hashes
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)


def get_body_text(msg) -> str:
    """Walk the email's MIME parts and collect any plain-text/html body."""
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode(errors="replace"))
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                parts.append(payload.decode(errors="replace"))
        except Exception:
            pass
    return "\n".join(parts)


def extract_urls_and_domains(body_text: str) -> tuple[list[str], list[str]]:
    urls = sorted(set(URL_PATTERN.findall(body_text)))
    domains = sorted({urlparse(u).netloc.lower() for u in urls if urlparse(u).netloc})
    return urls, domains


def extract_attachment_hashes(msg) -> list[dict]:
    """Find any attached files and compute their SHA-256 hash.

    A hash is a fixed-length fingerprint of a file's exact contents --
    VirusTotal's database is keyed by file hash, so this lets us check
    "has anyone, anywhere, already seen this exact file and flagged it
    as malware" without ever needing to run the attachment ourselves.
    """
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        sha256 = hashlib.sha256(payload).hexdigest()
        attachments.append({"filename": filename, "sha256": sha256})
    return attachments


# ---------------------------------------------------------------------------
# Step 4: Enrich IOCs against VirusTotal
# ---------------------------------------------------------------------------

VT_BASE = "https://www.virustotal.com/api/v3"


def vt_headers(api_key: str) -> dict:
    return {"x-apikey": api_key}


def vt_lookup_domain(domain: str, api_key: str) -> dict:
    url = f"{VT_BASE}/domains/{domain}"
    resp = requests.get(url, headers=vt_headers(api_key), timeout=15)
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}"}
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return stats


def vt_lookup_ip(ip: str, api_key: str) -> dict:
    """IP addresses use a different VirusTotal endpoint than domains."""
    resp = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=vt_headers(api_key), timeout=15)
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}"}
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return stats


def vt_lookup_url(target_url: str, api_key: str) -> dict:
    # VirusTotal identifies URLs by a URL-safe base64 ID of the URL itself.
    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=vt_headers(api_key), timeout=15)
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}"}
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return stats


def vt_lookup_hash(sha256: str, api_key: str) -> dict:
    resp = requests.get(f"{VT_BASE}/files/{sha256}", headers=vt_headers(api_key), timeout=15)
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}"}
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return stats


# ---------------------------------------------------------------------------
# Step 5: Turn VirusTotal results into a simple risk score
# ---------------------------------------------------------------------------

def score_from_stats(stats: dict) -> float:
    """Very simple scoring: each vendor that flagged this IOC adds 1 point,
    each 'suspicious' verdict adds half a point. This is intentionally
    transparent -- every point in the score is a real vendor detection,
    not a guess."""
    if "error" in stats:
        return 0.0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    return malicious * 1.0 + suspicious * 0.5


def risk_label(score: float) -> str:
    if score >= 5:
        return "HIGH"
    if score >= 1:
        return "MEDIUM"
    return "LOW"


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Main: tie it all together
# ---------------------------------------------------------------------------

def main():
    api_key = load_api_key()

    mbox_path = Path(MBOX_PATH)
    if not mbox_path.exists():
        print(f"ERROR: mbox file not found at {mbox_path.resolve()}")
        sys.exit(1)

    mbox = mailbox.mbox(str(mbox_path))

    # Cache so we never look the same IOC up twice (respects the rate limit
    # and avoids wasting your daily 500-request quota on duplicates).
    domain_cache: dict[str, dict] = {}
    url_cache: dict[str, dict] = {}
    hash_cache: dict[str, dict] = {}

    report_lines = ["# Phishing Investigation Report\n"]
    ioc_csv_rows = [("email_index", "subject", "ioc_type", "ioc_value", "malicious", "suspicious", "score")]

    processed = 0
    for i, msg in enumerate(mbox):
        if processed >= MAX_EMAILS:
            break
        processed += 1

        headers = extract_headers(msg)
        # Skip mbox internal artifacts (e.g. "DON'T DELETE THIS MESSAGE" placeholders)
        if "MAILER-DAEMON" in headers["from"]:
            continue
        body = get_body_text(msg)
        urls, domains = extract_urls_and_domains(body)
        attachments = extract_attachment_hashes(msg)

        report_lines.append(f"## Email {i}: {headers['subject']}\n")
        report_lines.append(f"- **From:** {headers['from']}")
        report_lines.append(f"- **Return-Path:** {headers['return_path']}")
        report_lines.append(f"- **Date:** {headers['date']}")
        report_lines.append(f"- **Message-ID:** {headers['message_id']}")
        if headers["received_chain"]:
            originating = headers["received_chain"][-1]
            report_lines.append(f"- **Originating hop (last Received line):** {originating}")
        report_lines.append("")

        email_score = 0.0
        ioc_findings = []

        for domain in domains:
            if domain not in domain_cache:
                ip = is_ip_address(domain)
                print(f"[VT] Checking {'IP' if ip else 'domain'}: {domain}")
                domain_cache[domain] = vt_lookup_ip(domain, api_key) if ip else vt_lookup_domain(domain, api_key)
                time.sleep(16)  # stay under VT free tier's 4 req/min limit
            stats = domain_cache[domain]
            score = score_from_stats(stats)
            email_score += score
            ioc_findings.append(("ip" if is_ip_address(domain) else "domain", domain, stats, score))

        for url in urls[:3]:  # cap per-email URL checks to conserve quota
            if url not in url_cache:
                print(f"[VT] Checking URL: {url}")
                url_cache[url] = vt_lookup_url(url, api_key)
                time.sleep(16)
            stats = url_cache[url]
            score = score_from_stats(stats)
            email_score += score
            ioc_findings.append(("url", url, stats, score))

        for att in attachments:
            sha = att["sha256"]
            if sha not in hash_cache:
                print(f"[VT] Checking attachment hash: {att['filename']}")
                hash_cache[sha] = vt_lookup_hash(sha, api_key)
                time.sleep(16)
            stats = hash_cache[sha]
            score = score_from_stats(stats)
            email_score += score
            ioc_findings.append(("attachment_sha256", f"{att['filename']} ({sha[:12]}...)", stats, score))

        report_lines.append(f"**Risk score: {email_score:.1f} ({risk_label(email_score)})**\n")
        report_lines.append("| IOC type | Value | Malicious | Suspicious | Score |")
        report_lines.append("|---|---|---|---|---|")
        for ioc_type, value, stats, score in ioc_findings:
            mal = stats.get("malicious", "err") if "error" not in stats else "err"
            sus = stats.get("suspicious", "err") if "error" not in stats else "err"
            report_lines.append(f"| {ioc_type} | {value} | {mal} | {sus} | {score:.1f} |")
            ioc_csv_rows.append((i, headers["subject"], ioc_type, value, mal, sus, score))
        report_lines.append("")

    Path("phishing_report.md").write_text("\n".join(report_lines), encoding="utf-8")
    with open("iocs.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(ioc_csv_rows)

    print(f"\nDone. Processed {processed} email(s).")
    print("Wrote: phishing_report.md")
    print("Wrote: iocs.csv")


if __name__ == "__main__":
    main()
