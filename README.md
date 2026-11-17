# Phishing Investigation & IOC Enrichment

A Python tool that investigates real phishing emails the way a SOC analyst would: parse the headers to trace the sender, extract every indicator of compromise (IOCs) from the body and attachments, check each one against VirusTotal's live threat intelligence, score the risk, and produce a report someone else could act on.

This isn't a toy script run against made-up data. It processes real phishing emails from the [Nazario Phishing Corpus](https://monkey.org/~jose/phishing/) — a public dataset of actual phishing campaigns used in security research — and every detection number in the output traces back to a real VirusTotal vendor verdict, not a guess.

## What it does

1. **Parses email headers** — From, Return-Path, Message-ID, and critically the **Received chain**: the list of mail servers that actually handled the message. The "From" field is just text anyone can fake; the Received chain is added by real infrastructure as the email moves, making it the most reliable field for spotting a spoofed sender.
2. **Extracts IOCs** — every URL in the email body, the domains/IPs those URLs point to, and SHA-256 hashes of any attachments (a fingerprint of a file's exact contents, so a known-malicious file can be identified without ever running it).
3. **Enriches against VirusTotal** — each *unique* IOC is checked against dozens of security vendors. Domains and raw IP addresses use different VirusTotal API endpoints, so the script detects which kind each one is and routes it correctly.
4. **Scores risk** — purely from real vendor detection counts (malicious = 1 point, suspicious = 0.5), so every number in the output is traceable to an actual external source, not a heuristic guess.
5. **Writes a report** — a Markdown writeup per email plus a CSV of every IOC, in a format a SOC lead could actually use.

## Why the design choices

- **Rate-limit aware**: VirusTotal's free tier allows 4 requests/minute. The script de-duplicates IOCs (an IP or domain reused across multiple phishing emails only gets checked once) and paces requests to stay within quota, rather than hammering the API and getting blocked.
- **IP vs. domain routing**: an early version sent raw IP addresses to VirusTotal's domain-lookup endpoint and got silent errors back. Fixed by detecting IP-shaped strings (`ipaddress.ip_address()`) and routing them to the correct `/ip_addresses/` endpoint instead.
- **API key kept out of the code**: the key lives in a local `.env` file, excluded from git via `.gitignore`, never hardcoded or committed.

## Sample findings (19 emails processed)

| Email | IOC | Verdict | What it shows |
|---|---|---|---|
| "Important system update" (eBay) | `http://218.94.38.201/ebay/` | 1 malicious, 1 suspicious | Fake eBay login page hosted directly on a raw IP, no domain — still flagged two decades after the original campaign |
| "System maintenance" (fake NCUA) | `http://www.intracon.com/www.ncua.gov/update.php` | 1 malicious | Typosquats a **federal agency** (National Credit Union Administration) by embedding "ncua.gov" inside an unrelated domain's URL path — a classic path-spoofing trick to look legitimate at a glance |
| "SOUTHTRUST BANK - URGENT SECURITY NOTICE" | `http://202.99.223.139/rpm/` | 1 malicious | Raw-IP hosted credential-harvesting page |
| 3 other emails (PayPal/eBay/sweepstakes spoofs) | various IPs/domains | 1 suspicious each | Weaker signal, still real |

**An important honest finding:** most IOCs in this dataset scored `0/0` clean. That's not a failure of the detection logic — this corpus is from **2005**, and the vast majority of that infrastructure (domains, IPs) has been dead, seized, or repurposed for 20 years. VirusTotal reflects the *current* state of the internet, not what these addresses were doing at the time. The IOCs that *did* get flagged are notable precisely because something about them (often raw-IP hosting with no legitimate reuse since) kept them on blocklists this long.

## Running it

```powershell
pip install requests
python phishing_analyzer.py
```

Requires a free VirusTotal API key (no credit card needed) in a local `.env` file:
```
VT_API_KEY=your_key_here
```

## Skills demonstrated

- Email header forensics (sender tracing via Received chain vs. the spoofable From field)
- IOC extraction from unstructured data (regex-based URL/domain parsing, MIME attachment handling)
- Threat intelligence API integration (VirusTotal v3, correct endpoint routing by IOC type)
- Rate-limit-aware, quota-conscious API design
- Transparent, source-traceable risk scoring (no unexplainable "AI judgment" — every point maps to a real vendor verdict)
- Secrets management (API key kept out of version control)

## Files

- `phishing_analyzer.py` — the full script
- `phishing_report.md` — generated investigation report
- `iocs.csv` — every IOC found, structured for further analysis
