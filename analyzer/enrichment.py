import requests
import base64
import time
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY


# ── VirusTotal ──────────────────────────────────────────────

def vt_scan_url(url: str) -> dict:
    """Submit URL to VirusTotal and return analysis summary."""
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        # Encode URL to base64 (VT requirement)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )

        if resp.status_code == 200:
            data  = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "source":     "VirusTotal",
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "verdict":    "MALICIOUS" if stats.get("malicious", 0) > 0
                              else "SUSPICIOUS" if stats.get("suspicious", 0) > 0
                              else "CLEAN",
            }
        return {"source": "VirusTotal", "error": f"HTTP {resp.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def vt_scan_hash(file_hash: str) -> dict:
    """Check file hash against VirusTotal."""
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "source":    "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "verdict":   "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN",
            }
        return {"source": "VirusTotal", "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


# ── AbuseIPDB ───────────────────────────────────────────────

def abuseipdb_check_ip(ip: str) -> dict:
    """Check IP reputation on AbuseIPDB."""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            return {
                "source":          "AbuseIPDB",
                "abuse_score":     score,
                "total_reports":   data.get("totalReports", 0),
                "country":         data.get("countryCode", "N/A"),
                "isp":             data.get("isp", "N/A"),
                "verdict":         "MALICIOUS" if score > 50
                                   else "SUSPICIOUS" if score > 10
                                   else "CLEAN",
            }
        return {"source": "AbuseIPDB", "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}


# ── URLScan.io ──────────────────────────────────────────────

def urlscan_submit(url: str) -> dict:
    """Submit URL to URLScan.io for scanning."""
    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={
                "API-Key": URLSCAN_API_KEY,
                "Content-Type": "application/json",
            },
            json={"url": url, "visibility": "unlisted"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "source":     "URLScan.io",
                "scan_id":    data.get("uuid"),
                "result_url": data.get("result"),
                "verdict":    "SUBMITTED — check result_url in 30s",
            }
        return {"source": "URLScan.io", "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"source": "URLScan.io", "error": str(e)}


# ── Master Enrichment ───────────────────────────────────────

def enrich_all(iocs: dict) -> dict:
    """Run all IOCs through all APIs. Returns enriched results."""
    enriched = {
        "urls":        [],
        "ips":         [],
        "file_hashes": [],
    }

    # Enrich URLs (limit to 5 to respect free tier rate limits)
    for url in iocs["urls"][:5]:
        result = vt_scan_url(url)
        enriched["urls"].append({"ioc": url, "analysis": result})
        time.sleep(15)  # VT free tier: 4 requests/minute

    # Enrich IPs
    for ip in iocs["ips"][:5]:
        result = abuseipdb_check_ip(ip)
        enriched["ips"].append({"ioc": ip, "analysis": result})
        time.sleep(1)

    # Enrich file hashes
    for att in iocs["attachment_hashes"]:
        if att["sha256"] != "N/A":
            result = vt_scan_hash(att["sha256"])
            enriched["file_hashes"].append({
                "ioc":      att["sha256"],
                "filename": att["filename"],
                "analysis": result,
            })
            time.sleep(15)

    return enriched


def calculate_threat_score(enriched: dict, spoofing_flags: list) -> dict:
    """Calculate overall threat score from all enrichment results."""
    score = 0
    reasons = []

    for item in enriched["urls"]:
        verdict = item["analysis"].get("verdict", "")
        if verdict == "MALICIOUS":
            score += 40
            reasons.append(f"Malicious URL detected: {item['ioc'][:60]}")
        elif verdict == "SUSPICIOUS":
            score += 20
            reasons.append(f"Suspicious URL: {item['ioc'][:60]}")

    for item in enriched["ips"]:
        verdict = item["analysis"].get("verdict", "")
        if verdict == "MALICIOUS":
            score += 30
            reasons.append(f"Malicious IP: {item['ioc']}")
        elif verdict == "SUSPICIOUS":
            score += 15

    for item in enriched["file_hashes"]:
        if item["analysis"].get("verdict") == "MALICIOUS":
            score += 50
            reasons.append(f"Malicious attachment: {item['filename']}")

    score += len(spoofing_flags) * 10
    for flag in spoofing_flags:
        reasons.append(flag)

    score = min(score, 100)

    if score >= 70:
        severity = "🔴 HIGH"
    elif score >= 40:
        severity = "🟡 MEDIUM"
    else:
        severity = "🟢 LOW"

    return {"score": score, "severity": severity, "reasons": reasons}
