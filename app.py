import os
import csv
import io
import json
import traceback
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, Response
from analyzer.email_parser   import parse_email
from analyzer.ioc_extractor  import extract_all_iocs
from analyzer.enrichment     import enrich_all, calculate_threat_score

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("reports/samples", exist_ok=True)

IST = timezone(timedelta(hours=5, minutes=30))


# ─────────────────────────────────────────────
#  CSV EXPORT ENDPOINT
# ─────────────────────────────────────────────
@app.route("/export/csv", methods=["POST"])
def export_csv():
    try:
        data     = request.get_json()
        parsed   = data.get("parsed", {})
        iocs     = data.get("iocs", {})
        enriched = data.get("enriched", {})
        threat   = data.get("threat", {})
        headers  = parsed.get("headers", {})

        output = io.StringIO()
        writer = csv.writer(output)

        # ── SECTION 1: Report Metadata ──
        writer.writerow(["=== PHISHING TRIAGE REPORT ==="])
        writer.writerow(["Generated",    datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")])
        writer.writerow(["File",         parsed.get("file", "N/A")])
        writer.writerow(["Threat Score", str(threat.get("score", 0)) + "/100"])
        writer.writerow(["Severity",     threat.get("severity", "N/A")])
        writer.writerow([])

        # ── SECTION 2: Threat Reasons ──
        writer.writerow(["=== THREAT INDICATORS ==="])
        writer.writerow(["#", "Reason"])
        reasons = threat.get("reasons", [])
        if reasons:
            for i, r in enumerate(reasons, 1):
                writer.writerow([i, r])
        else:
            writer.writerow(["—", "No threat indicators found"])
        writer.writerow([])

        # ── SECTION 3: Email Headers ──
        writer.writerow(["=== EMAIL HEADERS ==="])
        writer.writerow(["Field", "Value"])
        for field, value in [
            ("Subject",          headers.get("subject",          "N/A")),
            ("From",             headers.get("from",             "N/A")),
            ("Reply-To",         headers.get("reply_to",         "N/A")),
            ("Return-Path",      headers.get("return_path",      "N/A")),
            ("Date",             headers.get("date",             "N/A")),
            ("Message-ID",       headers.get("message_id",       "N/A")),
            ("SPF",              headers.get("spf",              "N/A")),
            ("DKIM",             "Present" if headers.get("dkim") and headers.get("dkim") != "N/A" else "Not found"),
            ("DMARC",            headers.get("dmarc",            "N/A")),
            ("X-Originating-IP", headers.get("x_originating_ip","N/A")),
        ]:
            writer.writerow([field, str(value)])
        writer.writerow([])

        # ── SECTION 4: Spoofing Flags ──
        writer.writerow(["=== SPOOFING INDICATORS ==="])
        writer.writerow(["#", "Flag"])
        flags = parsed.get("spoofing_flags", [])
        if flags:
            for i, f in enumerate(flags, 1):
                writer.writerow([i, f])
        else:
            writer.writerow(["—", "No spoofing indicators detected"])
        writer.writerow([])

        # ── SECTION 5: Extracted IOCs ──
        writer.writerow(["=== EXTRACTED IOCs ==="])
        writer.writerow(["Type", "Value"])
        for url    in iocs.get("urls",    []): writer.writerow(["URL",           url])
        for ip     in iocs.get("ips",     []): writer.writerow(["IP",            ip])
        for domain in iocs.get("domains", []): writer.writerow(["Domain",        domain])
        for email  in iocs.get("emails",  []): writer.writerow(["Email Address", email])
        for att in iocs.get("attachment_hashes", []):
            writer.writerow(["Attachment MD5",    att.get("filename","?") + " — " + att.get("md5","N/A")])
            writer.writerow(["Attachment SHA256", att.get("filename","?") + " — " + att.get("sha256","N/A")])
        if not any([iocs.get("urls"), iocs.get("ips"), iocs.get("domains"),
                    iocs.get("emails"), iocs.get("attachment_hashes")]):
            writer.writerow(["—", "No IOCs found"])
        writer.writerow([])

        # ── SECTION 6: URL Enrichment ──
        writer.writerow(["=== URL ENRICHMENT (VirusTotal) ==="])
        writer.writerow(["URL", "Malicious Detections", "Suspicious Detections", "Harmless", "Verdict"])
        url_enriched = enriched.get("urls", [])
        if url_enriched:
            for item in url_enriched:
                a = item.get("analysis", {})
                writer.writerow([item.get("ioc","N/A"), a.get("malicious","N/A"),
                                  a.get("suspicious","N/A"), a.get("harmless","N/A"), a.get("verdict","N/A")])
        else:
            writer.writerow(["—","—","—","—","No URLs enriched"])
        writer.writerow([])

        # ── SECTION 7: IP Enrichment ──
        writer.writerow(["=== IP REPUTATION (AbuseIPDB) ==="])
        writer.writerow(["IP Address", "Abuse Score", "Total Reports", "Country", "ISP", "Verdict"])
        ip_enriched = enriched.get("ips", [])
        if ip_enriched:
            for item in ip_enriched:
                a = item.get("analysis", {})
                writer.writerow([item.get("ioc","N/A"), a.get("abuse_score","N/A"), a.get("total_reports","N/A"),
                                  a.get("country","N/A"), a.get("isp","N/A"), a.get("verdict","N/A")])
        else:
            writer.writerow(["—","—","—","—","—","No IPs enriched"])
        writer.writerow([])

        # ── SECTION 8: File Hash Enrichment ──
        writer.writerow(["=== ATTACHMENT ANALYSIS (VirusTotal) ==="])
        writer.writerow(["Filename", "SHA256", "Verdict"])
        hash_enriched = enriched.get("file_hashes", [])
        if hash_enriched:
            for item in hash_enriched:
                a = item.get("analysis", {})
                writer.writerow([item.get("filename","N/A"), item.get("ioc","N/A"), a.get("verdict","N/A")])
        else:
            writer.writerow(["—","—","No attachments found"])
        writer.writerow([])

        # ── SECTION 9: MITRE ATT&CK ──
        writer.writerow(["=== MITRE ATT&CK MAPPING ==="])
        writer.writerow(["Technique ID", "Name", "Tactic", "Observed"])
        writer.writerow(["T1566", "Phishing",                "Initial Access", "Suspicious email received"])
        writer.writerow(["T1598", "Phishing for Information", "Reconnaissance", "Credential harvesting indicators"])
        writer.writerow(["T1204", "User Execution",           "Execution",      "Malicious links/attachments present"])
        writer.writerow([])

        # ── SECTION 10: Analyst Recommendation ──
        writer.writerow(["=== ANALYST RECOMMENDATION ==="])
        score = threat.get("score", 0)
        if score >= 70:
            writer.writerow(["Action",  "BLOCK & ESCALATE"])
            writer.writerow(["Details", "High-confidence phishing. Quarantine email, block sender domain, escalate to Tier-2."])
        elif score >= 40:
            writer.writerow(["Action",  "INVESTIGATE FURTHER"])
            writer.writerow(["Details", "Suspicious indicators. Manual header review and sender verification recommended."])
        else:
            writer.writerow(["Action",  "MONITOR"])
            writer.writerow(["Details", "Low threat score. Log IOCs, add to watchlist, monitor for similar activity."])

        output.seek(0)
        filename = f"phishing_triage_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  MAIN DASHBOARD
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Phishing Triage | Vatsal Sapovadiya</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#020408; --bg2:#050d14; --bg3:#0a1628;
  --cyan:#00f5ff; --cyan2:#00bcd4;
  --green:#00ff88; --red:#ff2d55; --yellow:#ffd60a;
  --border:rgba(0,245,255,0.15); --border2:rgba(0,245,255,0.08);
  --text:#b0c4d8; --text2:#5a7a8a;
  --glow:0 0 20px rgba(0,245,255,0.3); --glow2:0 0 40px rgba(0,245,255,0.15);
}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;min-height:100vh;overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,245,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,245,255,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.08) 2px,rgba(0,0,0,0.08) 4px);pointer-events:none;z-index:1;}
.container{position:relative;z-index:2;max-width:1400px;margin:0 auto;padding:0 24px;}
header{border-bottom:1px solid var(--border);background:linear-gradient(180deg,rgba(0,245,255,0.04) 0%,transparent 100%);padding:16px 0;position:sticky;top:0;backdrop-filter:blur(20px);z-index:100;}
.header-inner{display:flex;align-items:center;justify-content:space-between;}
.logo{display:flex;align-items:center;gap:12px;}
.logo-icon{width:40px;height:40px;border:2px solid var(--cyan);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;animation:pulse-border 2s ease-in-out infinite;}
@keyframes pulse-border{0%,100%{box-shadow:0 0 10px rgba(0,245,255,0.3);}50%{box-shadow:0 0 25px rgba(0,245,255,0.7);}}
.logo-text{font-family:'Orbitron',monospace;font-size:14px;font-weight:700;color:var(--cyan);letter-spacing:2px;}
.logo-sub{font-size:10px;color:var(--text2);letter-spacing:1px;}
.header-status{display:flex;align-items:center;gap:20px;}
.status-dot{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2);}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 1.5s ease-in-out infinite;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:0.3;}}
.time-display{font-family:'Orbitron',monospace;font-size:12px;color:var(--cyan2);letter-spacing:1px;}
.hero{padding:60px 0 40px;text-align:center;}
.hero-title{font-family:'Orbitron',monospace;font-size:clamp(28px,5vw,52px);font-weight:900;color:var(--cyan);letter-spacing:4px;text-shadow:0 0 30px rgba(0,245,255,0.5);margin-bottom:8px;}
.hero-sub{font-size:13px;color:var(--text2);letter-spacing:3px;text-transform:uppercase;margin-bottom:50px;}
.upload-zone{background:linear-gradient(135deg,rgba(0,245,255,0.03) 0%,rgba(0,0,0,0) 100%);border:2px dashed var(--border);border-radius:16px;padding:50px 40px;max-width:600px;margin:0 auto 40px;cursor:pointer;transition:all 0.3s;position:relative;overflow:hidden;}
.upload-zone:hover,.upload-zone.dragover{border-color:var(--cyan);box-shadow:var(--glow),inset 0 0 30px rgba(0,245,255,0.05);}
.upload-icon{font-size:48px;margin-bottom:16px;display:block;filter:drop-shadow(0 0 12px rgba(0,245,255,0.6));}
.upload-title{font-family:'Orbitron',monospace;font-size:14px;color:var(--cyan);letter-spacing:2px;margin-bottom:8px;}
.upload-sub{font-size:12px;color:var(--text2);margin-bottom:20px;}
.file-input{display:none;}
.file-label{display:inline-block;background:transparent;border:1px solid var(--cyan);color:var(--cyan);padding:8px 24px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:12px;cursor:pointer;letter-spacing:1px;transition:all 0.2s;}
.file-label:hover{background:rgba(0,245,255,0.1);box-shadow:var(--glow);}
.file-selected{margin-top:16px;font-size:12px;color:var(--green);display:none;}
.analyze-btn{display:block;width:100%;max-width:600px;margin:0 auto;background:linear-gradient(135deg,rgba(0,245,255,0.15) 0%,rgba(0,188,212,0.1) 100%);border:1px solid var(--cyan);color:var(--cyan);padding:16px;border-radius:8px;font-family:'Orbitron',monospace;font-size:14px;font-weight:700;letter-spacing:3px;cursor:pointer;transition:all 0.3s;text-transform:uppercase;box-shadow:var(--glow2);}
.analyze-btn:hover:not(:disabled){background:linear-gradient(135deg,rgba(0,245,255,0.25) 0%,rgba(0,188,212,0.2) 100%);box-shadow:var(--glow);transform:translateY(-1px);}
.analyze-btn:disabled{opacity:0.5;cursor:not-allowed;}
#loading-section{display:none;max-width:600px;margin:30px auto;}
.terminal{background:#000d1a;border:1px solid var(--border);border-radius:8px;overflow:hidden;}
.terminal-header{background:rgba(0,245,255,0.05);border-bottom:1px solid var(--border);padding:10px 16px;display:flex;align-items:center;gap:8px;}
.terminal-dot{width:10px;height:10px;border-radius:50%;}
.t-red{background:#ff5f57;}.t-yellow{background:#febc2e;}.t-green{background:#28c840;}
.terminal-title{margin-left:8px;font-size:11px;color:var(--text2);letter-spacing:1px;}
.terminal-body{padding:20px;font-size:12px;line-height:1.8;min-height:160px;}
.t-line{color:var(--text2);opacity:0;animation:fadein 0.3s forwards;}
.t-line.cyan{color:var(--cyan);}.t-line.green{color:var(--green);}.t-line.yellow{color:var(--yellow);}.t-line.red{color:var(--red);}
@keyframes fadein{to{opacity:1;}}
.cursor{display:inline-block;width:8px;height:14px;background:var(--cyan);vertical-align:middle;animation:blink 0.8s step-end infinite;}
#results-section{display:none;padding:20px 0 60px;}
.threat-banner{border-radius:12px;padding:30px 40px;margin-bottom:30px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;border:1px solid;position:relative;overflow:hidden;}
.threat-banner::before{content:'';position:absolute;inset:0;opacity:0.04;}
.threat-banner.high{border-color:var(--red);background:rgba(255,45,85,0.08);}
.threat-banner.high::before{background:var(--red);}
.threat-banner.medium{border-color:var(--yellow);background:rgba(255,214,10,0.06);}
.threat-banner.medium::before{background:var(--yellow);}
.threat-banner.low{border-color:var(--green);background:rgba(0,255,136,0.06);}
.threat-banner.low::before{background:var(--green);}
.threat-left{display:flex;align-items:center;gap:24px;}
.threat-icon{font-size:48px;}
.threat-label{font-family:'Orbitron',monospace;font-size:11px;letter-spacing:3px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;}
.threat-severity{font-family:'Orbitron',monospace;font-size:28px;font-weight:900;letter-spacing:2px;}
.threat-banner.high .threat-severity{color:var(--red);text-shadow:0 0 20px rgba(255,45,85,0.5);}
.threat-banner.medium .threat-severity{color:var(--yellow);text-shadow:0 0 20px rgba(255,214,10,0.5);}
.threat-banner.low .threat-severity{color:var(--green);text-shadow:0 0 20px rgba(0,255,136,0.5);}
.score-meter{text-align:right;min-width:200px;}
.score-number{font-family:'Orbitron',monospace;font-size:52px;font-weight:900;line-height:1;margin-bottom:8px;}
.threat-banner.high .score-number{color:var(--red);}
.threat-banner.medium .score-number{color:var(--yellow);}
.threat-banner.low .score-number{color:var(--green);}
.meter-bar{width:100%;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden;}
.meter-fill{height:100%;border-radius:3px;transition:width 1.5s cubic-bezier(0.4,0,0.2,1);width:0%;}
.threat-banner.high .meter-fill{background:var(--red);box-shadow:0 0 10px var(--red);}
.threat-banner.medium .meter-fill{background:var(--yellow);box-shadow:0 0 10px var(--yellow);}
.threat-banner.low .meter-fill{background:var(--green);box-shadow:0 0 10px var(--green);}
.score-label{font-size:10px;color:var(--text2);letter-spacing:1px;margin-top:4px;text-align:right;}
.reasons-list{margin-top:16px;}
.reason-item{font-size:12px;padding:6px 12px;border-left:3px solid;margin-bottom:6px;background:rgba(0,0,0,0.3);border-radius:0 4px 4px 0;}
.reason-item.high{border-color:var(--red);color:#ff8099;}
.reason-item.medium{border-color:var(--yellow);color:#ffe566;}
.reason-item.low{border-color:var(--green);color:#66ffaa;}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:30px;}
.stat-card{background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:20px;text-align:center;transition:all 0.3s;position:relative;overflow:hidden;}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--cyan);opacity:0.5;}
.stat-card:hover{border-color:var(--border);transform:translateY(-2px);box-shadow:var(--glow2);}
.stat-number{font-family:'Orbitron',monospace;font-size:32px;font-weight:700;color:var(--cyan);text-shadow:0 0 15px rgba(0,245,255,0.4);}
.stat-label{font-size:10px;color:var(--text2);letter-spacing:2px;text-transform:uppercase;margin-top:4px;}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;}
@media(max-width:900px){.grid-2{grid-template-columns:1fr;}}
.card{background:var(--bg2);border:1px solid var(--border2);border-radius:10px;overflow:hidden;transition:border-color 0.3s;}
.card:hover{border-color:var(--border);}
.card-header{background:rgba(0,245,255,0.03);border-bottom:1px solid var(--border2);padding:14px 20px;display:flex;align-items:center;justify-content:space-between;}
.card-title{font-family:'Orbitron',monospace;font-size:11px;color:var(--cyan);letter-spacing:2px;text-transform:uppercase;}
.card-badge{font-size:10px;padding:3px 8px;border-radius:3px;background:rgba(0,245,255,0.1);color:var(--cyan2);border:1px solid rgba(0,245,255,0.2);}
.card-body{padding:16px 20px;}
.data-table{width:100%;border-collapse:collapse;font-size:12px;}
.data-table th{text-align:left;padding:8px 12px;color:var(--text2);font-size:10px;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid var(--border2);background:rgba(0,0,0,0.2);}
.data-table td{padding:10px 12px;border-bottom:1px solid var(--border2);color:var(--text);word-break:break-all;vertical-align:top;}
.data-table tr:last-child td{border-bottom:none;}
.data-table tr:hover td{background:rgba(0,245,255,0.03);}
.ioc-badge{display:inline-block;font-size:9px;padding:2px 6px;border-radius:3px;letter-spacing:1px;text-transform:uppercase;font-weight:bold;}
.ioc-url{background:rgba(0,245,255,0.1);color:var(--cyan);border:1px solid rgba(0,245,255,0.2);}
.ioc-ip{background:rgba(255,214,10,0.1);color:var(--yellow);border:1px solid rgba(255,214,10,0.2);}
.ioc-domain{background:rgba(0,255,136,0.1);color:var(--green);border:1px solid rgba(0,255,136,0.2);}
.ioc-email{background:rgba(200,130,255,0.1);color:#c882ff;border:1px solid rgba(200,130,255,0.2);}
.verdict{display:inline-block;font-size:10px;padding:3px 10px;border-radius:12px;font-weight:bold;letter-spacing:1px;white-space:nowrap;}
.verdict-malicious{background:rgba(255,45,85,0.15);color:var(--red);border:1px solid rgba(255,45,85,0.3);}
.verdict-suspicious{background:rgba(255,214,10,0.15);color:var(--yellow);border:1px solid rgba(255,214,10,0.3);}
.verdict-clean{background:rgba(0,255,136,0.15);color:var(--green);border:1px solid rgba(0,255,136,0.3);}
.verdict-na{background:rgba(90,122,138,0.15);color:var(--text2);border:1px solid rgba(90,122,138,0.3);}
.header-row{display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--border2);font-size:12px;}
.header-row:last-child{border-bottom:none;}
.header-key{color:var(--cyan2);min-width:120px;flex-shrink:0;font-size:11px;}
.header-value{color:var(--text);word-break:break-all;}
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.mitre-card{background:var(--bg3);border:1px solid rgba(0,245,255,0.1);border-radius:8px;padding:14px;transition:all 0.3s;}
.mitre-card:hover{border-color:var(--cyan);box-shadow:var(--glow2);transform:translateY(-2px);}
.mitre-id{font-family:'Orbitron',monospace;font-size:13px;color:var(--cyan);font-weight:700;margin-bottom:4px;}
.mitre-name{font-size:12px;color:var(--text);margin-bottom:6px;}
.mitre-observed{font-size:10px;color:var(--text2);border-top:1px solid var(--border2);padding-top:6px;}
.recommendation{border-radius:10px;padding:24px;margin-bottom:20px;border:1px solid;display:flex;align-items:flex-start;gap:16px;}
.recommendation.high{border-color:rgba(255,45,85,0.4);background:rgba(255,45,85,0.06);}
.recommendation.medium{border-color:rgba(255,214,10,0.4);background:rgba(255,214,10,0.06);}
.recommendation.low{border-color:rgba(0,255,136,0.4);background:rgba(0,255,136,0.06);}
.rec-icon{font-size:32px;flex-shrink:0;}
.rec-title{font-family:'Orbitron',monospace;font-size:13px;font-weight:700;letter-spacing:2px;margin-bottom:6px;}
.recommendation.high .rec-title{color:var(--red);}
.recommendation.medium .rec-title{color:var(--yellow);}
.recommendation.low .rec-title{color:var(--green);}
.rec-body{font-size:12px;color:var(--text);line-height:1.7;}
.actions-row{display:flex;gap:12px;flex-wrap:wrap;margin-top:30px;}
.btn{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border-radius:6px;font-family:'Share Tech Mono',monospace;font-size:13px;cursor:pointer;letter-spacing:1px;transition:all 0.2s;text-decoration:none;border:1px solid;}
.btn-primary{background:rgba(0,245,255,0.1);border-color:var(--cyan);color:var(--cyan);}
.btn-primary:hover{background:rgba(0,245,255,0.2);box-shadow:var(--glow);}
.btn-green{background:rgba(0,255,136,0.1);border-color:var(--green);color:var(--green);}
.btn-green:hover{background:rgba(0,255,136,0.2);box-shadow:0 0 20px rgba(0,255,136,0.3);}
.btn-yellow{background:rgba(255,214,10,0.1);border-color:var(--yellow);color:var(--yellow);}
.btn-yellow:hover{background:rgba(255,214,10,0.2);box-shadow:0 0 20px rgba(255,214,10,0.3);}
.btn-ghost{background:transparent;border-color:var(--border);color:var(--text2);}
.btn-ghost:hover{border-color:var(--cyan2);color:var(--cyan2);}
.flag-item{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;background:rgba(255,45,85,0.05);border:1px solid rgba(255,45,85,0.15);border-radius:6px;margin-bottom:8px;font-size:12px;color:#ff8099;}
.flag-icon{flex-shrink:0;color:var(--red);}
.no-flags{display:flex;align-items:center;gap:8px;color:var(--green);font-size:12px;padding:10px 0;}
.empty-state{text-align:center;padding:30px;color:var(--text2);font-size:12px;}
.empty-state span{font-size:24px;display:block;margin-bottom:8px;}
.fade-in{opacity:0;transform:translateY(20px);transition:opacity 0.5s ease,transform 0.5s ease;}
.fade-in.visible{opacity:1;transform:translateY(0);}
.card-full{margin-bottom:20px;}
.section-divider{display:flex;align-items:center;gap:16px;margin:30px 0 20px;}
.divider-line{flex:1;height:1px;background:var(--border2);}
.divider-label{font-family:'Orbitron',monospace;font-size:10px;color:var(--text2);letter-spacing:3px;text-transform:uppercase;white-space:nowrap;}
.copy-btn{background:none;border:1px solid var(--border2);color:var(--text2);font-size:10px;padding:2px 6px;border-radius:3px;cursor:pointer;font-family:'Share Tech Mono',monospace;transition:all 0.2s;}
.copy-btn:hover{border-color:var(--cyan);color:var(--cyan);}
</style>
</head>
<body>

<header>
  <div class="container">
    <div class="header-inner">
      <div class="logo">
        <div class="logo-icon">🛡</div>
        <div>
          <div class="logo-text">PhishTriage</div>
          <div class="logo-sub">SOC ANALYST WORKSTATION</div>
        </div>
      </div>
      <div class="header-status">
        <div class="status-dot"><div class="dot"></div>SYSTEM ONLINE</div>
        <div class="time-display" id="clock">--:--:-- IST</div>
      </div>
    </div>
  </div>
</header>

<div class="container">

  <div class="hero" id="upload-section">
    <div class="hero-title">PHISHING TRIAGE</div>
    <div class="hero-sub">Automated IOC Extraction &amp; Threat Intel Enrichment</div>
    <div class="upload-zone" id="dropZone">
      <span class="upload-icon">📧</span>
      <div class="upload-title">DROP .EML FILE HERE</div>
      <div class="upload-sub">or click to browse your files</div>
      <label class="file-label" for="fileInput">SELECT FILE</label>
      <input type="file" class="file-input" id="fileInput" accept=".eml">
      <div class="file-selected" id="fileSelected"></div>
    </div>
    <button class="analyze-btn" id="analyzeBtn" disabled>▶ &nbsp; INITIATE ANALYSIS</button>
  </div>

  <div id="loading-section">
    <div class="terminal">
      <div class="terminal-header">
        <div class="terminal-dot t-red"></div>
        <div class="terminal-dot t-yellow"></div>
        <div class="terminal-dot t-green"></div>
        <div class="terminal-title">SOC ANALYSIS ENGINE v2.0</div>
      </div>
      <div class="terminal-body" id="terminalBody"><span class="cursor"></span></div>
    </div>
  </div>

  <div id="results-section"></div>

</div>

<script>
// ── IST Clock ──
function updateClock() {
  const now = new Date();
  const ist = new Date(now.getTime() + (5.5 * 60 * 60 * 1000));
  const hh  = String(ist.getUTCHours()).padStart(2,'0');
  const mm  = String(ist.getUTCMinutes()).padStart(2,'0');
  const ss  = String(ist.getUTCSeconds()).padStart(2,'0');
  document.getElementById('clock').textContent = hh+':'+mm+':'+ss+' IST';
}
setInterval(updateClock, 1000);
updateClock();

// ── Drag & Drop ──
const dropZone     = document.getElementById('dropZone');
const fileInput    = document.getElementById('fileInput');
const fileSelected = document.getElementById('fileSelected');
const analyzeBtn   = document.getElementById('analyzeBtn');
let selectedFile   = null;

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.eml')) setFile(f);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });

function setFile(file) {
  selectedFile = file;
  fileSelected.style.display = 'block';
  fileSelected.textContent   = '✓ ' + file.name + ' (' + (file.size/1024).toFixed(1) + ' KB)';
  analyzeBtn.disabled = false;
}

// ── Terminal ──
const terminalLines = [
  {text:'> Initializing SOC Analysis Engine...', cls:'cyan',   delay:0   },
  {text:'> Loading threat intelligence modules...', cls:'',    delay:400 },
  {text:'> Parsing email headers and body...',   cls:'',       delay:900 },
  {text:'> Extracting IOCs (URLs, IPs, domains, hashes)...', cls:'', delay:1500},
  {text:'> Querying VirusTotal API...',          cls:'yellow', delay:2200},
  {text:'> Querying AbuseIPDB reputation database...', cls:'yellow', delay:3000},
  {text:'> Calculating threat score...',         cls:'',       delay:3800},
  {text:'> Mapping to MITRE ATT&CK framework...', cls:'',     delay:4400},
  {text:'> Generating triage report...',         cls:'green',  delay:5000},
];

function runTerminal() {
  const body = document.getElementById('terminalBody');
  body.innerHTML = '';
  terminalLines.forEach(line => {
    setTimeout(() => {
      const el = document.createElement('div');
      el.className   = 't-line ' + line.cls;
      el.textContent = line.text;
      body.appendChild(el);
      body.scrollTop = body.scrollHeight;
    }, line.delay);
  });
}

// ── Analyze ──
analyzeBtn.addEventListener('click', () => {
  if (!selectedFile) return;
  document.getElementById('upload-section').style.display  = 'none';
  document.getElementById('loading-section').style.display = 'block';
  document.getElementById('results-section').style.display = 'none';
  document.getElementById('results-section').innerHTML = '';
  runTerminal();

  const formData = new FormData();
  formData.append('email_file', selectedFile);

  fetch('/analyze', {method:'POST', body:formData})
    .then(r => r.json())
    .then(data => {
      document.getElementById('loading-section').style.display = 'none';
      data.error ? showError(data.error) : renderResults(data);
    })
    .catch(err => {
      document.getElementById('loading-section').style.display = 'none';
      showError(err.toString());
    });
});

// ── Helpers ──
function verdictClass(v) {
  if (!v) return 'verdict-na';
  v = v.toUpperCase();
  if (v==='MALICIOUS')  return 'verdict-malicious';
  if (v==='SUSPICIOUS') return 'verdict-suspicious';
  if (v==='CLEAN')      return 'verdict-clean';
  return 'verdict-na';
}
function severityKey(s) {
  if (!s) return 'low';
  s = s.toLowerCase();
  if (s.includes('high'))   return 'high';
  if (s.includes('medium')) return 'medium';
  return 'low';
}
function escHtml(s) {
  if (!s) return 'N/A';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function truncate(s,n) { s=String(s||''); return s.length>n ? s.slice(0,n)+'…':s; }

// ── Render Results ──
function renderResults(d) {
  window._lastData = d;
  const sev   = severityKey(d.threat.severity);
  const icons = {high:'🔴', medium:'🟡', low:'🟢'};
  const recs  = {
    high:   {title:'BLOCK & ESCALATE',    body:'High-confidence phishing. Immediately quarantine the email, block sender domain at the email gateway, and escalate to Tier-2 for further investigation. Document all IOCs in the ticketing system.', icon:'🚨'},
    medium: {title:'INVESTIGATE FURTHER', body:'Suspicious indicators detected. Perform additional manual header analysis, verify the sender with the reported organization, and check for similar emails in the mail queue before taking action.', icon:'⚠️'},
    low:    {title:'MONITOR',             body:'Low threat score. No immediate action required. Log the IOCs for correlation, add to watchlist, and monitor for similar activity patterns over the next 24-48 hours.', icon:'👁️'},
  };
  const rec   = recs[sev];
  const score = d.threat.score || 0;

  let iocRows = '';
  (d.iocs.urls   ||[]).forEach(u  => { iocRows += `<tr><td><span class="ioc-badge ioc-url">URL</span></td><td style="color:var(--cyan);font-size:11px;">${escHtml(truncate(u,80))}</td><td><button class="copy-btn" onclick="copyText('${escHtml(u)}')">COPY</button></td></tr>`; });
  (d.iocs.ips    ||[]).forEach(ip => { iocRows += `<tr><td><span class="ioc-badge ioc-ip">IP</span></td><td>${escHtml(ip)}</td><td><button class="copy-btn" onclick="copyText('${escHtml(ip)}')">COPY</button></td></tr>`; });
  (d.iocs.domains||[]).forEach(dm => { iocRows += `<tr><td><span class="ioc-badge ioc-domain">DOMAIN</span></td><td>${escHtml(dm)}</td><td><button class="copy-btn" onclick="copyText('${escHtml(dm)}')">COPY</button></td></tr>`; });
  (d.iocs.emails ||[]).forEach(em => { iocRows += `<tr><td><span class="ioc-badge ioc-email">EMAIL</span></td><td>${escHtml(em)}</td><td><button class="copy-btn" onclick="copyText('${escHtml(em)}')">COPY</button></td></tr>`; });
  if (!iocRows) iocRows = `<tr><td colspan="3"><div class="empty-state"><span>🔍</span>No IOCs extracted</div></td></tr>`;

  let urlRows = '';
  (d.enriched.urls||[]).forEach(item => {
    const a = item.analysis||{};
    urlRows += `<tr><td style="font-size:11px;color:var(--cyan2);">${escHtml(truncate(item.ioc,55))}</td><td>${a.malicious??'N/A'}</td><td>${a.suspicious??'N/A'}</td><td><span class="verdict ${verdictClass(a.verdict)}">${escHtml(a.verdict||'N/A')}</span></td></tr>`;
  });
  if (!urlRows) urlRows = `<tr><td colspan="4"><div class="empty-state"><span>✓</span>No URLs enriched</div></td></tr>`;

  let ipRows = '';
  (d.enriched.ips||[]).forEach(item => {
    const a = item.analysis||{};
    ipRows += `<tr><td style="color:var(--yellow);">${escHtml(item.ioc)}</td><td>${a.abuse_score??'N/A'}</td><td>${escHtml(a.country||'N/A')}</td><td style="font-size:11px;">${escHtml(truncate(a.isp||'N/A',25))}</td><td><span class="verdict ${verdictClass(a.verdict)}">${escHtml(a.verdict||'N/A')}</span></td></tr>`;
  });
  if (!ipRows) ipRows = `<tr><td colspan="5"><div class="empty-state"><span>✓</span>No IPs enriched</div></td></tr>`;

  let flagsHtml = '';
  (d.parsed.spoofing_flags||[]).forEach(f => { flagsHtml += `<div class="flag-item"><span class="flag-icon">⚠</span>${escHtml(f)}</div>`; });
  if (!flagsHtml) flagsHtml = `<div class="no-flags"><span>✓</span>&nbsp;No spoofing indicators detected</div>`;

  let reasonsHtml = '';
  (d.threat.reasons||[]).forEach(r => { reasonsHtml += `<div class="reason-item ${sev}">${escHtml(r)}</div>`; });

  const h = d.parsed.headers||{};
  let headersHtml = '';
  [['Subject',h.subject],['From',h.from],['Reply-To',h.reply_to],['Return-Path',h.return_path],
   ['Date',h.date],['SPF',h.spf],['DKIM',h.dkim?'Present':'Not found'],['DMARC',h.dmarc]
  ].forEach(([k,v]) => {
    headersHtml += `<div class="header-row"><div class="header-key">${k}</div><div class="header-value">${escHtml(truncate(v||'N/A',120))}</div></div>`;
  });

  const html = `
  <div class="threat-banner ${sev} fade-in">
    <div class="threat-left">
      <div class="threat-icon">${icons[sev]}</div>
      <div>
        <div class="threat-label">Threat Level</div>
        <div class="threat-severity">${escHtml(d.threat.severity)}</div>
        <div style="font-size:11px;color:var(--text2);margin-top:4px;">File: ${escHtml(d.parsed.file)}</div>
      </div>
    </div>
    <div class="score-meter">
      <div class="score-number">${score}</div>
      <div class="meter-bar"><div class="meter-fill" id="meterFill"></div></div>
      <div class="score-label">THREAT SCORE / 100</div>
    </div>
  </div>
  ${reasonsHtml ? `<div class="reasons-list fade-in">${reasonsHtml}</div>` : ''}
  <div class="stats-row fade-in">
    <div class="stat-card"><div class="stat-number">${(d.iocs.urls||[]).length}</div><div class="stat-label">URLs Found</div></div>
    <div class="stat-card"><div class="stat-number">${(d.iocs.ips||[]).length}</div><div class="stat-label">IPs Found</div></div>
    <div class="stat-card"><div class="stat-number">${(d.iocs.domains||[]).length}</div><div class="stat-label">Domains</div></div>
    <div class="stat-card"><div class="stat-number">${(d.iocs.emails||[]).length}</div><div class="stat-label">Email Addrs</div></div>
    <div class="stat-card"><div class="stat-number">${(d.parsed.spoofing_flags||[]).length}</div><div class="stat-label">Spoof Flags</div></div>
    <div class="stat-card"><div class="stat-number">${(d.iocs.attachment_hashes||[]).length}</div><div class="stat-label">Attachments</div></div>
  </div>
  <div class="recommendation ${sev} fade-in">
    <div class="rec-icon">${rec.icon}</div>
    <div><div class="rec-title">${rec.title}</div><div class="rec-body">${rec.body}</div></div>
  </div>
  <div class="section-divider"><div class="divider-line"></div><div class="divider-label">IOC Analysis</div><div class="divider-line"></div></div>
  <div class="grid-2">
    <div class="card fade-in">
      <div class="card-header"><div class="card-title">Extracted IOCs</div><div class="card-badge">${(d.iocs.urls||[]).length+(d.iocs.ips||[]).length+(d.iocs.domains||[]).length} total</div></div>
      <div class="card-body" style="padding:0;"><table class="data-table"><thead><tr><th>Type</th><th>Value</th><th></th></tr></thead><tbody>${iocRows}</tbody></table></div>
    </div>
    <div class="card fade-in">
      <div class="card-header"><div class="card-title">Spoofing Indicators</div><div class="card-badge">${(d.parsed.spoofing_flags||[]).length} flags</div></div>
      <div class="card-body">${flagsHtml}</div>
    </div>
  </div>
  <div class="section-divider"><div class="divider-line"></div><div class="divider-label">Threat Intelligence Enrichment</div><div class="divider-line"></div></div>
  <div class="card card-full fade-in">
    <div class="card-header"><div class="card-title">URL Enrichment — VirusTotal</div><div class="card-badge">${(d.enriched.urls||[]).length} checked</div></div>
    <div class="card-body" style="padding:0;"><table class="data-table"><thead><tr><th>URL</th><th>Malicious</th><th>Suspicious</th><th>Verdict</th></tr></thead><tbody>${urlRows}</tbody></table></div>
  </div>
  <div class="card card-full fade-in">
    <div class="card-header"><div class="card-title">IP Reputation — AbuseIPDB</div><div class="card-badge">${(d.enriched.ips||[]).length} checked</div></div>
    <div class="card-body" style="padding:0;"><table class="data-table"><thead><tr><th>IP Address</th><th>Abuse Score</th><th>Country</th><th>ISP</th><th>Verdict</th></tr></thead><tbody>${ipRows}</tbody></table></div>
  </div>
  <div class="section-divider"><div class="divider-line"></div><div class="divider-label">Email Headers &amp; MITRE ATT&CK</div><div class="divider-line"></div></div>
  <div class="grid-2">
    <div class="card fade-in">
      <div class="card-header"><div class="card-title">Email Headers</div></div>
      <div class="card-body">${headersHtml}</div>
    </div>
    <div class="card fade-in">
      <div class="card-header"><div class="card-title">MITRE ATT&amp;CK Mapping</div><div class="card-badge">3 techniques</div></div>
      <div class="card-body">
        <div class="mitre-grid">
          <div class="mitre-card"><div class="mitre-id">T1566</div><div class="mitre-name">Phishing</div><div class="mitre-observed">Suspicious email received with deceptive indicators</div></div>
          <div class="mitre-card"><div class="mitre-id">T1598</div><div class="mitre-name">Phishing for Information</div><div class="mitre-observed">Credential harvesting indicators present</div></div>
          <div class="mitre-card"><div class="mitre-id">T1204</div><div class="mitre-name">User Execution</div><div class="mitre-observed">Malicious links and/or attachments present</div></div>
        </div>
      </div>
    </div>
  </div>
  <div class="actions-row fade-in">
    <button class="btn btn-primary" onclick="downloadHTML()">⬇ Download HTML Report</button>
    <button class="btn btn-yellow"  onclick="downloadPDF()">🖨 Download PDF Report</button>
    <button class="btn btn-green"   onclick="downloadCSV()">📊 Download CSV Report</button>
    <button class="btn btn-ghost"   onclick="resetDashboard()">← Analyze Another Email</button>
  </div>
  `;

  const rs = document.getElementById('results-section');
  rs.style.display = 'block';
  rs.innerHTML = html;

  setTimeout(() => {
    const fill = document.getElementById('meterFill');
    if (fill) fill.style.width = score + '%';
  }, 300);
  setTimeout(() => {
    document.querySelectorAll('.fade-in').forEach((el,i) => {
      setTimeout(() => el.classList.add('visible'), i*80);
    });
  }, 100);
}

// ── Downloads ──
function downloadHTML() {
  if (!window._lastData) return;
  const blob = new Blob([buildReportHtml(window._lastData)], {type:'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'phishing_triage_report.html';
  a.click();
}

function downloadPDF() {
  if (!window._lastData) return;
  const win = window.open('','_blank');
  win.document.write(buildReportHtml(window._lastData));
  win.document.close();
  win.onload = function() { win.focus(); win.print(); };
}

function downloadCSV() {
  if (!window._lastData) return;
  fetch('/export/csv', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(window._lastData)
  })
  .then(r => r.blob())
  .then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'phishing_triage_report.csv';
    a.click();
  })
  .catch(err => alert('CSV export failed: ' + err));
}

function buildReportHtml(d) {
  function esc(s) { return String(s||'N/A').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  const h = d.parsed.headers||{};
  const now = new Date();
  const ist = new Date(now.getTime() + (5.5*60*60*1000));
  const ts  = ist.toISOString().replace('T',' ').slice(0,19) + ' IST';
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Phishing Triage Report</title>
  <style>body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:30px;line-height:1.6;}
  h1{color:#00f2ff;border-bottom:2px solid #00f2ff;padding-bottom:8px;margin-bottom:4px;}
  h2{color:#58a6ff;margin:24px 0 10px;font-size:14px;letter-spacing:2px;}
  p.meta{color:#5a7a8a;font-size:12px;margin-bottom:20px;}
  table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12px;}
  th,td{border:1px solid #30363d;padding:8px 12px;text-align:left;}
  th{background:#161b22;color:#58a6ff;}tr:nth-child(even){background:#0a1628;}
  .section{background:#161b22;border:1px solid #30363d;padding:16px 20px;border-radius:6px;margin:16px 0;}
  .flag{color:#f85149;margin:4px 0;font-size:12px;}.score{font-size:32px;font-weight:bold;color:#00f2ff;}
  @media print{body{background:#fff;color:#000;}h1,h2{color:#000;}th{background:#eee;color:#000;}
  table,tr,td,th{border-color:#ccc;}.section{background:#f9f9f9;border-color:#ccc;}.flag{color:#cc0000;}.score{color:#000;}}
  </style></head><body>
  <h1>🛡️ Phishing Triage Report</h1>
  <p class="meta">Generated: ${ts} &nbsp;|&nbsp; File: ${esc(d.parsed.file)}</p>
  <div class="section"><h2>THREAT ASSESSMENT</h2>
  <div class="score">${d.threat.score}/100 — ${esc(d.threat.severity)}</div><br>
  ${(d.threat.reasons||[]).map(r=>`<div class="flag">⚠ ${esc(r)}</div>`).join('')}</div>
  <div class="section"><h2>EMAIL HEADERS</h2>
  <table><tr><th>Field</th><th>Value</th></tr>
  ${[['Subject',h.subject],['From',h.from],['Reply-To',h.reply_to],['Return-Path',h.return_path],
     ['Date',h.date],['SPF',h.spf],['DKIM',h.dkim?'Present':'Not found'],['DMARC',h.dmarc]]
    .map(([k,v])=>`<tr><td>${k}</td><td>${esc(v)}</td></tr>`).join('')}</table></div>
  <div class="section"><h2>SPOOFING INDICATORS</h2>
  ${(d.parsed.spoofing_flags||[]).length?(d.parsed.spoofing_flags||[]).map(f=>`<div class="flag">⚠ ${esc(f)}</div>`).join(''):'<p style="color:#00ff88">✓ No spoofing indicators detected</p>'}</div>
  <div class="section"><h2>EXTRACTED IOCs</h2>
  <table><tr><th>Type</th><th>Value</th></tr>
  ${(d.iocs.urls||[]).map(u=>`<tr><td>URL</td><td>${esc(u)}</td></tr>`).join('')}
  ${(d.iocs.ips||[]).map(ip=>`<tr><td>IP</td><td>${esc(ip)}</td></tr>`).join('')}
  ${(d.iocs.domains||[]).map(dm=>`<tr><td>Domain</td><td>${esc(dm)}</td></tr>`).join('')}
  ${(d.iocs.emails||[]).map(em=>`<tr><td>Email</td><td>${esc(em)}</td></tr>`).join('')}</table></div>
  <div class="section"><h2>URL ENRICHMENT — VIRUSTOTAL</h2>
  <table><tr><th>URL</th><th>Malicious</th><th>Suspicious</th><th>Verdict</th></tr>
  ${(d.enriched.urls||[]).map(item=>{const a=item.analysis||{};return`<tr><td>${esc(item.ioc)}</td><td>${a.malicious??'N/A'}</td><td>${a.suspicious??'N/A'}</td><td>${esc(a.verdict||'N/A')}</td></tr>`;}).join('')||'<tr><td colspan="4">No URLs enriched</td></tr>'}</table></div>
  <div class="section"><h2>IP REPUTATION — ABUSEIPDB</h2>
  <table><tr><th>IP</th><th>Abuse Score</th><th>Country</th><th>ISP</th><th>Verdict</th></tr>
  ${(d.enriched.ips||[]).map(item=>{const a=item.analysis||{};return`<tr><td>${esc(item.ioc)}</td><td>${a.abuse_score??'N/A'}</td><td>${esc(a.country||'N/A')}</td><td>${esc(a.isp||'N/A')}</td><td>${esc(a.verdict||'N/A')}</td></tr>`;}).join('')||'<tr><td colspan="5">No IPs enriched</td></tr>'}</table></div>
  <div class="section"><h2>MITRE ATT&amp;CK MAPPING</h2>
  <table><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr>
  <tr><td>T1566</td><td>Phishing</td><td>Initial Access</td></tr>
  <tr><td>T1598</td><td>Phishing for Information</td><td>Reconnaissance</td></tr>
  <tr><td>T1204</td><td>User Execution</td><td>Execution</td></tr></table></div>
  </body></html>`;
}

function copyText(text) { navigator.clipboard.writeText(text).catch(()=>{}); }

function resetDashboard() {
  document.getElementById('results-section').style.display  = 'none';
  document.getElementById('results-section').innerHTML = '';
  document.getElementById('upload-section').style.display   = 'block';
  selectedFile = null;
  analyzeBtn.disabled = true;
  document.getElementById('fileSelected').style.display = 'none';
  fileInput.value = '';
  window._lastData = null;
}

function showError(msg) {
  document.getElementById('upload-section').style.display = 'block';
  document.getElementById('results-section').style.display = 'block';
  document.getElementById('results-section').innerHTML =
    `<div style="background:rgba(255,45,85,0.1);border:1px solid rgba(255,45,85,0.3);border-radius:8px;padding:20px;color:#ff8099;font-size:12px;margin-bottom:30px;">
    <strong style="color:#ff2d55">⚠ ANALYSIS ERROR</strong><br><br>
    <pre style="white-space:pre-wrap;overflow-x:auto;">${String(msg).replace(/&/g,'&amp;').replace(/</g,'&lt;')}</pre></div>`;
}
</script>
</body>
</html>''', 200, {'Content-Type': 'text/html'}


# ─────────────────────────────────────────────
#  ANALYZE ENDPOINT — returns JSON
# ─────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
def analyze():
    print(">>> /analyze hit")

    if "email_file" not in request.files:
        return jsonify({"error": "No file in request"}), 400

    file = request.files["email_file"]
    if file.filename == "" or not file.filename.endswith(".eml"):
        return jsonify({"error": "Invalid file. Only .eml files accepted."}), 400

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    print(f">>> Saved: {file_path}")

    try:
        parsed   = parse_email(file_path)
        iocs     = extract_all_iocs(parsed)
        enriched = enrich_all(iocs)
        threat   = calculate_threat_score(enriched, parsed["spoofing_flags"])

        parsed_clean = {
            "file":           parsed["file"],
            "headers":        parsed["headers"],
            "spoofing_flags": parsed["spoofing_flags"],
            "attachments": [
                {"filename": a["filename"], "size_bytes": a["size_bytes"]}
                for a in parsed.get("attachments", [])
            ]
        }
        iocs_clean = {
            "urls":    iocs.get("urls", []),
            "ips":     iocs.get("ips", []),
            "domains": iocs.get("domains", []),
            "emails":  iocs.get("emails", []),
            "attachment_hashes": [
                {k: v for k, v in a.items() if k != "data"}
                for a in iocs.get("attachment_hashes", [])
            ]
        }

        print(f">>> Score: {threat['score']} | {threat['severity']}")
        return jsonify({
            "parsed":   parsed_clean,
            "iocs":     iocs_clean,
            "enriched": enriched,
            "threat":   threat,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": traceback.format_exc()}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
