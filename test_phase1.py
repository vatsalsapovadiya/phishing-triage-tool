# test_phase1.py — run this to verify
from analyzer.email_parser import parse_email
from analyzer.ioc_extractor import extract_all_iocs

result = parse_email("/home/zeus/Desktop/phishing-triage-tool/phishing-samples/email/sample-9.eml")
iocs   = extract_all_iocs(result)

print("=== HEADERS ===")
for k, v in result["headers"].items():
    print(f"{k}: {v}")

print("\n=== SPOOFING FLAGS ===")
for flag in result["spoofing_flags"]:
    print(flag)

print("\n=== IOCS ===")
print("URLs:",    iocs["urls"])
print("IPs:",     iocs["ips"])
print("Domains:", iocs["domains"])
