import sys
import os
from analyzer.email_parser    import parse_email
from analyzer.ioc_extractor   import extract_all_iocs
from analyzer.enrichment      import enrich_all, calculate_threat_score
from reports.report_generator import generate_report

def analyze(eml_path):
    print(f"\n[*] Analyzing: {eml_path}")
    print("[*] Parsing email...")
    parsed   = parse_email(eml_path)

    print("[*] Extracting IOCs...")
    iocs     = extract_all_iocs(parsed)

    print("[*] Enriching via APIs...")
    enriched = enrich_all(iocs)

    print("[*] Calculating threat score...")
    threat   = calculate_threat_score(enriched, parsed["spoofing_flags"])

    print("[*] Generating report...")
    report   = generate_report(parsed, iocs, enriched, threat)

    print(f"\n✅ Done!")
    print(f"   Threat Score : {threat['score']}/100")
    print(f"   Severity     : {threat['severity']}")
    print(f"   Report saved : {report}")

    # Open report in browser
    os.system(f"xdg-open {os.path.abspath(report)}")

if __name__ == "__main__":
    eml = sys.argv[1] if len(sys.argv) > 1 else "phishing_samples/test-phish.eml"
    analyze(eml)
