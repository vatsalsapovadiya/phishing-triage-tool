import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def generate_report(parsed_email, iocs, enriched, threat, output_dir="reports/samples"):

    os.makedirs(output_dir, exist_ok=True)

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env      = Environment(loader=FileSystemLoader(os.path.join(BASE_DIR, "templates")))
    template = env.get_template("report_template.html")

    context = {
        "generated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "email_file":     parsed_email["file"],
        "headers":        parsed_email["headers"],
        "spoofing_flags": parsed_email["spoofing_flags"],
        "iocs":           iocs,
        "enriched":       enriched,
        "threat":         threat,
    }

    html_out  = template.render(**context)
    base_name = parsed_email["file"].replace(".eml", "")
    html_path = os.path.join(output_dir, f"{base_name}_report.html")

    with open(html_path, "w") as f:
        f.write(html_out)

    print(f"[+] Report saved: {html_path}")
    return html_path
