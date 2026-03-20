import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML


def generate_report(
    parsed_email: dict,
    iocs: dict,
    enriched: dict,
    threat: dict,
    output_dir: str = "reports/samples"
) -> str:
    """Generate HTML + PDF triage report."""

    os.makedirs(output_dir, exist_ok=True)

    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")

    context = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "email_file":   parsed_email["file"],
        "headers":      parsed_email["headers"],
        "spoofing_flags": parsed_email["spoofing_flags"],
        "iocs":         iocs,
        "enriched":     enriched,
        "threat":       threat,
    }

    html_out = template.render(**context)

    # Save HTML
    base_name   = parsed_email["file"].replace(".eml", "")
    html_path   = os.path.join(output_dir, f"{base_name}_report.html")
    pdf_path    = os.path.join(output_dir, f"{base_name}_report.pdf")

    with open(html_path, "w") as f:
        f.write(html_out)

    # Save PDF
    HTML(string=html_out).write_pdf(pdf_path)

    print(f"[+] Report saved: {html_path}")
    print(f"[+] PDF saved:    {pdf_path}")

    return html_path
