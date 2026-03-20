import os
from flask import Flask, render_template, request, redirect, url_for, send_file
from analyzer.email_parser   import parse_email
from analyzer.ioc_extractor  import extract_all_iocs
from analyzer.enrichment     import enrich_all, calculate_threat_score
from reports.report_generator import generate_report

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "email_file" not in request.files:
        return redirect(url_for("index"))

    file = request.files["email_file"]
    if not file.filename.endswith(".eml"):
        return "Only .eml files are supported.", 400

    # Save uploaded file
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Run pipeline
    parsed   = parse_email(file_path)
    iocs     = extract_all_iocs(parsed)
    enriched = enrich_all(iocs)
    threat   = calculate_threat_score(enriched, parsed["spoofing_flags"])

    # Generate report
    report_path = generate_report(parsed, iocs, enriched, threat)
    pdf_path    = report_path.replace(".html", ".pdf")

    return render_template(
        "results.html",
        parsed=parsed,
        iocs=iocs,
        enriched=enriched,
        threat=threat,
        report_html=report_path,
        report_pdf=pdf_path,
    )


@app.route("/download/<path:filename>")
def download(filename):
    return send_file(filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
