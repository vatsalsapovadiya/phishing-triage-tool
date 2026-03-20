import email
import email.policy
from email.utils import parseaddr, getaddresses
from pathlib import Path


def load_eml(file_path: str) -> email.message.EmailMessage:
    """Load a raw .eml file and return parsed EmailMessage object."""
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    return msg


def extract_headers(msg: email.message.EmailMessage) -> dict:
    """Extract key headers useful for phishing analysis."""
    headers = {
        "subject":          msg.get("Subject", "N/A"),
        "from":             msg.get("From", "N/A"),
        "reply_to":         msg.get("Reply-To", "N/A"),
        "to":               msg.get("To", "N/A"),
        "date":             msg.get("Date", "N/A"),
        "message_id":       msg.get("Message-ID", "N/A"),
        "received":         msg.get_all("Received", []),
        "x_originating_ip": msg.get("X-Originating-IP", "N/A"),
        "return_path":      msg.get("Return-Path", "N/A"),
        "spf":              msg.get("Received-SPF", "N/A"),
        "dkim":             msg.get("DKIM-Signature", "N/A"),
        "dmarc":            msg.get("Authentication-Results", "N/A"),
    }
    return headers


def detect_spoofing(headers: dict) -> list:
    """Basic checks for common phishing spoofing indicators."""
    flags = []

    from_name, from_addr = parseaddr(headers["from"])
    _, reply_addr = parseaddr(headers["reply_to"])

    # From display name vs actual email domain mismatch
    if from_name and "@" in from_name:
        flags.append(f"[!] From display name contains email address: {from_name}")

    # Reply-To differs from From
    if reply_addr and from_addr and reply_addr.lower() != from_addr.lower():
        flags.append(
            f"[!] Reply-To ({reply_addr}) differs from From ({from_addr}) — common phishing tactic"
        )

    # No SPF record
    if headers["spf"] == "N/A" or "fail" in headers["spf"].lower():
        flags.append(f"[!] SPF check failed or missing: {headers['spf']}")

    # No DKIM
    if headers["dkim"] == "N/A":
        flags.append("[!] No DKIM signature found")

    return flags


def extract_body(msg: email.message.EmailMessage) -> dict:
    """Extract plain text and HTML body from email."""
    body = {"plain": "", "html": ""}

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    decoded = payload.decode("utf-8", errors="ignore")
                    if content_type == "text/plain":
                        body["plain"] += decoded
                    elif content_type == "text/html":
                        body["html"] += decoded
            except Exception:
                continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body["plain"] = payload.decode("utf-8", errors="ignore")

    return body


def extract_attachments(msg: email.message.EmailMessage) -> list:
    """Extract attachment names and content for hashing."""
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            attachments.append({
                "filename": filename,
                "data": payload,
                "size_bytes": len(payload) if payload else 0,
            })
    return attachments


def parse_email(file_path: str) -> dict:
    """Master function: parse everything from a .eml file."""
    msg = load_eml(file_path)
    headers = extract_headers(msg)
    body = extract_body(msg)

    return {
        "headers": headers,
        "body": body,
        "spoofing_flags": detect_spoofing(headers),
        "attachments": extract_attachments(msg),
        "file": Path(file_path).name,
    }
