import re
import hashlib
from urllib.parse import urlparse


# --- Regex Patterns ---
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+', re.IGNORECASE
)
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|co|info|biz|xyz|top|'
    r'club|online|site|ru|cn|tk|ml|ga|cf|gq)\b',
    re.IGNORECASE
)


def extract_urls(text: str) -> list:
    return list(set(URL_PATTERN.findall(text)))


def extract_ips(text: str) -> list:
    found = IP_PATTERN.findall(text)
    # Filter out private/loopback ranges
    public_ips = [
        ip for ip in found
        if not (
            ip.startswith("192.168.") or
            ip.startswith("10.") or
            ip.startswith("127.") or
            ip.startswith("172.")
        )
    ]
    return list(set(public_ips))


def extract_emails(text: str) -> list:
    return list(set(EMAIL_PATTERN.findall(text)))


def extract_domains(urls: list) -> list:
    """Pull domains out of extracted URLs."""
    domains = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc.lower())
        except Exception:
            continue
    return list(domains)


def hash_file(data: bytes) -> dict:
    """Generate MD5 and SHA256 of attachment data."""
    if not data:
        return {"md5": "N/A", "sha256": "N/A"}
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extract_all_iocs(parsed_email: dict) -> dict:
    """Run all extractors against email body + headers."""
    full_text = (
        parsed_email["body"]["plain"] + " " +
        parsed_email["body"]["html"]
    )

    urls    = extract_urls(full_text)
    ips     = extract_ips(full_text)
    domains = extract_domains(urls)
    emails  = extract_emails(full_text)

    # Hash attachments
    attachment_hashes = []
    for att in parsed_email["attachments"]:
        h = hash_file(att["data"])
        attachment_hashes.append({
            "filename": att["filename"],
            "md5":      h["md5"],
            "sha256":   h["sha256"],
            "size":     att["size_bytes"],
        })

    return {
        "urls":               urls,
        "ips":                ips,
        "domains":            domains,
        "emails":             emails,
        "attachment_hashes":  attachment_hashes,
    }
