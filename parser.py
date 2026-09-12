from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from urllib.parse import urlparse
import re
import base64


def parse_eml(email_path):
    """Parse an .eml file and extract email metadata, IOCs and security headers."""

    # Read and parse email
    with open(email_path, "rb") as f:
        raw_bytes = f.read()

    # Strip UTF-8 BOM if present
    if raw_bytes.startswith(b'\xef\xbb\xbf'):
        raw_bytes = raw_bytes[3:]

    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    # Sender
    sender_list = [
        email for _, email in getaddresses([msg.get("From") or ""])
        if email
    ]

    # Receiver
    receiver_list = [
        email for _, email in getaddresses([msg.get("To") or ""])
        if email
    ]

    # Reply-To
    reply_to_list = [
        email for _, email in getaddresses([msg.get("Reply-To") or ""])
        if email
    ]

    # Get email body
    body = msg.get_body(preferencelist=("plain", "html"))

    if body:
        body_text = body.get_content()
    else:
        body_text = ""

    # Decode Base64 embedded content
    decoded_content = ""

    base64_matches = re.findall(
        r'data:[^;]+;base64,\s*(.*?)#rectangle',
        body_text,
        re.DOTALL | re.IGNORECASE
    )

    for encoded_data in base64_matches:
        try:
            encoded_data = re.sub(r'\s+', '', encoded_data)

            decoded_content += base64.b64decode(
                encoded_data
            ).decode(
                "utf-8",
                errors="replace"
            )
        except Exception:
            pass

    # Scan both normal body and decoded content
    content_to_scan = body_text + "\n" + decoded_content

    # Extract URLs
    urls = re.findall(
        r'https?://[^\s"\'<>]+',
        content_to_scan
    )
    urls = sorted(set(urls))

    # Ignore technical W3C URLs
    ignored_domains = {
        "www.w3.org",
        "w3.org"
    }

    filtered_urls = []

    for url in urls:
        domain = urlparse(url).netloc.lower()

        if domain not in ignored_domains:
            filtered_urls.append(url)

    # Extract IP addresses
    ip_addresses = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        content_to_scan
    )
    ip_addresses = sorted(set(ip_addresses))

    # Extract domains
    domains = set()

    # Domains from URLs
    for url in filtered_urls:
        domain = urlparse(url).netloc.lower()

        if domain:
            domains.add(domain)

    # Domains from email addresses
    for email in sender_list + receiver_list + reply_to_list:
        if "@" in email:
            domain = email.split("@", 1)[1].lower()
            domains.add(domain)

    domains = sorted(domains)

    # Extract attachments
    attachments = []

    for part in msg.walk():
        filename = part.get_filename()

        if filename:
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type()
            })

    # Security headers
    security_headers = {
        "received": msg.get_all("Received", []),
        "authentication_results": msg.get_all(
            "Authentication-Results", []
        ),
        "dkim_signature": msg.get_all(
            "DKIM-Signature", []
        ),
        "received_spf": msg.get_all(
            "Received-SPF", []
        ),
        "return_path": msg.get("Return-Path"),
        "message_id": msg.get("Message-ID")
    }

    # Suspicious indicators
    suspicious_indicators = []

    patterns = {
        "javascript": r'javascript\s*:',
        "script_tag": r'<\s*script\b',
        "iframe_tag": r'<\s*iframe\b',
        "embed_tag": r'<\s*embed\b',
        "object_tag": r'<\s*object\b',
        "base64_content": r'base64,'
    }

    for indicator, pattern in patterns.items():
        if re.search(
            pattern,
            content_to_scan,
            re.IGNORECASE
        ):
            suspicious_indicators.append(indicator)

    # Final structured result
    import os
    base_name = os.path.basename(email_path)
    clean_id = os.path.splitext(base_name)[0]

    result = {
        "email_id": clean_id,
        "sender": sender_list,
        "receiver": receiver_list,
        "subject": msg.get("Subject"),
        "reply_to": reply_to_list,
        "urls": filtered_urls,
        "domains": domains,
        "ips": ip_addresses,
        "attachments": attachments,
        "security_headers": security_headers,
        "suspicious_indicators": suspicious_indicators
    }

    return result


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python parser.py <path_to_eml_file>\n")
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        parsed_data = parse_eml(file_path)
        print(json.dumps(parsed_data))
    except Exception as e:
        sys.stderr.write(f"Parser error: {str(e)}\n")
        sys.exit(1)

