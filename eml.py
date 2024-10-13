import sys
import hashlib
import re
from email import policy
from email.parser import BytesParser

def calculate_hashes(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def extract_headers(eml_file):
    """Extract relevant headers from the EML file."""
    with open(eml_file, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "From": msg['from'],
        "To": msg['to'],
        "Subject": msg['subject'],
        "Date": msg['date'],
        "CC": msg['cc'],
        "BCC": msg['bcc'],
        "X-Headers": {k: v for k, v in msg.items() if k.startswith('X-')},
        "Attachments": [part.get_filename() for part in msg.iter_attachments() if part.get_filename()]
    }

    return headers

def extract_ip_addresses_and_urls(msg):
    """Extract unique IP addresses and URLs from the email body."""
    body = msg.get_body(preferencelist=('html', 'plain'))
    content = body.get_content()

    # Find URLs
    urls = re.findall(r'https?://[^\s]+', content)
    unique_urls = list(set(urls))

    # Find IP addresses
    ip_addresses = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
    unique_ips = list(set(ip_addresses))

    return unique_ips, unique_urls

def sanitize_ip_addresses(ips):
    """Sanitize IP addresses by replacing '.' with '[.]'."""
    return [ip.replace('.', '[.]') for ip in ips]

def clean_html(content):
    """Convert HTML content to plain text by removing tags."""
    text = re.sub(r'<[^>]+>', ' ', content)  # Remove HTML tags
    text = re.sub(r'\s+', ' ', text)          # Replace multiple spaces with a single space
    return text.strip()

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <eml_file> [-c | -f <output_file> | -fs <output_file>]")
        sys.exit(1)

    eml_file = sys.argv[1]
    copy_to_clipboard = '-c' in sys.argv
    output_file = None
    sanitize_ips = '-fs' in sys.argv

    if '-f' in sys.argv or sanitize_ips:
        try:
            output_index = sys.argv.index('-f' if '-f' in sys.argv else '-fs') + 1
            output_file = sys.argv[output_index]
        except IndexError:
            print("Please specify a filename after -f or -fs")
            sys.exit(1)

    # Calculate hashes
    md5_hash, sha1_hash, sha256_hash = calculate_hashes(eml_file)

    # Extract headers and body content
    headers = extract_headers(eml_file)

    with open(eml_file, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
        body = msg.get_body(preferencelist=('html', 'plain'))
        content = body.get_content()

    unique_ips, unique_urls = extract_ip_addresses_and_urls(msg)
    cleaned_html = clean_html(content)

    # Prepare sanitized IPs if requested
    sanitized_ips = sanitize_ip_addresses(unique_ips) if sanitize_ips else []

    # Prepare the output
    output = (
        f"Processed EML File: {eml_file}\n"
        f"MD5: {md5_hash}\n"
        f"SHA1: {sha1_hash}\n"
        f"SHA256: {sha256_hash}\n\n"
        f"From: {headers['From']}\n"
        f"To: {headers['To']}\n"
        f"Subject: {headers['Subject']}\n"
        f"Date: {headers['Date']}\n"
        f"CC: {headers['CC']}\n"
        f"BCC: {headers['BCC']}\n"
        f"Attachments: {', '.join(headers['Attachments'])}\n\n"
        f"Unique IP Addresses: {', '.join(unique_ips) if unique_ips else 'None'}\n"
        f"Sanitized IP Addresses: {', '.join(sanitized_ips) if sanitized_ips else 'None'}\n"
        f"Unique URLs: {', '.join(unique_urls) if unique_urls else 'None'}\n\n"
        f"Butchering HTML Embedded Contents:\n{cleaned_html}\n\n"
        f"Listing Down All X-* Headers:\n{headers['X-Headers']}\n"
    )

    if copy_to_clipboard:
        print("Clipboard functionality not available without additional libraries.")
    elif output_file:
        with open(output_file, 'w') as f:
            f.write(output)
        print(f"Output written to {output_file}.")
    else:
        print(output)

if __name__ == "__main__":
    main()
