import re
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urlparse

# Regular expressions for extraction
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_REGEX = re.compile(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

def extract_urls(text, html):
    urls = set()
    mismatched_links = []
    
    # Extract from plain text
    if text:
        urls.update(URL_REGEX.findall(text))
        
    # Extract from HTML and detect mismatches
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            text_content = a_tag.get_text().strip()
            
            # Add to URLs
            if href.startswith('http'):
                urls.add(href)
                
            # Check for mismatch
            # If the visible text is a URL, but it doesn't match the href
            if text_content.startswith('http') and text_content != href:
                # Basic check: are the domains different?
                href_domain = urlparse(href).netloc
                text_domain = urlparse(text_content).netloc
                if href_domain and text_domain and href_domain != text_domain:
                    mismatched_links.append({
                        'href': href,
                        'text': text_content
                    })
                    
    return list(urls), mismatched_links

def extract_domains(urls, email_addresses):
    domains = set()
    for url in urls:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            domains.add(f"{ext.domain}.{ext.suffix}")
            
    for email in email_addresses:
        parts = email.split('@')
        if len(parts) == 2:
            domains.add(parts[1])
            
    return list(domains)

def extract_iocs(parsed_email):
    body_text = parsed_email.get('body', {}).get('text', '')
    body_html = parsed_email.get('body', {}).get('html', '')
    
    combined_content = f"{body_text} {body_html}"
    
    emails = list(set(EMAIL_REGEX.findall(combined_content)))
    
    # Also get emails from headers
    headers = parsed_email.get('headers', {})
    for header in ['From', 'Return-Path', 'Reply-To']:
        header_val = headers.get(header, '')
        if header_val:
            emails.extend(EMAIL_REGEX.findall(header_val))
    emails = list(set(emails))
    
    ips = list(set(IP_REGEX.findall(combined_content)))
    
    # Get IPs from received headers
    received_headers = parsed_email.get('received', [])
    for rh in received_headers:
        if rh:
            ips.extend(IP_REGEX.findall(rh))
    ips = list(set(ips))
    
    urls, mismatched = extract_urls(body_text, body_html)
    domains = extract_domains(urls, emails)
    
    hashes = []
    for attachment in parsed_email.get('attachments', []):
        if 'md5' in attachment:
            hashes.append({'type': 'md5', 'value': attachment['md5']})
        if 'sha256' in attachment:
            hashes.append({'type': 'sha256', 'value': attachment['sha256']})
            
    return {
        'emails': emails,
        'ips': ips,
        'urls': urls,
        'domains': domains,
        'hashes': hashes,
        'mismatched_links': mismatched
    }

if __name__ == '__main__':
    # Simple test code could go here
    pass
