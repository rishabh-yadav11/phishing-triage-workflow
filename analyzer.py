import re
import dns.resolver

# Mock data for demonstration purposes
MOCK_NEW_DOMAINS = ['new-login-update.com', 'secure-bank-alert.net']
MOCK_MALICIOUS_IPS = ['192.168.1.100']
MOCK_MALICIOUS_HASHES = ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'] # Empty file sha256

SHORTENERS = [
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd',
    'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc',
    'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
    'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as',
    'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com',
    'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly',
    'to.ly', 'bit.do', 't2m.io', 'lnkd.in', 'db.tt',
    'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv',
    'ow.ly', 'ity.im', 'q.gs', 'is.gd', 'po.st',
    'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com',
    'cutt.us', 'u.bb', 'yourls.org', 'x.co', 'prettylinkpro.com',
    'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com',
    'tweez.me', 'v.gd', 'tr.im', 'link.zip.net'
]

DANGEROUS_EXTENSIONS = [
    '.exe', '.vbs', '.bat', '.cmd', '.js', '.jse', '.wsf', '.wsh', 
    '.scr', '.hta', '.cpl', '.msc', '.jar', '.ps1', '.docm', '.xlsm', 
    '.pptm', '.rtf', '.iso', '.img', '.cab', '.zip', '.rar', '.7z'
]

def check_spf_dkim_dmarc(auth_results):
    if not auth_results:
        return {'spf': 'unknown', 'dkim': 'unknown', 'dmarc': 'unknown'}
        
    auth_lower = auth_results.lower()
    
    spf = 'pass' if 'spf=pass' in auth_lower else ('fail' if 'spf=fail' in auth_lower else 'unknown')
    dkim = 'pass' if 'dkim=pass' in auth_lower else ('fail' if 'dkim=fail' in auth_lower else 'unknown')
    dmarc = 'pass' if 'dmarc=pass' in auth_lower else ('fail' if 'dmarc=fail' in auth_lower else 'unknown')
    
    return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc}

def analyze_domains(domains):
    results = []
    for domain in domains:
        is_new = domain in MOCK_NEW_DOMAINS
        has_mx = False
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            if answers:
                has_mx = True
        except Exception:
            pass
            
        results.append({
            'domain': domain,
            'is_new': is_new,
            'has_mx': has_mx
        })
    return results

def calculate_risk_score(parsed_email, iocs):
    score = 0
    reasons = []
    
    # 1. Authentication Checks
    auth_status = check_spf_dkim_dmarc(parsed_email.get('auth_results', ''))
    
    if auth_status['spf'] == 'fail':
        score += 30
        reasons.append("SPF check failed (+30)")
    elif auth_status['spf'] == 'unknown':
        score += 10
        reasons.append("SPF check unknown/missing (+10)")
        
    if auth_status['dkim'] == 'fail':
        score += 20
        reasons.append("DKIM check failed (+20)")
        
    if auth_status['dmarc'] == 'fail':
        score += 30
        reasons.append("DMARC check failed (+30)")

    # 2. Header Anomalies
    headers = parsed_email.get('headers', {})
    from_header = headers.get('From', '')
    return_path = headers.get('Return-Path', '')
    reply_to = headers.get('Reply-To', '')
    
    # Simple extraction of email from header
    from_email = re.search(r'<([^>]+)>', from_header)
    from_email = from_email.group(1) if from_email else from_header.strip()
    
    return_email = re.search(r'<([^>]+)>', return_path)
    return_email = return_email.group(1) if return_email else return_path.strip()
    
    if return_email and from_email and return_email != from_email:
        # Ignore empty/missing return path for this check
        if return_email != '<>':
            score += 25
            reasons.append(f"Return-Path ({return_email}) does not match From address ({from_email}) (+25)")
            
    if reply_to and from_email:
        reply_email = re.search(r'<([^>]+)>', reply_to)
        reply_email = reply_email.group(1) if reply_email else reply_to.strip()
        if reply_email and reply_email != from_email:
            score += 15
            reasons.append(f"Reply-To ({reply_email}) differs from From address ({from_email}) (+15)")

    # 3. Content Analysis
    # Mismatched links
    if iocs.get('mismatched_links'):
        score += 40
        reasons.append(f"Found {len(iocs['mismatched_links'])} mismatched anchor links (+40)")

    # URL Shorteners
    for url in iocs.get('urls', []):
        for shortener in SHORTENERS:
            if shortener in url:
                score += 20
                reasons.append(f"URL shortener detected: {url} (+20)")
                break

    # 4. Attachment Analysis
    for attachment in parsed_email.get('attachments', []):
        filename = attachment.get('filename', '').lower()
        is_dangerous = any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS)
        if is_dangerous:
            score += 50
            reasons.append(f"Dangerous attachment type detected: {filename} (+50)")
            
        # Check against mock malicious hashes
        if attachment.get('md5') in MOCK_MALICIOUS_HASHES or attachment.get('sha256') in MOCK_MALICIOUS_HASHES:
            score += 100
            reasons.append(f"Known malicious attachment hash detected: {attachment.get('filename')} (+100)")

    # 5. Domain Analysis
    domain_results = analyze_domains(iocs.get('domains', []))
    for dr in domain_results:
        if dr['is_new']:
            score += 35
            reasons.append(f"Newly registered domain detected: {dr['domain']} (+35)")
        if not dr['has_mx']:
            score += 15
            reasons.append(f"Domain lacking MX records: {dr['domain']} (+15)")

    return {
        'total_score': min(score, 100), # Cap at 100
        'reasons': reasons,
        'auth_status': auth_status,
        'domain_analysis': domain_results
    }

if __name__ == '__main__':
    # Simple test code could go here
    pass
