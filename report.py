import json

def generate_verdict(score):
    if score >= 70:
        return 'Likely Phishing'
    elif score >= 30:
        return 'Suspicious'
    else:
        return 'Benign'

def generate_report(parsed_email, iocs, analysis_results):
    score = analysis_results['total_score']
    verdict = generate_verdict(score)
    
    report_data = {
        'metadata': {
            'subject': parsed_email['headers'].get('Subject', ''),
            'from': parsed_email['headers'].get('From', ''),
            'date': parsed_email['headers'].get('Date', ''),
            'message_id': parsed_email['headers'].get('Message-ID', '')
        },
        'verdict': {
            'status': verdict,
            'risk_score': score,
            'reasons': analysis_results['reasons']
        },
        'authentication': analysis_results['auth_status'],
        'iocs': {
            'urls': list(iocs['urls']),
            'domains': list(iocs['domains']),
            'ips': list(iocs['ips']),
            'emails': list(iocs['emails']),
            'attachments': parsed_email['attachments'],
            'mismatched_links': iocs['mismatched_links']
        },
        'domain_analysis': analysis_results['domain_analysis']
    }
    
    return report_data

def report_to_markdown(report_data):
    md = f"# Phishing Triage Report\n\n"
    
    # Verdict Section
    verdict = report_data['verdict']['status']
    score = report_data['verdict']['risk_score']
    
    status_icon = "🟢" if verdict == "Benign" else "🟡" if verdict == "Suspicious" else "🔴"
    
    md += f"## Verdict: {status_icon} **{verdict}** (Risk Score: {score}/100)\n\n"
    
    md += "### Key Reasons:\n"
    if not report_data['verdict']['reasons']:
        md += "- No suspicious indicators found.\n"
    for reason in report_data['verdict']['reasons']:
        md += f"- {reason}\n"
    md += "\n"

    # Metadata Section
    md += "## Email Metadata\n"
    meta = report_data['metadata']
    md += f"- **Subject:** {meta.get('subject', 'N/A')}\n"
    md += f"- **From:** {meta.get('from', 'N/A')}\n"
    md += f"- **Date:** {meta.get('date', 'N/A')}\n"
    md += f"- **Message-ID:** {meta.get('message_id', 'N/A')}\n\n"

    # Authentication Section
    md += "## Authentication Results\n"
    auth = report_data['authentication']
    md += f"- **SPF:** {auth.get('spf', 'Unknown')}\n"
    md += f"- **DKIM:** {auth.get('dkim', 'Unknown')}\n"
    md += f"- **DMARC:** {auth.get('dmarc', 'Unknown')}\n\n"

    # IOCs Section
    md += "## Extracted IOCs\n\n"
    
    iocs = report_data['iocs']
    
    md += "### URLs\n"
    if iocs['urls']:
        for url in iocs['urls']:
            md += f"- {url}\n"
    else:
        md += "None found.\n"
    md += "\n"
        
    if iocs['mismatched_links']:
        md += "### ⚠️ Mismatched Links Found:\n"
        for link in iocs['mismatched_links']:
            md += f"- Visible Text: `{link['text']}` -> Destination: `{link['href']}`\n"
        md += "\n"

    md += "### Domains\n"
    if iocs['domains']:
        for domain in iocs['domains']:
            # Find if there's analysis info for this domain
            analysis_info = next((d for d in report_data['domain_analysis'] if d['domain'] == domain), None)
            notes = []
            if analysis_info:
                if analysis_info.get('is_new'): notes.append("Newly Registered")
                if not analysis_info.get('has_mx'): notes.append("No MX Record")
            
            note_str = f" ({', '.join(notes)})" if notes else ""
            md += f"- {domain}{note_str}\n"
    else:
        md += "None found.\n"
    md += "\n"

    md += "### IP Addresses\n"
    if iocs['ips']:
        for ip in iocs['ips']:
            md += f"- {ip}\n"
    else:
        md += "None found.\n"
    md += "\n"

    md += "### Email Addresses\n"
    if iocs['emails']:
        for email in iocs['emails']:
            md += f"- {email}\n"
    else:
        md += "None found.\n"
    md += "\n"

    md += "### Attachments\n"
    if iocs['attachments']:
        for att in iocs['attachments']:
            md += f"- **Filename:** {att.get('filename', 'Unknown')}\n"
            md += f"  - **Type:** {att.get('content_type', 'Unknown')}\n"
            md += f"  - **Size:** {att.get('size', 0)} bytes\n"
            md += f"  - **MD5:** `{att.get('md5', 'N/A')}`\n"
            md += f"  - **SHA256:** `{att.get('sha256', 'N/A')}`\n"
    else:
        md += "None found.\n"
        
    md += "\n## Recommended Actions\n"
    if verdict == 'Likely Phishing':
        md += "- **Block** the sender email address and extracted IPs/Domains at the gateway/firewall.\n"
        md += "- **Purge** the email from user inboxes.\n"
        md += "- **Investigate** if any users clicked the links or opened attachments.\n"
        md += "- **Reset** credentials if a user interacted with a phishing page.\n"
    elif verdict == 'Suspicious':
        md += "- **Quarantine** similar emails.\n"
        md += "- **Investigate** further to confirm intent.\n"
        md += "- **Monitor** for interaction with extracted IOCs.\n"
    else:
        md += "- **No immediate action required.** Continue normal monitoring.\n"

    return md

def report_to_json(report_data):
    return json.dumps(report_data, indent=4)

if __name__ == '__main__':
    # Simple test code could go here
    pass
