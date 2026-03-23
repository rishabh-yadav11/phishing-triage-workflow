# Phishing Triage Workflow

Automated phishing email analysis and triage tool. Parse `.eml` files, extract Indicators of Compromise (IOCs), calculate risk scores, and generate actionable reports.

## Features

- **Email Parsing** — Extract headers, body content, and attachments from `.eml` files
- **IOC Extraction** — Identify URLs, domains, IP addresses, email addresses, and file hashes
- **Risk Scoring** — Score-based analysis with weighted factors:
  - SPF/DKIM/DMARC authentication failures
  - Header mismatches (From/Return-Path/Reply-To)
  - Mismatched anchor links
  - URL shortener detection
  - Dangerous attachment types
  - Newly registered domains
- **Multiple Input Support** — Analyze single files, multiple files, or entire directories
- **Output Formats** — Markdown or JSON reports

## Installation

```bash
pip install -r requirements.txt
```

### Dependencies

- `beautifulsoup4` — HTML parsing
- `tldextract` — Domain extraction
- `dnspython` — DNS resolution for MX record checks

## Usage

### Single File

```bash
python main.py email.eml
```

### Multiple Files

```bash
python main.py file1.eml file2.eml file3.eml
```

### Directory

```bash
python main.py samples/
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --format` | Output format (`markdown` or `json`) | `markdown` |
| `-o, --output` | Save report to file | stdout |
| `-s, --summary` | Show summary table for multiple files | disabled |

### Examples

```bash
# Markdown output to stdout
python main.py suspicious_email.eml

# JSON output to file
python main.py suspicious_email.eml -f json -o report.json

# Analyze directory with summary
python main.py samples/ -s

# Analyze multiple files with individual reports
python main.py email1.eml email2.eml -o analysis.md
```

## Risk Scoring

| Score | Verdict | Action |
|-------|---------|--------|
| 0-29 | low | No immediate action required |
| 30-69 | Suspicious | Quarantine, investigate further |
| 70-100 | Likely Phishing | Block sender, purge emails, reset credentials |

### Scoring Factors

| Factor | Points |
|--------|--------|
| SPF failure | +30 |
| SPF unknown | +10 |
| DKIM failure | +20 |
| DMARC failure | +30 |
| Return-Path mismatch | +25 |
| Reply-To mismatch | +15 |
| Mismatched anchor links | +40 |
| URL shortener | +20 per URL |
| Dangerous attachment | +50 per file |
| Known malicious hash | +100 |
| Newly registered domain | +35 |
| Domain without MX | +15 |

## Project Structure

```
.
├── main.py        # CLI entry point
├── parser.py     # Email (.eml) parsing
├── ioc.py         # IOC extraction
├── analyzer.py    # Risk scoring logic
├── report.py      # Report generation
├── samples/       # Sample phishing emails for testing
└── requirements.txt
```

## Sample Output

```
# Phishing Triage Report

## Verdict: 🔴 **Likely Phishing** (Risk Score: 95/100)

### Key Reasons:
- SPF check failed (+30)
- DMARC check failed (+30)
- Found 2 mismatched anchor links (+40)
- Dangerous attachment type detected: invoice.exe (+50)
- URL shortener detected: bit.ly/fake-link (+20)

## Email Metadata
- **Subject:** Invoice #48291 Due Today
- **From:** billing@secure-invoice.net
- **Date:** Mon, 23 Mar 2026 10:30:00 +0000

## Authentication Results
- **SPF:** fail
- **DKIM:** unknown
- **DMARC:** fail

## Extracted IOCs
### URLs
- https://bit.ly/fake-link
- http://malicious-site.com/login

### ⚠️ Mismatched Links Found:
- Visible Text: `https://amazon.com/orders` -> Destination: `http://malicious-site.com/login`

### Attachments
- **Filename:** invoice.exe
  - **Type:** application/x-msdownload
  - **Size:** 156000 bytes
  - **MD5:** `a1b2c3d4e5f6...`
  - **SHA256:** `deadbeef...`

## Recommended Actions
- **Block** the sender email address and extracted IPs/Domains at the gateway/firewall.
- **Purge** the email from user inboxes.
- **Investigate** if any users clicked the links or opened attachments.
- **Reset** credentials if a user interacted with a phishing page.
```

## Extending

### Adding IOC Lookups

Edit `analyzer.py` to add real-time checks against threat intelligence feeds:

```python
MOCK_MALICIOUS_HASHES = ['known-bad-hash-here']
```

### Custom Scoring Weights

Adjust point values in `analyzer.py` `calculate_risk_score()` to tune for your environment.

### Additional Output Formats

Add new format functions in `report.py`:

```python
def report_to_csv(report_data):
    # Implement CSV export
    pass
```
