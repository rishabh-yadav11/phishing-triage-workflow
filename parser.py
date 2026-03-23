import email
from email import policy
import hashlib

def parse_eml(file_path):
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    
    parsed_data = {
        'headers': {
            'From': msg.get('From', ''),
            'Return-Path': msg.get('Return-Path', ''),
            'Reply-To': msg.get('Reply-To', ''),
            'Subject': msg.get('Subject', ''),
            'Date': msg.get('Date', ''),
            'Message-ID': msg.get('Message-ID', ''),
        },
        'auth_results': msg.get('Authentication-Results', ''),
        'received': msg.get_all('Received', []),
        'body': {
            'text': '',
            'html': ''
        },
        'attachments': []
    }
    
    # Process payload
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", ""))
        
        if "attachment" in content_disposition or part.get_filename():
            filename = part.get_filename() or "unknown"
            payload = part.get_payload(decode=True)
            if payload:
                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()
                parsed_data['attachments'].append({
                    'filename': filename,
                    'content_type': content_type,
                    'size': len(payload),
                    'md5': md5_hash,
                    'sha256': sha256_hash
                })
        else:
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    parsed_data['body']['text'] += payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
            elif content_type == 'text/html':
                payload = part.get_payload(decode=True)
                if payload:
                    parsed_data['body']['html'] += payload.decode(part.get_content_charset() or 'utf-8', errors='replace')

    return parsed_data

if __name__ == '__main__':
    # Simple test code could go here
    pass
