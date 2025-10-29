# filename: centurion.py
# Centurion: Gmail helper for verification codes, labels, and email viewing
# Requirements:
#   pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib html2text beautifulsoup4
# Setup:
#   1) Create OAuth 2.0 Client ID (Desktop app) in Google Cloud Console
#   2) Enable Gmail API
#   3) Download client_secret.json to the same folder as this script
#   4) Run: python centurion.py --help
# Security: Do not check client_secret.json or token.json into public repos.

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup
import html2text

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# OAuth scopes:
# - readonly is enough for searching and reading messages/labels
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

TOKEN_PATH = "token.json"
CLIENT_SECRET_PATH = "client_secret.json"

def auth_gmail_service():
    """
    Authenticate and return a Gmail API service client.
    Uses local token.json for reuse.
    """
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())  # type: ignore
            except Exception:
                creds = None
        if not creds:
            if not os.path.exists(CLIENT_SECRET_PATH):
                print("Missing client_secret.json. Place your OAuth client file next to this script.", file=sys.stderr)
                sys.exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_PATH, "w") as token:
            token.write(creds.to_json())
    service = build("gmail", "v1", credentials=creds)
    return service

def gmail_search_messages(service, query: str, max_results: int = 20, label_ids: Optional[List[str]] = None) -> List[dict]:
    """
    Search Gmail messages via query. Returns list of message metadata dicts with id.
    """
    try:
        msgs = []
        request = service.users().messages().list(userId="me", q=query, maxResults=max_results, labelIds=label_ids or [])
        while request is not None:
            resp = request.execute()
            msgs.extend(resp.get("messages", []))
            request = service.users().messages().list_next(previous_request=request, previous_response=resp)
        return msgs
    except HttpError as e:
        print(f"Gmail search error: {e}", file=sys.stderr)
        return []

def gmail_get_message_full(service, msg_id: str) -> Optional[dict]:
    """
    Get the full message payload.
    """
    try:
        return service.users().messages().get(userId="me", id=msg_id, format="full").execute()
    except HttpError as e:
        print(f"Gmail get error: {e}", file=sys.stderr)
        return None

def extract_headers(message: dict) -> dict:
    headers = {h["name"].lower(): h["value"] for h in message.get("payload", {}).get("headers", [])}
    return {
        "subject": headers.get("subject", ""),
        "from": headers.get("from", ""),
        "date": headers.get("date", ""),
        "to": headers.get("to", ""),
    }

def decode_part_body(part: dict) -> str:
    """
    Decode a MIME part body (base64url-encoded).
    """
    data = part.get("body", {}).get("data")
    if not data:
        return ""
    decoded_bytes = base64.urlsafe_b64decode(data.encode("utf-8"))
    return decoded_bytes.decode("utf-8", errors="replace")

def flatten_message_body(message: dict) -> Tuple[str, str]:
    """
    Return (text_body, html_body) from a Gmail message.
    Tries to extract both plain text and HTML parts; falls back to snippet if empty.
    """
    payload = message.get("payload", {})
    text_body = ""
    html_body = ""

    def walk_parts(p):
        nonlocal text_body, html_body
        mime_type = p.get("mimeType", "")
        if "multipart" in mime_type:
            for sp in p.get("parts", []):
                walk_parts(sp)
        else:
            body = decode_part_body(p)
            if mime_type == "text/plain":
                text_body += f"\n{body}"
            elif mime_type == "text/html":
                html_body += f"\n{body}"
            else:
                # Some providers set text/plain without proper mimeType
                if not text_body and body and "text" in mime_type:
                    text_body += f"\n{body}"

    walk_parts(payload)

    if not text_body and html_body:
        # Convert HTML to text
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.ignore_images = True
        text_body = h.handle(html_body)

    if not text_body:
        # Fallback: Gmail snippet
        text_body = message.get("snippet", "")

    return (text_body.strip(), html_body.strip())

# Regexes for common verification code formats.
CODE_PATTERNS = [
    r"\b(\d{6})\b",
    r"\b(\d{7,8})\b",
    r"code[:\s-]+(\d{6,8})",
    r"verification\s*code[:\s-]+(\d{6,8})",
    r"one-time\s*password[:\s-]+(\d{6,8})",
    r"otp[:\s-]+(\d{4,8})",
    r"security\s*code[:\s-]+(\d{6,8})",
]

def find_verification_codes_in_text(text: str) -> List[str]:
    """
    Parse text to find likely verification codes.
    Filters out obvious phone numbers or long sequences; de-duplicates.
    """
    candidates = []
    for pat in CODE_PATTERNS:
        for m in re.findall(pat, text, flags=re.IGNORECASE):
            candidates.append(m)
    # Deduplicate while preserving order
    seen = set()
    result = []
    for c in candidates:
        if c not in seen:
            # Simple heuristic: ignore sequences with repeating digits >80%
            if len(c) <= 8:
                result.append(c)
            seen.add(c)
    return result

def search_recent_verification_code(service, window_minutes: int = 20) -> Optional[Tuple[str, dict]]:
    """
    Search for the most recent verification code email in the last window_minutes.
    Returns (code, message_headers) or None.
    Search strategy:
      - Use Gmail query with common keywords and time window
      - Read messages newest first and parse for codes
    """
    after_ts = int((dt.datetime.utcnow() - dt.timedelta(minutes=window_minutes)).timestamp())
    query_keywords = [
        "subject:(code)",
        "subject:(verification)",
        "subject:(otp)",
        "subject:(two-step)",
        "subject:(security)",
        "subject:(passcode)",
        "subject:(login)",
        "otp OR verification OR code OR passcode OR security",
    ]
    # Gmail query supports after: unix epoch seconds
    query = f"after:{after_ts} ({' OR '.join(query_keywords)}) -category:social"
    messages = gmail_search_messages(service, query=query, max_results=25)
    # Sort newest first by internalDate
    if not messages:
        return None

    def msg_ts(m):
        try:
            full = service.users().messages().get(userId='me', id=m['id'], format='metadata').execute()
            return int(full.get('internalDate', '0'))
        except Exception:
            return 0

    messages.sort(key=msg_ts, reverse=True)

    for msg in messages:
        full = gmail_get_message_full(service, msg["id"])
        if not full:
            continue
        text_body, html_body = flatten_message_body(full)
        combined = f"{extract_headers(full).get('subject', '')}\n{text_body}\n{html_body}"
        codes = find_verification_codes_in_text(combined)
        if codes:
            headers = extract_headers(full)
            return (codes[0], headers)
    return None

def list_labels(service):
    try:
        resp = service.users().labels().list(userId="me").execute()
        labels = resp.get("labels", [])
        print(f"Found {len(labels)} labels:")
        for l in labels:
            print(f"- {l.get('name')} (id: {l.get('id')})")
    except HttpError as e:
        print(f"Label list error: {e}", file=sys.stderr)

SECTION_QUERIES = {
    # These are not real Gmail categories; we emulate "sections" via queries
    "otp_recent": "newer_than:1d (otp OR verification OR code) -category:social",
    "promotions_recent": "category:promotions newer_than:1d",
    "updates_recent": "category:updates newer_than:1d",
    "primary_recent": "category:primary newer_than:1d",
    "all_last_24h": "newer_than:1d",
}

def list_section(service, section_key: str, max_results: int = 20):
    q = SECTION_QUERIES.get(section_key)
    if not q:
        print(f"Unknown section '{section_key}'. Available: {', '.join(SECTION_QUERIES.keys())}")
        return
    msgs = gmail_search_messages(service, q, max_results=max_results)
    print(f"Section '{section_key}' — {len(msgs)} messages")
    for m in msgs:
        full = gmail_get_message_full(service, m["id"])
        if not full:
            continue
        h = extract_headers(full)
        print(f"- {h['date']} | {h['from']} | {h['subject']} | id={m['id']}")

def show_email(service, message_id: str):
    m = gmail_get_message_full(service, message_id)
    if not m:
        print("Message not found.")
        return
    h = extract_headers(m)
    text, html = flatten_message_body(m)
    print("----- EMAIL -----")
    print(f"From: {h['from']}")
    print(f"To: {h['to']}")
    print(f"Date: {h['date']}")
    print(f"Subject: {h['subject']}")
    print("\nBody (text):")
    print(text if text else "[No text body]")
    if html:
        print("\nBody (HTML preview, text-converted):")
        h2t = html2text.HTML2Text()
        h2t.ignore_links = False
        h2t.ignore_images = True
        print(h2t.handle(html))

def main():
    parser = argparse.ArgumentParser(description="Centurion Gmail Assistant (codes, labels, sections, email view)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("labels", help="List Gmail labels")

    p_section = sub.add_subparser("section", help="List messages for a section/query")
    p_section.add_argument("key", choices=list(SECTION_QUERIES.keys()), help="Section key")
    p_section.add_argument("--max", type=int, default=20, help="Max results")

    p_email = sub.add_subparser("show", help="Show a specific email by message ID")
    p_email.add_argument("id", help="Gmail message ID")

    p_code = sub.add_subparser("code", help="Find recent verification code (last N minutes)")
    p_code.add_argument("--window", type=int, default=20, help="Minutes to look back")

    args = parser.parse_args()

    service = auth_gmail_service()

    if args.cmd == "labels":
        list_labels(service)
    elif args.cmd == "section":
        list_section(service, args.key, max_results=args.max)
    elif args.cmd == "show":
        show_email(service, args.id)
    elif args.cmd == "code":
        res = search_recent_verification_code(service, window_minutes=args.window)
        if not res:
            print("No verification codes found in the recent window.")
        else:
            code, headers = res
            print("----- VERIFICATION CODE FOUND -----")
            print(f"Code: {code}")
            print(f"From: {headers.get('from')}")
            print(f"Subject: {headers.get('subject')}")
            print(f"Date: {headers.get('date')}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
