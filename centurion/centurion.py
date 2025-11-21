# filename: centurion.py
import os.path
import argparse
import base64
import re
import sys
from typing import List, Optional, Tuple
from tqdm import tqdm
from time import sleep

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]



## Commands:
# python centurion.py --code --window 30 (Search for verification codes from messages





#parser = argparse.ArgumentParser(description="Gmail helper (labels + verification code search)")
#parser.add_argument("--code", action="store_true", help="Search for a recent verification code instead of listing labels")
#parser.add_argument("--window", type=int, default=20, help="Minutes to look back for the code (default: 20)")
#args = parser.parse_args()




# ---------- Verification code helpers ----------

CODE_PATTERNS = [
    r"\b(\d{6})\b",
    r"\b(\d{7,8})\b",
    r"code[:\s-]+(\d{6,8})",
    r"verification\s*code[:\s-]+(\d{6,8})",
    r"one[-\s]*time\s*password[:\s-]+(\d{6,8})",
    r"otp[:\s-]+(\d{4,8})",
    r"security\s*code[:\s-]+(\d{6,8})",
]

def gmail_search_messages(service, query: str, max_results: int = 20, label_ids: Optional[List[str]] = None) -> List[dict]:
    """Search Gmail messages via query; returns list of message metadata dicts with id."""
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
    """Get the full message payload."""
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
    """Decode a MIME part body (base64url-encoded)."""
    data = part.get("body", {}).get("data")
    if not data:
        return ""
    decoded_bytes = base64.urlsafe_b64decode(data.encode("utf-8"))
    return decoded_bytes.decode("utf-8", errors="replace")

def flatten_message_body(message: dict) -> Tuple[str, str]:
    """
    Return (text_body, html_body) from a Gmail message.
    Traverses multipart; converts HTML to text if needed; falls back to snippet.
    """
    payload = message.get("payload", {})
    text_body = ""
    html_body = ""

    def walk(p):
        nonlocal text_body, html_body
        mime = p.get("mimeType", "")
        if "multipart" in mime:
            for sp in p.get("parts", []):
                walk(sp)
        else:
            body = decode_part_body(p)
            if mime == "text/plain":
                text_body += f"\n{body}"
            elif mime == "text/html":
                html_body += f"\n{body}"
            else:
                if not text_body and body and "text" in mime:
                    text_body += f"\n{body}"

    walk(payload)

    if not text_body and html_body:
        import html2text
        h2t = html2text.HTML2Text()
        h2t.ignore_links = False
        h2t.ignore_images = True
        text_body = h2t.handle(html_body)

    if not text_body:
        text_body = message.get("snippet", "")

    return (text_body.strip(), html_body.strip())

def find_verification_codes_in_text(text: str) -> List[str]:
    """Find likely verification codes with regex; deduplicate."""
    candidates = []
    for pat in CODE_PATTERNS:
        for m in re.findall(pat, text, flags=re.IGNORECASE):
            candidates.append(m)
    seen = set()
    result = []
    for c in candidates:
        if c not in seen and 4 <= len(c) <= 8:
            result.append(c)
            seen.add(c)
    return result

def search_recent_verification_code(service, window_minutes: int = 20) -> Optional[Tuple[str, dict]]:
    """
    Search for the most recent verification code email in the last window_minutes.
    Returns (code, headers) or None.
    """
    # Use Gmail-supported relative time operator
    query = f"newer_than:{window_minutes}m (otp OR verification OR code OR passcode OR security) -category:social"
    messages = gmail_search_messages(service, query=query, max_results=25)
    if not messages:
        return None

    # Iterate newest first (list API returns approx newest first already)
    for m in messages:
        full = gmail_get_message_full(service, m["id"])
        if not full:
            continue
        headers = extract_headers(full)
        text_body, html_body = flatten_message_body(full)
        combined = f"{headers.get('subject','')}\n{text_body}\n{html_body}"
        codes = find_verification_codes_in_text(combined)
        if codes:
            return (codes[0], headers)
    return None

# ---------- Original boilerplate flow with CLI toggle ----------

def build_service(creds):
    return build("gmail", "v1", credentials=creds)

def list_labels(service):
    results = service.users().labels().list(userId="me").execute()
    labels = results.get("labels", [])
    if not labels:
        print("No labels found.")
        return
    print("Labels:")
    for label in labels:
        print(label["name"])

def main():
    """
    Default: list labels
    Optional: --code [--window M] to search and display a verification code
    """
    print("Booting Centurion:")
    for i in tqdm(range(100)):
        # do work
        sleep(0.01)
    usr = input("""
X - List Labels
Y - Search for auth/verification codes  
          """).upper()



    
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())





    if usr == "X":
        service = build_service(creds)
        list_labels(service)

    if usr == "Y":
        try:
            service = build_service(creds)
            res = search_recent_verification_code(service, window_minutes=args.window)
            
            if not res:
                print("No verification codes found in the recent window.")
                return
            code, headers = res
            print("----- VERIFICATION CODE FOUND -----")
            print(f"Code: {code}")
            print(f"From: {headers.get('from')}")
            print(f"Subject: {headers.get('subject')}")
            print(f"Date: {headers.get('date')}")



        except HttpError as error:
            print(f"An error occurred: {error}")

if __name__ == "__main__":
    main()
