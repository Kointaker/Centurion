# filename: centurion.py
import os.path
import argparse
import base64
import re
import sys
from typing import List, Optional, Tuple
from tqdm import tqdm
from time import sleep


# Gmail API modules
# Import errors if any are because modules are in virtual environment and not the computer itself
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.message import EmailMessage


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

def list_messages(creds, count, type):
    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=creds)
        results = (
            service.users().messages().list(userId="me", labelIds=[type]).execute()
        ) # LabelIds is the label that program will look in when listing messages
        # type is the user inputted type of label that will be parsed
        messages = results.get("messages", [])

        if not messages:
            print("No messages found.")
            print("")
            return

        print("Messages:")
        for message in messages[:count]:# <-----
            # number in brackets = number of messages shown
            msg = (
                service.users().messages().get(userId="me", id=message["id"], format="full").execute()
            )
            headers = {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", [])}
            date = headers.get("date", "")
            from_ = headers.get("from", "")
            subject = headers.get("subject", msg.get("snippet", ""))

            print(f"From:   {from_}")
            print(f'    Subject: {msg["snippet"]}')
            print(f"Date:  {date}")
            print(f'Message ID: {message["id"]}')
            print("")
    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f"An error occurred: {error}")

def query_search(service, user_id, keyword, amount) -> list[str]:
    """
    Return up to `amount` Gmail message IDs containing the keyword (case-insensitive),
    and print Date, From, Subject, and Message ID for each result.
    """
    if not keyword:
        raise ValueError("keyword must be a non-empty string")

    # Gmail search is case-insensitive by default; quoting matches the phrase exactly
    query = f'"{keyword}"'

    # List messages that match the query
    resp = service.users().messages().list(userId=user_id, q=query, maxResults=amount).execute()
    msgs = resp.get("messages", [])

    if not msgs:
        print("No messages found.")
        return []

    print("Messages:")
    for m in msgs[:amount]:
        # Fetch full message for headers
        msg_full = service.users().messages().get(
            userId=user_id,
            id=m["id"],
            format="full"
        ).execute()

        headers_map = {h["name"].lower(): h["value"] for h in msg_full.get("payload", {}).get("headers", [])}
        date = headers_map.get("date", "")
        from_ = headers_map.get("from", "")
        subject = headers_map.get("subject", msg_full.get("snippet", ""))

        print(f"Message ID: {m['id']}")
        print(f"Date:    {date}")
        print(f"From:    {from_}")
        print(f"Subject: {subject}")
        print("")

    return [m["id"] for m in msgs]

def inbox_choice(usrz):
    # Parses usrz and returns inbox selection
    if usrz == 1:
        return "INBOX"
    elif usrz == 2:
        return "SPAM"
    elif usrz == 3:
        return "TRASH"
    if usrz == 4:
        return "SENT"
    elif usrz == 5:
        return "DRAFT"
    elif usrz == 6:
        return "UNREAD"
    elif usrz == 7:
        return "STARRED"

def gmail_create_draft(creds):
# Email Drafting

    try:
        # Create gmail api client
        service = build("gmail", "v1", credentials=creds)

        message = EmailMessage()

        message.set_content("This is automated draft mail")

        message["To"] = "gduser1@workspacesamples.dev"
        message["From"] = "gduser2@workspacesamples.dev"
        message["Subject"] = "Automated draft"

        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {"message": {"raw": encoded_message}}
        # pylint: disable=E1101
        draft = (
            service.users()
            .drafts()
            .create(userId="me", body=create_message)
            .execute()
        )

        print(f'Draft id: {draft["id"]}\nDraft message: {draft["message"]}')

    except HttpError as error:
        print(f"An error occurred: {error}")
        draft = None

    return draft
