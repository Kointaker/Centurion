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

# Function imports


from centurion_functions import gmail_search_messages, gmail_get_message_full, extract_headers, decode_part_body, flatten_message_body, find_verification_codes_in_text, search_recent_verification_code, build_service, list_labels, list_messages, query_search, inbox_choice, gmail_create_draft








# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly",
       "https://www.googleapis.com/auth/gmail.compose"]

parser = argparse.ArgumentParser(description="Gmail helper (labels + verification code search)")
parser.add_argument("--code", action="store_true", help="Search for a recent verification code instead of listing labels")
parser.add_argument("--window", type=int, default=20, help="Minutes to look back for the code (default: 20)")
args = parser.parse_args()


# Pattern that Centurion will look for 
# when searching for verification codes
CODE_PATTERNS = [
    r"\b(\d{6})\b",
    r"\b(\d{7,8})\b",
    r"code[:\s-]+(\d{6,8})",
    r"verification\s*code[:\s-]+(\d{6,8})",
    r"one[-\s]*time\s*password[:\s-]+(\d{6,8})",
    r"otp[:\s-]+(\d{4,8})",
    r"security\s*code[:\s-]+(\d{6,8})",
]

# Patterns that Centurion will look for
# when searching for promo codes
PROMO_CODE_PATTERNS = [
    r"\bpromo\s*code[:\s-]+([A-Z0-9][A-Z0-9._\-]{3,49})\b",
    r"\bdiscount\s*code[:\s-]+([A-Z0-9][A-Z0-9._\-]{3,49})\b",
    r"\buse\s*code[:\s-]+([A-Z0-9][A-Z0-9._\-]{3,49})\b",
    r"\bapply\s*code[:\s-]+([A-Z0-9][A-Z0-9._\-]{3,49})\b",
    r"\bcoupon\s*code[:\s-]+([A-Z0-9][A-Z0-9._\-]{3,49})\b",
    r"\bcode[:\s-]+([A-Z0-9][A-Z0-9._\-]{3,49})\b",
]







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
V - Draft new message
W - Search messages using keyword
X - List Labels
Y - Search for auth/verification codes  
Z - List Messages

:: """).upper()
    print("\n\n\n")


    
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




    if usr == "V":
        service = build_service(creds)
        gmail_create_draft(creds)

    if usr == "W":
        service = build_service(creds)
        keyword = input("Enter keyword to search by: ")
        amt = int(input("How many messages to display? "))
        query_search(service, "me", keyword, amt)


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
    
    if usr == "Z":
        # Needed parameters
        usrx = int(input("How many messages would you like to see? "))
        usrz = int(input("""
Which messages would you like to print:
1. Inbox
2. Spam
3. Trash
4. Sent
5. Draft
6. Unread
7. Starred                         
:: """))
        
        # Gets the inbox choice ready for the list_messages function
        type = inbox_choice(usrz)

        # Service and function running
        service = build_service(creds)
        # extract_headers()
        list_messages(creds, usrx, type)
        

if __name__ == "__main__":
    main()
