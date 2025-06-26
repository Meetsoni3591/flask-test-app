from flask import Flask, request, jsonify
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["*"], supports_credentials=True)  # Allow all origins for CORS
# Replace with your actual values
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URIS")
tokens = {}

def creds_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Flask server is running'}), 200
@app.route('/exchange', methods=['POST'])
def exchange():
    try:
        print("🔄 Exchange Request Received")
        code = request.json.get('code')
        print("🔄 Exchange Code:", code)
        if not code:
            return jsonify({'error': 'No code provided'}), 400

        flow = Flow.from_client_config({
            # from_client_secrets_file
            "web": {
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [REDIRECT_URI]
                }
            },
            scopes=[
            "https://www.googleapis.com/auth/gmail.send",
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
        )
        flow.redirect_uri = 'postmessage'  # 👈 match here too
        print("➡️ Using redirect_uri:", flow.redirect_uri)
        flow.fetch_token(code=code)
        print("✅ Token fetched successfully")
        print("🔑 Credentials:", flow.credentials)
        if not flow.credentials:
            return jsonify({'error': 'Failed to fetch credentials'}), 500
        creds = flow.credentials
        print("🔑 Credentials Object:", creds)
        idinfo = google_id_token.verify_oauth2_token(
            creds.id_token,
            google_requests.Request(),
            CLIENT_ID
        )

        user_id = idinfo['sub']
        user_email = idinfo['email']
        tokens[user_id] = creds_to_dict(creds)
        print("🆔 User ID:", user_id)
        print("📧 User Email:", user_email)
        print("🔑 Stored Tokens:", tokens)
        print("✅ Exchange successful")
        # Return user ID and email

        return jsonify({'id': user_id, 'email': user_email})
    except Exception as e:
        print("❌ Exchange Error:", str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/send', methods=['POST'])
def send():
    try:
        data = request.json
        print("📬 Send Request Data:", data)
        user_id = request.json.get('user_id')
        if user_id not in tokens:
            return jsonify({'error': 'Invalid user ID'}), 400

        creds_data = tokens[user_id]
        creds = Credentials(
            token=creds_data['token'],
            refresh_token=creds_data.get('refresh_token'),
            token_uri=creds_data['token_uri'],
            client_id=creds_data['client_id'],
            client_secret=creds_data['client_secret'],
            scopes=creds_data['scopes']
        )

        service = build('gmail', 'v1', credentials=creds)
        temp="meetstudy413@gmail.com"
        message = {
            'raw': create_message_raw(
                sender="me",
                to=temp,  # Replace with your temp mail
                subject="Test from Gmail API",
                body="This email is sent from the user's Gmail account."
            )
        }

        service.users().messages().send(userId='me', body=message).execute()
        print("📤 Mail sent!")
        response = {
            'status': 'Mail sent successfully',
            'email': temp
        }
        return jsonify(response), 200

    except Exception as e:
        print("❌ Send Mail Error:", str(e))
        return jsonify({'error': str(e)}), 500

import base64
from email.mime.text import MIMEText

def create_message_raw(sender, to, subject, body):
    message = MIMEText(body)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    return base64.urlsafe_b64encode(message.as_bytes()).decode()

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)