import os
import time
from flask import Flask, jsonify, request, render_template, flash, redirect, url_for, session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import secrets
from werkzeug.utils import secure_filename
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Configuration
SCOPES = ['https://www.googleapis.com/auth/drive.file']
UPLOAD_FOLDER = 'user_credentials'
ALLOWED_EXTENSIONS = {'json'}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# User sessions storage
user_sync_tools = {}

class UserWhatsAppSync:
    def __init__(self, user_id):
        self.user_id = user_id
        self.drive_service = None
        self.sync_status = {
            'is_running': False,
            'last_synced': None,
            'total_files_synced': 0,
            'last_error': None,
            'sync_directory': None
        }
        
    def get_credentials_path(self):
        return os.path.join(UPLOAD_FOLDER, f'credentials_{self.user_id}.json')
        
    def get_token_path(self):
        return os.path.join(UPLOAD_FOLDER, f'token_{self.user_id}.json')

    def authenticate(self):
        """Handles Google Drive authentication for specific user."""
        creds = None
        token_path = self.get_token_path()
        
        if os.path.exists(token_path):
            with open(token_path, 'r') as token:
                creds_data = json.load(token)
                creds = Credentials.from_authorized_user_info(creds_data, SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                credentials_path = self.get_credentials_path()
                if not os.path.exists(credentials_path):
                    raise Exception("Please upload credentials.json first")
                    
                flow = Flow.from_client_secrets_file(
                    credentials_path,
                    scopes=SCOPES,
                    redirect_uri=url_for('oauth2callback', _external=True)
                )
                
                # Store flow in session for callback
                auth_url, _ = flow.authorization_url(prompt='consent')
                session['current_flow'] = flow
                return auth_url

            # Save the credentials
            with open(token_path, 'w') as token:
                token.write(creds.to_json())

        self.drive_service = build('drive', 'v3', credentials=creds)
        return None  # Authentication successful

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Landing page with setup instructions."""
    user_id = session.get('user_id')
    if not user_id:
        user_id = secrets.token_urlsafe(16)
        session['user_id'] = user_id
        
    sync_tool = user_sync_tools.get(user_id)
    return render_template('index.html', 
                         sync_status=sync_tool.sync_status if sync_tool else None,
                         user_id=user_id)

@app.route('/upload_credentials', methods=['POST'])
def upload_credentials():
    """Handle credentials.json upload."""
    if 'credentials' not in request.files:
        flash('No file provided')
        return redirect(url_for('index'))
        
    file = request.files['credentials']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
        
    if file and allowed_file(file.filename):
        user_id = session.get('user_id')
        if not user_id:
            flash('Session expired')
            return redirect(url_for('index'))
            
        filename = f'credentials_{user_id}.json'
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        # Initialize sync tool for user
        sync_tool = UserWhatsAppSync(user_id)
        user_sync_tools[user_id] = sync_tool
        
        # Start OAuth flow
        try:
            auth_url = sync_tool.authenticate()
            if auth_url:
                return redirect(auth_url)
        except Exception as e:
            flash(f'Authentication error: {str(e)}')
            
        return redirect(url_for('index'))
        
    flash('Invalid file type')
    return redirect(url_for('index'))

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth callback."""
    flow = session.get('current_flow')
    if not flow:
        return 'Error: OAuth flow not found', 400
        
    flow.fetch_token(authorization_response=request.url)
    
    user_id = session.get('user_id')
    if not user_id:
        return 'Error: User session expired', 400
        
    sync_tool = user_sync_tools.get(user_id)
    if not sync_tool:
        return 'Error: Sync tool not initialized', 400
        
    # Save credentials
    creds = flow.credentials
    with open(sync_tool.get_token_path(), 'w') as token:
        token.write(creds.to_json())
        
    # Clean up
    session.pop('current_flow', None)
    
    flash('Successfully authenticated with Google Drive!')
    return redirect(url_for('index'))

@app.route('/set_sync_directory', methods=['POST'])
def set_sync_directory():
    """Set the directory to sync."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'status': 'error', 'message': 'Session expired'}), 401
        
    sync_tool = user_sync_tools.get(user_id)
    if not sync_tool:
        return jsonify({'status': 'error', 'message': 'Please upload credentials first'}), 400
        
    directory = request.form.get('directory')
    if not directory:
        return jsonify({'status': 'error', 'message': 'No directory provided'}), 400
        
    sync_tool.sync_status['sync_directory'] = directory
    return jsonify({'status': 'success', 'message': 'Sync directory updated'})

@app.route('/start', methods=['POST'])
def start_sync():
    """Start the sync service for a user."""
    user_id = session.get('user_id')
    if not user_id or user_id not in user_sync_tools:
        return jsonify({'status': 'error', 'message': 'Please set up credentials first'}), 400
        
    sync_tool = user_sync_tools[user_id]
    if not sync_tool.sync_status['sync_directory']:
        return jsonify({'status': 'error', 'message': 'Please set sync directory first'}), 400
        
    try:
        # Start sync process for user
        sync_tool.sync_status['is_running'] = True
        return jsonify({'status': 'success', 'message': 'Sync service started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/stop', methods=['POST'])
def stop_sync():
    """Stop the sync service for a user."""
    user_id = session.get('user_id')
    if not user_id or user_id not in user_sync_tools:
        return jsonify({'status': 'error', 'message': 'Service not running'}), 400
        
    try:
        sync_tool = user_sync_tools[user_id]
        sync_tool.sync_status['is_running'] = False
        return jsonify({'status': 'success', 'message': 'Sync service stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/status')
def get_status():
    """Get sync status for a user."""
    user_id = session.get('user_id')
    if not user_id or user_id not in user_sync_tools:
        return jsonify({'status': 'not_configured'})
        
    return jsonify(user_sync_tools[user_id].sync_status)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)