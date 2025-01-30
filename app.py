from flask import Flask, render_template, request, jsonify, session
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import timedelta
from uuid import uuid4
import os
import logging
from dotenv import load_dotenv
from flask import redirect, request
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
import json

from sync_manager import SCOPES, WhatsAppSyncManager
from auth_manager import setup_logging, login_required

# Load environment variables
load_dotenv()

# Initialize logging
logger = setup_logging()

# Initialize Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure app
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    raise ValueError("No FLASK_SECRET_KEY set in environment")

# Configure session settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max file size
)

# Configure upload settings
UPLOAD_FOLDER = os.path.join(os.getenv('RENDER_INTERNAL_TEMP_DIR', '/tmp'), 'whatsapp-sync')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize sync manager
sync_manager = WhatsAppSyncManager(UPLOAD_FOLDER)

@app.before_request
def initialize_session():
    if 'user_id' not in session and request.endpoint != 'static':
        session['user_id'] = str(uuid4())
        session['authenticated'] = False
        session['has_credentials'] = False
        session.modified = True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        if 'user_id' not in session:
            session['user_id'] = str(uuid4())
            session['authenticated'] = False
            session['has_credentials'] = False
            session.modified = True
        
        return jsonify({'status': 'success', 'user_id': session['user_id']})
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/oauth2callback')
def oauth2callback():
    try:
        # Get authorization code and state from callback
        code = request.args.get('code')
        state = request.args.get('state')
        
        if not code:
            return jsonify({'error': 'No authorization code received'}), 400
            
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'No user session found'}), 401
            
        # Complete OAuth flow and start sync
        credentials_path = os.path.join(
            app.config['UPLOAD_FOLDER'], 
            f'credentials_{user_id}.json'
        )
        
        with open(credentials_path, 'r') as f:
            creds_data = json.load(f)
            
        flow = InstalledAppFlow.from_client_config(
            creds_data,
            SCOPES
        )
        
        # Use the redirect URI from credentials.json
        flow.redirect_uri = creds_data['web']['redirect_uris'][0]
        
        # Fetch token using the authorization code
        flow.fetch_token(code=code)
        
        # Store the credentials
        token_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            f'token_{user_id}.pickle'
        )
        with open(token_path, 'wb') as token:
            pickle.dump(flow.credentials, token)
            
        session['authenticated'] = True
        session.modified = True
        
        # Start sync if WhatsApp directory is set
        if 'whatsapp_dir' in session:
            sync_manager.start_sync(user_id, session['whatsapp_dir'])
            
        return redirect('/?auth=success')
        
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return redirect('/?auth=error&message=' + str(e))
    
@app.route('/check-auth-status')
def check_auth_status():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'authenticated': False,
                'has_credentials': False,
                'is_syncing': False,
                'whatsapp_dir': None
            })

        status = sync_manager.get_user_status(user_id)
        session['has_credentials'] = status['has_credentials']
        session.modified = True
        
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error checking auth status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload-credentials', methods=['POST'])
def upload_credentials():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'No session found'}), 401

        if 'credentials' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['credentials']
        result = sync_manager.upload_credentials(user_id, file)
        
        if result['success']:
            session['has_credentials'] = True
            session.modified = True
            
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error uploading credentials: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/setup', methods=['POST'])
@login_required
def setup():
    try:
        user_id = session['user_id']
        whatsapp_dir = request.json.get('whatsapp_dir')
        
        result = sync_manager.setup_directory(user_id, whatsapp_dir)
        if result['success']:
            session['whatsapp_dir'] = whatsapp_dir
            session.modified = True
            
        return jsonify(result)
    except Exception as e:
        logger.error(f"Setup error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/start-sync', methods=['POST'])
@login_required
def start_sync():
    try:
        user_id = session['user_id']
        whatsapp_dir = session.get('whatsapp_dir')
        
        if not whatsapp_dir:
            return jsonify({'error': 'WhatsApp directory not set'}), 400
            
        result = sync_manager.start_sync(user_id, whatsapp_dir)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting sync: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/stop-sync', methods=['POST'])
@login_required
def stop_sync():
    try:
        user_id = session['user_id']
        result = sync_manager.stop_sync(user_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error stopping sync: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Clean up on shutdown
@app.teardown_appcontext
def cleanup(error):
    try:
        sync_manager.cleanup()
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)