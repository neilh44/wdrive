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
from typing import Dict
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Configuration
SCOPES = ['https://www.googleapis.com/auth/drive.file']
UPLOAD_FOLDER = 'user_credentials'
ALLOWED_EXTENSIONS = {'json'}
SYNC_TOOLS_FILE = 'sync_tools.json'
SYNC_TOOLS_DIR = 'sync_tools_data'

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SYNC_TOOLS_DIR, exist_ok=True)

SYNC_TOOLS_PATH = os.path.join(SYNC_TOOLS_DIR, SYNC_TOOLS_FILE)

# User sessions storage
user_sync_tools = {}

class UserWhatsAppSync:
    def __init__(self, user_id):
        """Initialize with error handling."""
        try:
            self.user_id = user_id
            self.drive_service = None
            self.sync_status = {
                'is_running': False,
                'last_synced': None,
                'total_files_synced': 0,
                'last_error': None,
                'sync_directory': None
            }
            logger.debug(f"Successfully initialized sync tool for user: {user_id}")
        except Exception as e:
            logger.error(f"Error initializing sync tool: {str(e)}")
            raise
        
    def get_credentials_path(self):
        return os.path.join(UPLOAD_FOLDER, f'credentials_{self.user_id}.json')
        
    def get_token_path(self):
        return os.path.join(UPLOAD_FOLDER, f'token_{self.user_id}.json')

    def authenticate(self):
        """Handles Google Drive authentication for specific user."""
        creds = None
        token_path = self.get_token_path()
        
        if os.path.exists(token_path):
            try:
                with open(token_path, 'r') as token:
                    creds_data = json.load(token)
                    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
                logger.debug(f"Loaded existing credentials for user: {self.user_id}")
            except Exception as e:
                logger.error(f"Error loading credentials: {str(e)}")
                raise

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    logger.debug(f"Refreshed expired credentials for user: {self.user_id}")
                except Exception as e:
                    logger.error(f"Error refreshing credentials: {str(e)}")
                    raise
            else:
                credentials_path = self.get_credentials_path()
                if not os.path.exists(credentials_path):
                    logger.error(f"Credentials file not found for user: {self.user_id}")
                    raise Exception("Please upload credentials.json first")
                    
                flow = Flow.from_client_secrets_file(
                    credentials_path,
                    scopes=SCOPES,
                    redirect_uri=url_for('oauth2callback', _external=True)
                )
                
                auth_url, _ = flow.authorization_url(prompt='consent')
                session['current_flow'] = flow
                logger.debug(f"Started new OAuth flow for user: {self.user_id}")
                return auth_url

            # Save the credentials
            try:
                with open(token_path, 'w') as token:
                    token.write(creds.to_json())
                logger.debug(f"Saved new credentials for user: {self.user_id}")
            except Exception as e:
                logger.error(f"Error saving credentials: {str(e)}")
                raise

        self.drive_service = build('drive', 'v3', credentials=creds)
        return None  # Authentication successful

def save_sync_tools() -> None:
    """Save sync tools state to file."""
    try:
        data: Dict = {}
        for user_id, tool in user_sync_tools.items():
            data[user_id] = {
                'sync_status': tool.sync_status,
                'credentials_path': tool.get_credentials_path(),
                'token_path': tool.get_token_path(),
                'last_saved': datetime.now().isoformat()
            }
        
        with open(SYNC_TOOLS_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            
        logger.debug(f"Successfully saved sync tools data for {len(data)} users")
        
    except Exception as e:
        logger.error(f"Error saving sync tools data: {str(e)}")
        raise

def load_sync_tools() -> None:
    """Load sync tools state from file."""
    try:
        if not os.path.exists(SYNC_TOOLS_PATH):
            logger.info("No existing sync tools data found")
            return
            
        with open(SYNC_TOOLS_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for user_id, tool_data in data.items():
            try:
                sync_tool = UserWhatsAppSync(user_id)
                sync_tool.sync_status = tool_data['sync_status']
                user_sync_tools[user_id] = sync_tool
                logger.debug(f"Restored sync tool for user: {user_id}")
            except Exception as e:
                logger.error(f"Error restoring sync tool for user {user_id}: {str(e)}")
                continue
                
        logger.info(f"Successfully loaded sync tools data for {len(user_sync_tools)} users")
        
    except Exception as e:
        logger.error(f"Error loading sync tools data: {str(e)}")
        raise

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Landing page with setup instructions."""
    user_id = session.get('user_id')
    if not user_id:
        user_id = secrets.token_urlsafe(16)
        session['user_id'] = user_id
        logger.debug(f"Created new user session with id: {user_id}")
    else:
        logger.debug(f"Existing user session found with id: {user_id}")
    
    # Initialize sync tool if it doesn't exist
    if user_id not in user_sync_tools:
        logger.debug(f"Initializing new sync tool for user: {user_id}")
        sync_tool = UserWhatsAppSync(user_id)
        user_sync_tools[user_id] = sync_tool
    else:
        sync_tool = user_sync_tools[user_id]
        logger.debug(f"Found existing sync tool for user: {user_id}")
        
    return render_template('index.html', 
                         sync_status=sync_tool.sync_status if sync_tool else None,
                         user_id=user_id)

@app.route('/upload_credentials', methods=['POST'])
def upload_credentials():
    """Handle credentials.json upload with enhanced error logging."""
    logger.debug("Starting credentials upload")
    logger.debug(f"Request files: {request.files}")
    logger.debug(f"Request form: {request.form}")
    
    try:
        if 'credentials' not in request.files:
            logger.error("No 'credentials' field in request.files")
            logger.debug(f"Available fields: {list(request.files.keys())}")
            flash('No file provided')
            return redirect(url_for('index'))
            
        file = request.files['credentials']
        logger.debug(f"Received file: {file.filename}")
        logger.debug(f"Content type: {file.content_type}")
        
        if file.filename == '':
            logger.error("Empty filename provided")
            flash('No file selected')
            return redirect(url_for('index'))
            
        if not allowed_file(file.filename):
            logger.error(f"Invalid file type: {file.filename}")
            flash('Invalid file type. Only .json files are allowed.')
            return redirect(url_for('index'))
            
        user_id = session.get('user_id')
        logger.debug(f"Processing upload for user_id: {user_id}")
        
        if not user_id:
            logger.error("No user_id in session during upload")
            flash('Session expired')
            return redirect(url_for('index'))
            
        try:
            # Read file content to verify it's valid JSON
            content = file.read()
            file.seek(0)  # Reset file pointer
            json.loads(content)  # Verify JSON is valid
            
            # Save file
            filename = f'credentials_{user_id}.json'
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            logger.debug(f"Saved credentials file to: {filepath}")
            
            # Verify file was saved
            if not os.path.exists(filepath):
                raise Exception("File was not saved successfully")
                
            # Initialize sync tool
            sync_tool = UserWhatsAppSync(user_id)
            user_sync_tools[user_id] = sync_tool
            
            # Save state
            save_sync_tools()
            logger.debug("Saved sync tools state")
            
            # Start OAuth flow
            try:
                flow = Flow.from_client_secrets_file(
                    filepath,
                    scopes=SCOPES,
                    redirect_uri=url_for('oauth2callback', _external=True)
                )
                
                # Instead of storing the entire flow object, store just the necessary state
                auth_url, state = flow.authorization_url(prompt='consent')
                session['oauth_state'] = state
                session['credentials_path'] = filepath
                
                logger.debug(f"Starting OAuth flow with URL: {auth_url}")
                return redirect(auth_url)
                
            except Exception as e:
                logger.error(f"Authentication error: {str(e)}")
                flash(f'Authentication error: {str(e)}')
                return redirect(url_for('index'))
            
        except json.JSONDecodeError:
            logger.error("Invalid JSON file uploaded")
            flash('Invalid JSON file format')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Error saving file: {str(e)}")
            flash(f'Error saving file: {str(e)}')
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"Error in upload_credentials: {str(e)}")
        flash(f'Upload error: {str(e)}')
        return redirect(url_for('index'))


@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth callback with state verification."""
    try:
        # Verify state
        if 'oauth_state' not in session:
            logger.error("OAuth state not found in session")
            return 'Error: OAuth flow not found', 400
            
        credentials_path = session.get('credentials_path')
        if not credentials_path:
            logger.error("Credentials path not found in session")
            return 'Error: Invalid OAuth flow', 400
            
        # Recreate flow with stored state
        flow = Flow.from_client_secrets_file(
            credentials_path,
            scopes=SCOPES,
            state=session['oauth_state'],
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        # Complete the flow
        flow.fetch_token(authorization_response=request.url)
        
        user_id = session.get('user_id')
        if not user_id:
            logger.error("User session expired during OAuth callback")
            return 'Error: User session expired', 400
            
        sync_tool = user_sync_tools.get(user_id)
        if not sync_tool:
            logger.error("Sync tool not found during OAuth callback")
            return 'Error: Sync tool not initialized', 400
            
        # Save credentials
        creds = flow.credentials
        with open(sync_tool.get_token_path(), 'w') as token:
            token.write(creds.to_json())
            
        # Clean up session
        session.pop('oauth_state', None)
        session.pop('credentials_path', None)
        
        logger.debug(f"Successfully completed OAuth flow for user: {user_id}")
        flash('Successfully authenticated with Google Drive!')
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Error in OAuth callback: {str(e)}")
        return f'Error during OAuth: {str(e)}', 400

@app.route('/set_sync_directory', methods=['POST'])
def set_sync_directory():
    """Set sync directory with persistent storage."""
    try:
        user_id = session.get('user_id')
        if not user_id:
            logger.error("No user_id in session during set_sync_directory")
            return jsonify({'status': 'error', 'message': 'Session expired'}), 401
            
        sync_tool = user_sync_tools.get(user_id)
        if not sync_tool:
            logger.error(f"No sync tool found for user: {user_id}")
            return jsonify({'status': 'error', 'message': 'Please upload credentials first'}), 400
            
        directory = request.form.get('directory')
        if not directory:
            logger.error("No directory provided")
            return jsonify({'status': 'error', 'message': 'No directory provided'}), 400
            
        # Update sync directory
        sync_tool.sync_status['sync_directory'] = directory
        
        # Save state
        save_sync_tools()
        
        logger.debug(f"Successfully set sync directory for user {user_id}: {directory}")
        return jsonify({'status': 'success', 'message': 'Sync directory updated'})
        
    except Exception as e:
        logger.error(f"Error in set_sync_directory: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/start', methods=['POST'])
def start_sync():
    """Start the sync service for a user."""
    try:
        user_id = session.get('user_id')
        if not user_id or user_id not in user_sync_tools:
            logger.error(f"Invalid user_id in start_sync: {user_id}")
            return jsonify({'status': 'error', 'message': 'Please set up credentials first'}), 400
            
        sync_tool = user_sync_tools[user_id]
        if not sync_tool.sync_status['sync_directory']:
            logger.error(f"No sync directory set for user: {user_id}")
            return jsonify({'status': 'error', 'message': 'Please set sync directory first'}), 400
            
        # Start sync process for user
        sync_tool.sync_status['is_running'] = True
        save_sync_tools()  # Save the running state
        
        logger.debug(f"Started sync process for user: {user_id}")
        return jsonify({'status': 'success', 'message': 'Sync service started'})
        
    except Exception as e:
        logger.error(f"Error in start_sync: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/stop', methods=['POST'])
def stop_sync():
    """Stop the sync service for a user."""
    try:
        user_id = session.get('user_id')
        if not user_id or user_id not in user_sync_tools:
            logger.error(f"Invalid user_id in stop_sync: {user_id}")
            return jsonify({'status': 'error', 'message': 'Service not running'}), 400
            
        sync_tool = user_sync_tools[user_id]
        sync_tool.sync_status['is_running'] = False
        save_sync_tools()  # Save the stopped state
        
        logger.debug(f"Stopped sync process for user: {user_id}")
        return jsonify({'status': 'success', 'message': 'Sync service stopped'})
        
    except Exception as e:
        logger.error(f"Error in stop_sync: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/status')
def get_status():
    """Get sync status for a user with debugging."""
    user_id = session.get('user_id')
    
    # Add debugging
    logger.debug(f"Current user_id from session: {user_id}")
    logger.debug(f"Available sync tools: {list(user_sync_tools.keys())}")
    
    if not user_id:
        logger.debug("No user_id in session")
        return jsonify({
            'status': 'not_configured',
            'reason': 'No user session'
        })
        
    if user_id not in user_sync_tools:
        logger.debug(f"User {user_id} has no sync tool configured")
        return jsonify({
            'status': 'not_configured',
            'reason': 'Sync tool not initialized'
        })
        
    sync_status = user_sync_tools[user_id].sync_status
    logger.debug(f"Returning sync status for user {user_id}: {sync_status}")
    return jsonify(sync_status)

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    logger.error(f"404 error: {error}")
    return jsonify({'status': 'error', 'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"500 error: {error}")
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.before_request
def before_request():
    """Ensure user session exists."""
    if request.endpoint != 'static':
        user_id = session.get('user_id')
        if not user_id and request.endpoint != 'index':
            logger.warning("No user_id in session, redirecting to index")
            return redirect(url_for('index'))

def cleanup_old_files():
    """Clean up old credential files that haven't been accessed in 24 hours."""
    try:
        current_time = time.time()
        for filename in os.listdir(UPLOAD_FOLDER):
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(filepath):
                # Check if file is older than 24 hours
                if current_time - os.path.getmtime(filepath) > 86400:  # 24 hours in seconds
                    os.remove(filepath)
                    logger.info(f"Cleaned up old file: {filename}")
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")

def init_app():
    """Initialize the application."""
    try:
        # Ensure required directories exist
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(SYNC_TOOLS_DIR, exist_ok=True)
        
        # Load existing sync tools
        load_sync_tools()
        
        # Clean up old files
        cleanup_old_files()
        
        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing application: {str(e)}")
        raise

if __name__ == '__main__':
    # Initialize the application
    init_app()
    
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    logger.info(f"Starting application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)