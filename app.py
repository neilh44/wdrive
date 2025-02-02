import os
import time
import asyncio
from flask import (
    Flask, 
    jsonify, 
    request, 
    render_template, 
    flash, 
    redirect, 
    url_for, 
    session
)
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import secrets
from werkzeug.utils import secure_filename
import json
import mimetypes
import re
from datetime import datetime
import logging
from threading import Thread
import uuid 
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Allow OAuth2 to work without HTTPS in development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Configuration constants
SCOPES = ['https://www.googleapis.com/auth/drive.file']
UPLOAD_FOLDER = 'user_credentials'
ALLOWED_EXTENSIONS = {'json'}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# User sessions storage
user_sync_tools = {}

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
                'sync_directory': None,
                'browser_dir_handle': None  # New field for browser directory handle
            }
            self.last_synced_files = set()
            logger.debug(f"Successfully initialized sync tool for user: {user_id}")
        except Exception as e:
            logger.error(f"Error initializing sync tool: {str(e)}")
            raise

    def get_credentials_path(self):
        return os.path.join(UPLOAD_FOLDER, f'credentials_{self.user_id}.json')
        
    def get_token_path(self):
        return os.path.join(UPLOAD_FOLDER, f'token_{self.user_id}.json')

    async def read_file_handle(self, file_handle):
        """Read file content from browser file handle."""
        try:
            file = await file_handle.getFile()
            content = await file.text()
            return content
        except Exception as e:
            logger.error(f"Error reading file handle: {str(e)}")
            raise

    async def list_directory_contents(self, dir_handle):
        """List contents of a directory using browser file handle."""
        contents = []
        try:
            async for entry in dir_handle.values():
                if entry.kind == 'file':
                    contents.append({
                        'name': entry.name,
                        'type': 'file',
                        'handle': entry
                    })
                elif entry.kind == 'directory':
                    subcontents = await self.list_directory_contents(entry)
                    contents.extend(subcontents)
        except Exception as e:
            logger.error(f"Error listing directory contents: {str(e)}")
        return contents

    def authenticate(self):
        """Handles Google Drive authentication for specific user."""
        creds = None
        token_path = self.get_token_path()
        
        if os.path.exists(token_path):
            try:
                with open(token_path, 'r') as token:
                    creds_data = json.load(token)
                    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
            except Exception as e:
                logger.error(f"Error loading credentials: {str(e)}")
                raise

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception as e:
                    logger.error(f"Error refreshing credentials: {str(e)}")
                    raise
            else:
                credentials_path = self.get_credentials_path()
                if not os.path.exists(credentials_path):
                    raise Exception("Please upload credentials.json first")
                    
                flow = Flow.from_client_secrets_file(
                    credentials_path,
                    scopes=SCOPES,
                    redirect_uri=url_for('oauth2callback', _external=True)
                )
                
                auth_url, _ = flow.authorization_url(prompt='consent')
                session['current_flow'] = flow
                return auth_url

            try:
                with open(token_path, 'w') as token:
                    token.write(creds.to_json())
            except Exception as e:
                logger.error(f"Error saving credentials: {str(e)}")
                raise

        self.drive_service = build('drive', 'v3', credentials=creds)
        return None

    def create_folder_if_not_exists(self, folder_name, parent_id=None):
        """Creates a folder in Google Drive if it doesn't exist."""
        try:
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
            if parent_id:
                query += f" and '{parent_id}' in parents"
                
            results = self.drive_service.files().list(
                q=query,
                spaces='drive',
                fields='files(id, name)').execute()
                
            if not results['files']:
                file_metadata = {
                    'name': folder_name,
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                if parent_id:
                    file_metadata['parents'] = [parent_id]
                    
                folder = self.drive_service.files().create(
                    body=file_metadata,
                    fields='id').execute()
                return folder.get('id')
                
            return results['files'][0]['id']
        except Exception as e:
            logger.error(f"Error creating folder {folder_name}: {str(e)}")
            raise

    async def upload_file(self, file_handle, relative_path=''):
        """Upload a single file to Google Drive using browser file handle."""
        try:
            if file_handle in self.last_synced_files:
                logger.debug(f"File already synced: {file_handle.name}")
                return True

            # Create folder structure
            current_folder_id = await self.get_folder_structure(relative_path)
            
            # Read file content
            file_content = await self.read_file_handle(file_handle)
            
            # Prepare file metadata
            file_metadata = {
                'name': file_handle.name,
                'parents': [current_folder_id]
            }
            
            # Upload to Google Drive
            media = MediaFileUpload(
                file_content,
                mimetype=mimetypes.guess_type(file_handle.name)[0],
                resumable=True
            )
            
            self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            self.last_synced_files.add(file_handle)
            self.sync_status['total_files_synced'] += 1
            self.sync_status['last_synced'] = datetime.now().isoformat()
            
            return True
            
        except Exception as e:
            logger.error(f"Error uploading {file_handle.name}: {str(e)}")
            self.sync_status['last_error'] = str(e)
            return False


    def upload_file(self, file_path):
        """Upload a single file to Google Drive."""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False
                
            # Skip if already synced
            if file_path in self.last_synced_files:
                logger.debug(f"File already synced: {file_path}")
                return True
                
            # Get parent folder ID
            base_folder_id = self.create_folder_if_not_exists('WhatsApp Backup')
            relative_path = os.path.relpath(os.path.dirname(file_path), self.sync_status['sync_directory'])
            
            current_folder_id = base_folder_id
            if relative_path != '.':
                for folder_name in relative_path.split(os.path.sep):
                    if folder_name:
                        current_folder_id = self.create_folder_if_not_exists(folder_name, current_folder_id)
            
            # Prepare file metadata
            file_metadata = {
                'name': os.path.basename(file_path),
                'parents': [current_folder_id]
            }
            
            # Prepare media upload
            mime_type = mimetypes.guess_type(file_path)[0]
            if mime_type is None:
                mime_type = 'application/octet-stream'
                
            media = MediaFileUpload(
                file_path,
                mimetype=mime_type,
                resumable=True
            )
            
            # Upload file
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            # Update tracking
            self.last_synced_files.add(file_path)
            self.sync_status['total_files_synced'] += 1
            self.sync_status['last_synced'] = datetime.now().isoformat()
            
            logger.debug(f"Successfully uploaded: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error uploading {file_path}: {str(e)}")
            self.sync_status['last_error'] = str(e)
            return False


    def sync_files(self):
        """Sync files from WhatsApp directory to Google Drive."""
        logger.debug("Starting sync_files method")
        
        if not self.sync_status['is_running']:
            logger.debug("Sync not running, exiting")
            return
            
        if not self.sync_status['sync_directory']:
            logger.error("No sync directory set")
            self.sync_status['last_error'] = "No sync directory set"
            return
            
        try:
            directory = self.sync_status['sync_directory']
            logger.debug(f"Syncing directory: {directory}")
            
            # Verify directory exists and is readable
            if not os.path.exists(directory):
                logger.error(f"Directory does not exist: {directory}")
                self.sync_status['last_error'] = "Directory not found"
                return
                
            if not os.access(directory, os.R_OK):
                logger.error(f"Cannot read directory: {directory}")
                self.sync_status['last_error'] = "Cannot read directory"
                return
                
            # Ensure Drive service is authenticated
            if not self.drive_service:
                logger.debug("Drive service not initialized, attempting authentication")
                auth_result = self.authenticate()
                if auth_result:
                    logger.error("Authentication required")
                    self.sync_status['last_error'] = "Authentication required"
                    return
                    
            # Walk through directory and upload files
            total_files = 0
            for root, _, files in os.walk(directory):
                for filename in files:
                    if filename.startswith('.'):  # Skip hidden files
                        continue
                        
                    file_path = os.path.join(root, filename)
                    try:
                        logger.debug(f"Processing file: {file_path}")
                        success = self.upload_file(file_path)
                        if success:
                            total_files += 1
                            logger.debug(f"Successfully uploaded {file_path}")
                    except Exception as e:
                        logger.error(f"Error processing {file_path}: {str(e)}")
                        continue
                        
            logger.debug(f"Sync iteration completed. Total files uploaded: {total_files}")
            
        except Exception as e:
            logger.error(f"Error in sync_files: {str(e)}")
            self.sync_status['last_error'] = str(e)


def background_sync(sync_tool):
    """Background sync process."""
    logger.debug("Starting background sync process")
    while sync_tool.sync_status['is_running']:
        try:
            sync_tool.sync_files()
            logger.debug("Completed sync iteration")
        except Exception as e:
            logger.error(f"Error in background sync: {str(e)}")
        time.sleep(30)  # Wait 30 seconds between sync attempts

@app.route('/')
def index():
    """Render the main page."""
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
        logger.debug(f"Created new user session: {session['user_id']}")
    
    user_id = session.get('user_id')
    sync_status = None
    if user_id in user_sync_tools:
        sync_status = user_sync_tools[user_id].sync_status
    
    return render_template('index.html', sync_status=sync_status)

@app.route('/set_sync_directory', methods=['POST'])
def set_sync_directory():
    """Set sync directory using either browser directory handle or manual path."""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Session expired'}), 401
            
        sync_tool = user_sync_tools.get(user_id)
        if not sync_tool:
            return jsonify({'status': 'error', 'message': 'Please upload credentials first'}), 400
            
        directory = request.form.get('directory')
        if not directory:
            return jsonify({'status': 'error', 'message': 'No directory provided'}), 400
            
        # Expand user path if it starts with ~
        if directory.startswith('~'):
            directory = os.path.expanduser(directory)
            
        # Verify directory exists and is accessible
        if not os.path.exists(directory):
            return jsonify({'status': 'error', 'message': 'Directory does not exist'}), 400
            
        if not os.path.isdir(directory):
            return jsonify({'status': 'error', 'message': 'Path is not a directory'}), 400
            
        if not os.access(directory, os.R_OK):
            return jsonify({'status': 'error', 'message': 'Directory is not readable'}), 400
            
        sync_tool.sync_status['sync_directory'] = directory
        logger.debug(f"Set sync directory for user {user_id}: {directory}")
        return jsonify({'status': 'success', 'message': 'Sync directory updated'})
        
    except Exception as e:
        logger.error(f"Error in set_sync_directory: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/upload_credentials', methods=['POST'])
def upload_credentials():
    """Handle credentials.json upload."""
    try:
        if 'credentials' not in request.files:
            flash('No file provided')
            return redirect(url_for('index'))
            
        file = request.files['credentials']
        if file.filename == '':
            flash('No file selected')
            return redirect(url_for('index'))
            
        if not allowed_file(file.filename):
            flash('Invalid file type. Only .json files are allowed.')
            return redirect(url_for('index'))
            
        user_id = session.get('user_id')
        if not user_id:
            flash('Session expired')
            return redirect(url_for('index'))
            
        # Initialize sync tool
        sync_tool = UserWhatsAppSync(user_id)
        user_sync_tools[user_id] = sync_tool
        
        # Save credentials file
        filename = f'credentials_{user_id}.json'
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        # Start OAuth flow
        flow = Flow.from_client_secrets_file(
            filepath,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        auth_url, state = flow.authorization_url(prompt='consent')
        session['oauth_state'] = state
        session['credentials_path'] = filepath
        
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Error in upload_credentials: {str(e)}")
        flash(f'Upload error: {str(e)}')
        return redirect(url_for('index'))

@app.route('/start', methods=['POST'])
def start_sync():
    """Start the sync service."""
    try:
        user_id = session.get('user_id')
        if not user_id or user_id not in user_sync_tools:
            return jsonify({'status': 'error', 'message': 'Please set up credentials first'}), 400
            
        sync_tool = user_sync_tools[user_id]
        
        if sync_tool.sync_status['is_running']:
            return jsonify({'status': 'success', 'message': 'Sync already running'})
            
        if not sync_tool.sync_status['sync_directory']:
            return jsonify({'status': 'error', 'message': 'Please set sync directory first'}), 400
            
        sync_tool.sync_status['is_running'] = True
        
        # Start background sync
        sync_thread = Thread(target=background_sync, args=(sync_tool,))
        sync_thread.daemon = True
        sync_thread.start()
        logger.debug("Started background sync thread")
        
        return jsonify({'status': 'success', 'message': 'Sync service started'})
        
    except Exception as e:
        logger.error(f"Error in start_sync: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/stop', methods=['POST'])
def stop_sync():
    """Stop the sync service."""
    try:
        user_id = session.get('user_id')
        if not user_id or user_id not in user_sync_tools:
            return jsonify({'status': 'error', 'message': 'Service not running'}), 400
            
        sync_tool = user_sync_tools[user_id]
        sync_tool.sync_status['is_running'] = False
        
        return jsonify({'status': 'success', 'message': 'Sync service stopped'})
        
    except Exception as e:
        logger.error(f"Error in stop_sync: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/status')
def get_status():
    """Get the current sync status."""
    try:
        user_id = session.get('user_id')
        if not user_id or user_id not in user_sync_tools:
            logger.debug(f"No sync status available for user: {user_id}")
            return jsonify({
                'is_running': False,
                'last_synced': None,
                'total_files_synced': 0,
                'sync_directory': None,
                'last_error': None
            })
            
        sync_tool = user_sync_tools[user_id]
        logger.debug(f"Returning sync status for user: {user_id}")
        return jsonify(sync_tool.sync_status)
        
    except Exception as e:
        logger.error(f"Error getting status: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth2 callback."""
    try:
        if 'error' in request.args:
            logger.error(f"OAuth error: {request.args['error']}")
            flash('Authentication failed.', 'error')
            return redirect(url_for('index'))
            
        if 'code' not in request.args:
            logger.error("No code in OAuth callback")
            flash('Authentication failed - no code received.', 'error')
            return redirect(url_for('index'))
            
        user_id = session.get('user_id')
        if not user_id or user_id not in user_sync_tools:
            logger.error(f"Invalid user session in OAuth callback: {user_id}")
            flash('Session expired. Please try again.', 'error')
            return redirect(url_for('index'))
            
        sync_tool = user_sync_tools[user_id]
        
        flow = Flow.from_client_secrets_file(
            sync_tool.get_credentials_path(),
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # Save the credentials
        with open(sync_tool.get_token_path(), 'w') as token:
            token.write(credentials.to_json())
            
        # Initialize drive service
        sync_tool.drive_service = build('drive', 'v3', credentials=credentials)
        
        flash('Successfully authenticated with Google Drive!', 'success')
        logger.debug(f"OAuth flow completed successfully for user: {user_id}")
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Error in OAuth callback: {str(e)}")
        flash(f'Authentication error: {str(e)}', 'error')
        return redirect(url_for('index'))

def init_application():
    """Initialize the application."""
    try:
        # Ensure required directories exist
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        # Ensure templates directory exists
        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        os.makedirs(template_dir, exist_ok=True)
        
        # Initialize logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('app.log')
            ]
        )
        
        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing application: {str(e)}")
        raise

if __name__ == '__main__':
    # Initialize the application
    init_application()
    
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Enable CORS for development
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # Run the application
    logger.info(f"Starting application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)