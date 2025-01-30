from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import json
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Google OAuth2 scopes
SCOPES = ['https://www.googleapis.com/auth/drive.file']

class FileHandler(FileSystemEventHandler):
    def __init__(self, sync_instance):
        self.sync = sync_instance
        self.processed_files = set()
        
    def on_created(self, event):
        if not event.is_directory and event.src_path not in self.processed_files:
            self.processed_files.add(event.src_path)
            self.sync.upload_file(event.src_path)
            
    def on_modified(self, event):
        if not event.is_directory and event.src_path not in self.processed_files:
            self.processed_files.add(event.src_path)
            self.sync.upload_file(event.src_path)

class WhatsAppSync:
    def __init__(self, user_id: str, credentials_path: str, whatsapp_dir: str):
        self.user_id = user_id
        self.credentials_path = credentials_path
        self.whatsapp_dir = whatsapp_dir
        self.drive_service = None
        self.observer = None
        self.is_syncing = False
        self.root_folder_id = None

    def authenticate(self) -> dict:
        """Authenticate with Google Drive"""
        try:
            with open(self.credentials_path, 'r') as f:
                creds_data = json.load(f)
            
            # Ensure we have the correct credentials format
            if 'web' not in creds_data:
                return {
                    'success': False, 
                    'error': 'Invalid credentials format: missing web configuration'
                }

            flow = InstalledAppFlow.from_client_config(
                creds_data, 
                SCOPES
            )
            
            # Use the redirect URI from credentials.json
            redirect_uri = creds_data['web']['redirect_uris'][0]
            flow.redirect_uri = redirect_uri
            
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'
            )
            
            return {'success': True, 'auth_url': auth_url}
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return {'success': False, 'error': str(e)}
        
        

    def setup_drive_service(self, credentials: Credentials) -> bool:
        """Setup Google Drive service"""
        try:
            self.drive_service = build('drive', 'v3', credentials=credentials)
            return True
        except Exception as e:
            logger.error(f"Error setting up drive service: {str(e)}")
            return False

    def create_folder(self, name: str, parent_id: Optional[str] = None) -> Optional[str]:
        """Create a folder in Google Drive"""
        try:
            file_metadata = {
                'name': name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            if parent_id:
                file_metadata['parents'] = [parent_id]
                
            folder = self.drive_service.files().create(
                body=file_metadata, fields='id'
            ).execute()
            return folder.get('id')
        except Exception as e:
            logger.error(f"Error creating folder: {str(e)}")
            return None

    def upload_file(self, file_path: str, parent_id: Optional[str] = None) -> bool:
        """Upload a file to Google Drive"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False

            filename = os.path.basename(file_path)
            file_metadata = {'name': filename}
            if parent_id:
                file_metadata['parents'] = [parent_id]

            media = MediaFileUpload(
                file_path,
                resumable=True
            )
            
            self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            logger.info(f"Uploaded: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error uploading {file_path}: {str(e)}")
            return False

    def start_monitoring(self) -> bool:
        """Start file system monitoring"""
        try:
            if self.observer:
                return True

            event_handler = FileHandler(self)
            self.observer = Observer()
            self.observer.schedule(event_handler, self.whatsapp_dir, recursive=True)
            self.observer.start()
            self.is_syncing = True
            return True
            
        except Exception as e:
            logger.error(f"Error starting monitoring: {str(e)}")
            return False

    def stop_monitoring(self) -> bool:
        """Stop file system monitoring"""
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join()
                self.observer = None
                self.is_syncing = False
            return True
        except Exception as e:
            logger.error(f"Error stopping monitoring: {str(e)}")
            return False

class WhatsAppSyncManager:
    def __init__(self, upload_folder: str):
        self.upload_folder = upload_folder
        self.sync_instances: Dict[str, WhatsAppSync] = {}

    def get_credentials_path(self, user_id: str) -> str:
        """Get path to user's credentials file"""
        return os.path.join(self.upload_folder, f'credentials_{user_id}.json')

    def get_user_status(self, user_id: str) -> dict:
        """Get user's sync status"""
        try:
            credentials_path = self.get_credentials_path(user_id)
            has_credentials = os.path.exists(credentials_path)
            is_syncing = (user_id in self.sync_instances and 
                         self.sync_instances[user_id].is_syncing)
            
            return {
                'authenticated': has_credentials,
                'has_credentials': has_credentials,
                'is_syncing': is_syncing,
                'whatsapp_dir': (self.sync_instances[user_id].whatsapp_dir 
                                if user_id in self.sync_instances else None)
            }
        except Exception as e:
            logger.error(f"Error getting user status: {str(e)}")
            return {
                'authenticated': False,
                'has_credentials': False,
                'is_syncing': False,
                'whatsapp_dir': None
            }

    def upload_credentials(self, user_id: str, file) -> dict:
        """Upload and validate credentials file"""
        try:
            if file.filename == '':
                return {'success': False, 'error': 'No file selected'}
                
            if not file.filename.endswith('.json'):
                return {'success': False, 'error': 'Invalid file type'}
                
            filepath = self.get_credentials_path(user_id)
            file.save(filepath)
            
            # Validate credentials
            try:
                with open(filepath, 'r') as f:
                    json.load(f)
                return {'success': True, 'message': 'Credentials uploaded successfully'}
            except json.JSONDecodeError:
                os.remove(filepath)
                return {'success': False, 'error': 'Invalid credentials format'}
                
        except Exception as e:
            logger.error(f"Error uploading credentials: {str(e)}")
            return {'success': False, 'error': str(e)}

    def setup_directory(self, user_id: str, whatsapp_dir: str) -> dict:
        """Setup sync directory for user"""
        try:
            if not os.path.exists(whatsapp_dir):
                return {'success': False, 'error': 'Directory not found'}
                
            return {'success': True, 'message': 'Directory setup successful'}
        except Exception as e:
            logger.error(f"Error setting up directory: {str(e)}")
            return {'success': False, 'error': str(e)}

    def start_sync(self, user_id: str, whatsapp_dir: str) -> dict:
        """Start sync for user"""
        try:
            if user_id in self.sync_instances and self.sync_instances[user_id].is_syncing:
                return {'success': False, 'error': 'Sync already running'}
                
            credentials_path = self.get_credentials_path(user_id)
            if not os.path.exists(credentials_path):
                return {'success': False, 'error': 'Credentials not found'}
                
            # Create new sync instance
            sync_instance = WhatsAppSync(user_id, credentials_path, whatsapp_dir)
            
            # Authenticate and get auth URL if needed
            auth_result = sync_instance.authenticate()
            if not auth_result['success']:
                return {'success': False, 'error': auth_result.get('error', 'Authentication failed')}
                
            if 'auth_url' in auth_result:
                return {
                    'success': True,
                    'status': 'authorization_required',
                    'auth_url': auth_result['auth_url']
                }
                
            # Start monitoring
            if not sync_instance.start_monitoring():
                return {'success': False, 'error': 'Failed to start monitoring'}
                
            self.sync_instances[user_id] = sync_instance
            return {'success': True, 'message': 'Sync started successfully'}
            
        except Exception as e:
            logger.error(f"Error starting sync: {str(e)}")
            return {'success': False, 'error': str(e)}

    def stop_sync(self, user_id: str) -> dict:
        """Stop sync for user"""
        try:
            if user_id not in self.sync_instances:
                return {'success': True, 'message': 'No sync running'}
                
            sync_instance = self.sync_instances[user_id]
            if sync_instance.stop_monitoring():
                del self.sync_instances[user_id]
                return {'success': True, 'message': 'Sync stopped successfully'}
            else:
                return {'success': False, 'error': 'Failed to stop sync'}
                
        except Exception as e:
            logger.error(f"Error stopping sync: {str(e)}")
            return {'success': False, 'error': str(e)}

    def handle_oauth_callback(self, user_id: str, auth_code: str) -> dict:
        """Handle OAuth callback after authorization"""
        try:
            if user_id not in self.sync_instances:
                return {'success': False, 'error': 'No sync instance found'}
                
            sync_instance = self.sync_instances[user_id]
            credentials_path = self.get_credentials_path(user_id)
            
            with open(credentials_path, 'r') as f:
                creds_data = json.load(f)
                
            flow = InstalledAppFlow.from_client_config(
                creds_data,
                SCOPES,
                redirect_uri=os.getenv('OAUTH_REDIRECT_URI')
            )
            
            flow.fetch_token(code=auth_code)
            
            # Setup drive service with new credentials
            if not sync_instance.setup_drive_service(flow.credentials):
                return {'success': False, 'error': 'Failed to setup drive service'}
                
            # Start monitoring
            if not sync_instance.start_monitoring():
                return {'success': False, 'error': 'Failed to start monitoring'}
                
            return {'success': True, 'message': 'Authorization completed successfully'}
            
        except Exception as e:
            logger.error(f"Error handling OAuth callback: {str(e)}")
            return {'success': False, 'error': str(e)}

    def cleanup(self):
        """Clean up all sync instances"""
        for user_id, sync_instance in list(self.sync_instances.items()):
            try:
                sync_instance.stop_monitoring()
                del self.sync_instances[user_id]
            except Exception as e:
                logger.error(f"Error cleaning up sync instance for user {user_id}: {str(e)}")

    def update_sync_settings(self, user_id: str, settings: dict) -> dict:
        """Update sync settings for a user"""
        try:
            if user_id not in self.sync_instances:
                return {'success': False, 'error': 'No active sync found'}
                
            sync_instance = self.sync_instances[user_id]
            
            # Stop current sync
            sync_instance.stop_monitoring()
            
            # Update settings
            if 'whatsapp_dir' in settings:
                sync_instance.whatsapp_dir = settings['whatsapp_dir']
            
            # Restart sync
            if sync_instance.start_monitoring():
                return {'success': True, 'message': 'Settings updated successfully'}
            else:
                return {'success': False, 'error': 'Failed to restart sync'}
                
        except Exception as e:
            logger.error(f"Error updating sync settings: {str(e)}")
            return {'success': False, 'error': str(e)}

    def get_sync_errors(self, user_id: str) -> dict:
        """Get sync errors for a user"""
        try:
            if user_id not in self.sync_instances:
                return {'success': False, 'error': 'No active sync found'}
                
            sync_instance = self.sync_instances[user_id]
            return {
                'success': True,
                'errors': sync_instance.get_errors() if hasattr(sync_instance, 'get_errors') else []
            }
            
        except Exception as e:
            logger.error(f"Error getting sync errors: {str(e)}")
            return {'success': False, 'error': str(e)}

# Additional utility functions
def validate_credentials_file(filepath: str) -> bool:
    """Validate Google credentials file"""
    try:
        with open(filepath, 'r') as f:
            creds_data = json.load(f)
            
        required_fields = ['client_id', 'client_secret', 'redirect_uris']
        if 'web' in creds_data:
            config = creds_data['web']
        elif 'installed' in creds_data:
            config = creds_data['installed']
        else:
            return False
            
        return all(field in config for field in required_fields)
        
    except (json.JSONDecodeError, KeyError, OSError):
        return False

def get_default_whatsapp_dir() -> Optional[str]:
    """Get default WhatsApp directory based on platform"""
    import platform
    system = platform.system()
    
    if system == "Windows":
        return os.path.join(
            os.getenv('LOCALAPPDATA', ''),
            'WhatsApp',
            'Media'
        )
    elif system == "Darwin":  # macOS
        return os.path.expanduser(
            '~/Library/Group Containers/net.whatsapp.WhatsApp/WhatsApp/Media'
        )
    elif system == "Linux":
        return os.path.expanduser('~/WhatsApp/Media')
        
    return None

# Error handling decorator for sync operations
def handle_sync_errors(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}")
            return {'success': False, 'error': str(e)}
    return wrapper

