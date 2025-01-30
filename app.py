import os
from flask import Flask, request, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from werkzeug.utils import secure_filename
import re
import mimetypes
import io
import json

app = Flask(__name__)

# Configuration
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS = json.loads(os.environ.get('GOOGLE_CREDENTIALS', '{}'))

class WhatsAppDriveSync:
    def __init__(self):
        self.drive_service = None
        
    def authenticate(self):
        """Handles Google Drive authentication for web service."""
        creds = None
        
        if CREDENTIALS:
            creds = Credentials.from_authorized_user_info(CREDENTIALS, SCOPES)
            
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                raise Exception("Invalid credentials. Please authenticate through OAuth flow.")
        
        self.drive_service = build('drive', 'v3', credentials=creds)
        
    def extract_contact_info(self, filename):
        """Extract contact info from filename."""
        # Assuming filename format: contact_id-timestamp.ext
        match = re.match(r'([^-]+)-.*', filename)
        if match:
            contact_id = match.group(1)
            is_group = '@g.us' in contact_id
            
            if not is_group:
                contact_id = re.sub(r'^(\d{1,3})(\d+)$', r'\1-\2', contact_id)
            else:
                contact_id = f'group-{contact_id}'
            return contact_id, is_group
        return 'unknown', False

    def create_folder_if_not_exists(self, folder_name, parent_id=None):
        """Creates a folder in Google Drive if it doesn't exist."""
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

    def get_media_type_folder(self, contact_id, is_group, media_type):
        """Creates or gets the folder structure for a specific media type."""
        whatsapp_folder_id = self.create_folder_if_not_exists('WhatsApp Sync')
        contact_type = 'Groups' if is_group else 'Contacts'
        type_folder_id = self.create_folder_if_not_exists(contact_type, whatsapp_folder_id)
        contact_folder_id = self.create_folder_if_not_exists(contact_id, type_folder_id)
        return self.create_folder_if_not_exists(media_type, contact_folder_id)

    def upload_file(self, file_data, filename):
        """Uploads a file to the appropriate folder in Google Drive."""
        try:
            contact_id, is_group = self.extract_contact_info(filename)
            
            mime_type = mimetypes.guess_type(filename)[0]
            if mime_type:
                if mime_type.startswith('image/'):
                    media_type = 'Images'
                elif mime_type.startswith('video/'):
                    media_type = 'Videos'
                elif mime_type.startswith('audio/'):
                    media_type = 'Audio'
                else:
                    media_type = 'Documents'
            else:
                media_type = 'Documents'

            folder_id = self.get_media_type_folder(contact_id, is_group, media_type)
            
            file_metadata = {
                'name': secure_filename(filename),
                'parents': [folder_id]
            }

            media = MediaIoBaseUpload(
                io.BytesIO(file_data),
                mimetype=mime_type,
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id').execute()
                
            return {
                'success': True,
                'file_id': file.get('id'),
                'location': f"{contact_id}/{media_type}/{filename}"
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# Initialize sync tool
sync_tool = WhatsAppDriveSync()

@app.before_first_request
def initialize():
    sync_tool.authenticate()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Render."""
    return jsonify({'status': 'healthy'})

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload requests."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    file_data = file.read()
    result = sync_tool.upload_file(file_data, file.filename)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)