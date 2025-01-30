from functools import wraps
from flask import session, jsonify
import os
import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    """Setup logging configuration"""
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Configure logger
    logger = logging.getLogger('whatsapp_sync')
    logger.setLevel(logging.INFO)
    
    # Create handlers
    file_handler = RotatingFileHandler(
        'logs/whatsapp_sync.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    console_handler = logging.StreamHandler()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Add formatter to handlers
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def credentials_required(f):
    """Decorator to check if user has uploaded credentials"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('has_credentials'):
            return jsonify({'error': 'Credentials required'}), 401
        return f(*args, **kwargs)
    return decorated_function

class AuthError(Exception):
    """Custom exception for authentication errors"""
    def __init__(self, message, status_code=401):
        super().__init__(message)
        self.status_code = status_code

def handle_auth_error(error):
    """Error handler for authentication errors"""
    response = jsonify({
        'error': str(error),
        'status_code': getattr(error, 'status_code', 500)
    })
    response.status_code = getattr(error, 'status_code', 500)
    return response

def verify_session():
    """Verify and refresh session if needed"""
    if 'user_id' not in session:
        raise AuthError('No active session')
    if not session.get('authenticated'):
        raise AuthError('Not authenticated')
    return True