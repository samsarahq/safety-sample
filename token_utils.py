from datetime import datetime, timedelta
import requests
from cryptography.fernet import Fernet
import os
import sqlite3
from typing import Optional, Tuple
import logging
DB_NAME = "samsara.db"

def get_or_create_key():
    """Generate encryption key if it doesn't exist"""
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

# Initialize encryption
ENCRYPTION_KEY = get_or_create_key()
fernet = Fernet(ENCRYPTION_KEY)

def is_token_expiring_soon(expires_at: str, threshold_minutes: int = 30) -> bool:
    """
    Check if token is expired or will expire within threshold_minutes
    
    Args:
        expires_at: ISO format datetime string
        threshold_minutes: Minutes before expiration to consider token as expiring
        
    Returns:
        bool: True if token is expired or expiring soon
    """
    if not expires_at:
        return True
        
    try:
        expiration = datetime.fromisoformat(expires_at)
        return datetime.utcnow() + timedelta(minutes=threshold_minutes) >= expiration
    except ValueError:
        logging.error(f"Invalid expiration date format: {expires_at}")
        return True
    except Exception as e:
        logging.error(f"Error checking token expiration: {str(e)}")
        return True

def refresh_access_token(refresh_token: str, token_url: str, client_id: str, client_secret: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Use refresh token to get new access token
    
    Args:
        refresh_token: The refresh token to use
        token_url: OAuth token endpoint URL
        client_id: OAuth client ID
        client_secret: OAuth client secret
        
    Returns:
        Tuple[Optional[str], Optional[str], Optional[int]]: 
        (new_access_token, new_refresh_token, expires_in) or (None, None, None) on failure
    """
    try:
        response = requests.post(
            token_url,
            data={
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            },
            timeout=30
        )
        
        if response.status_code != 200:
            logging.error(f"Error refreshing token: Status={response.status_code}, Response={response.text}")
            return None, None, None
            
        token_info = response.json()
        return (
            token_info.get('access_token'),
            token_info.get('refresh_token'),
            token_info.get('expires_in')
        )
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error refreshing token: {str(e)}")
        return None, None, None
    except Exception as e:
        logging.error(f"Unexpected error refreshing token: {str(e)}")
        return None, None, None

def update_org_tokens(org_id: str, org_name: str, access_token: str, refresh_token: str, expires_in: int, region: str, conn) -> bool:
    """
    Update organization tokens with expiration time and region
    
    Args:
        org_id: Organization ID
        org_name: Organization name
        access_token: New access token
        refresh_token: New refresh token
        expires_in: Token expiration in seconds
        region: API region (us or emea)
        conn: Database connection
        
    Returns:
        bool: True if update was successful
    """
    try:
        c = conn.cursor()
        
        # Calculate expiration time
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Encrypt tokens
        encrypted_access = fernet.encrypt(access_token.encode())
        encrypted_refresh = fernet.encrypt(refresh_token.encode())
        
        c.execute('''
            INSERT OR REPLACE INTO organizations 
            (org_id, org_name, access_token, refresh_token, last_updated, expires_at, region)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            org_id,
            org_name,
            encrypted_access,
            encrypted_refresh,
            datetime.utcnow().isoformat(),
            expires_at.isoformat(),
            region
        ))
        
        conn.commit()
        return True
        
    except sqlite3.Error as e:
        logging.error(f"Database error updating tokens: {str(e)}")
        conn.rollback()
        return False
    except Exception as e:
        logging.error(f"Unexpected error updating tokens: {str(e)}")
        conn.rollback()
        return False

def get_valid_token(org_id: str, conn) -> Optional[str]:
    """
    Get a valid access token for an organization, refreshing if needed
    
    Args:
        org_id: Organization ID
        conn: Database connection
        
    Returns:
        Optional[str]: Valid access token or None if unable to get/refresh token
    """
    try:
        c = conn.cursor()
        
        c.execute('''
            SELECT access_token, refresh_token, expires_at, region
            FROM organizations 
            WHERE org_id = ?
        ''', (org_id,))
        result = c.fetchone()
        
        if not result:
            logging.error(f"No token information found for organization {org_id}")
            return None
            
        encrypted_access, encrypted_refresh, expires_at, region = result
        
        try:
            # Decrypt tokens
            access_token = fernet.decrypt(encrypted_access).decode()
            refresh_token = fernet.decrypt(encrypted_refresh).decode()
        except Exception as e:
            logging.error(f"Error decrypting tokens: {str(e)}")
            return None
        
        # Check if current token is valid
        if not is_token_expiring_soon(expires_at):
            return access_token
            
        # Get appropriate token URL and credentials based on region
        if region == 'us':
            from config import US_TOKEN_URL as token_url
            from config import US_CLIENT_ID as client_id
            from config import US_CLIENT_SECRET as client_secret
        else:
            from config import TOKEN_URL as token_url
            from config import CLIENT_ID as client_id
            from config import CLIENT_SECRET as client_secret
            
        # Token is expired or expiring soon, try to refresh
        new_access, new_refresh, expires_in = refresh_access_token(
            refresh_token, token_url, client_id, client_secret
        )
        
        if not new_access or not new_refresh or not expires_in:
            logging.error(f"Failed to refresh token for organization {org_id}")
            return None
            
        # Get organization name
        c.execute('SELECT org_name FROM organizations WHERE org_id = ?', (org_id,))
        org_name = c.fetchone()[0]
        
        # Update database with new tokens
        if update_org_tokens(org_id, org_name, new_access, new_refresh, expires_in, region, conn):
            return new_access
        
        return None
        
    except Exception as e:
        logging.error(f"Error getting valid token: {str(e)}")
        return None