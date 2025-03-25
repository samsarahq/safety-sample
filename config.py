import os

# Flask configuration
SECRET_KEY = 'd*_NZo|z]B^jzgfRD4Fs;Q$X|OwS@PZ3'

# Samsara EU API configuration
CLIENT_ID = ''
CLIENT_SECRET = ''
REDIRECT_URI = ''
AUTH_URL = 'https://api.eu.samsara.com/oauth2/authorize'
TOKEN_URL = 'https://api.eu.samsara.com/oauth2/token'
ME_URL = 'https://api.eu.samsara.com/me'

# Samsara US API ocnfiguration
US_CLIENT_ID = ''
US_CLIENT_SECRET = ''
US_REDIRECT_URI = ''
US_AUTH_URL = 'https://api.samsara.com/oauth2/authorize'
US_TOKEN_URL = 'https://api.samsara.com/oauth2/token'
US_ME_URL = 'https://api.samsara.com/me'


# Email configuration
EMAIL_SENDER = ''
SMTP_SERVER = ''
SMTP_PORT = 0
SMTP_USERNAME = ''
SMTP_PASSWORD = ''


# Admin configuration
ADMIN_USERNAME = 'root'
ADMIN_PASSWORD = 'Pass1234'

# Path configurations
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "samsara.db")
