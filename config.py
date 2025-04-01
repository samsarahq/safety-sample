import os

from dotenv import load_dotenv

load_dotenv()

# Flask configuration
SECRET_KEY = os.getenv('FLASK_SESSION_KEY')

# Samsara EU API configuration
CLIENT_ID = os.getenv('SAMSARA_EU_CLIENT_ID')
CLIENT_SECRET = os.getenv('SAMSARA_EU_CLIENT_SECRET')
REDIRECT_URI = os.getenv('SAMSARA_EU_REDIRECT_URI')
AUTH_URL = os.getenv('SAMSARA_EU_AUTH_URL')
TOKEN_URL = os.getenv('SAMSARA_EU_TOKEN_URL')
ME_URL = os.getenv('SAMSARA_EU_ME_URL')

# Samsara US API ocnfiguration
US_CLIENT_ID = os.getenv('SAMSARA_US_CLIENT_ID')
US_CLIENT_SECRET = os.getenv('SAMSARA_US_CLIENT_SECRET')
US_REDIRECT_URI = os.getenv('SAMSARA_US_REDIRECT_URI')
US_AUTH_URL = os.getenv('SAMSARA_US_AUTH_URL')
US_TOKEN_URL = os.getenv('SAMSARA_US_TOKEN_URL')
US_ME_URL = os.getenv('SAMSARA_US_ME_URL')


# Email configuration
EMAIL_SENDER = os.getenv('EMAIL_SENDER')
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')


# Admin configuration
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Path configurations
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "samsara.db")
