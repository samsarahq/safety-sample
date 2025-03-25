# Samsara Partner Portal

A web application for managing Samsara fleet integrations, safety settings, and driver safety scores.

## Overview

The Samsara Partner Portal allows partners to connect to Samsara customer accounts via OAuth2, fetch safety settings, view driver safety scores, and manage multiple organizations' connections. It supports both US and EU Samsara API regions.

## Features

- OAuth2 integration with Samsara API (US and EU regions)
- View and monitor driver safety scores
- Retrieve and view organization safety settings
- User management with role-based permissions
- Audit logging for security and compliance
- Database management and maintenance tools
- Configuration management via web interface

## Requirements

- Python 3.11+
- Flask and related extensions
- SQLite for database storage
- Internet connectivity to access Samsara APIs

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/samsara-partner-portal.git
cd samsara-partner-portal
```

### 2. Create a virtual environment

```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize the application

```bash
python app.py
```

This will create the necessary database files and start the application on port 8000.

## Configuration

Before using the application, you need to configure the following in the `config.py` file:

### Samsara API Configuration

You need to register an application in the [Samsara Developer Portal](https://developers.samsara.com/) for both EU and/or US regions:

```python
# EU Region
CLIENT_ID = 'your-eu-client-id'
CLIENT_SECRET = 'your-eu-client-secret'
REDIRECT_URI = 'http://your-domain/authorize'
AUTH_URL = 'https://api.eu.samsara.com/oauth2/authorize'
TOKEN_URL = 'https://api.eu.samsara.com/oauth2/token'
ME_URL = 'https://api.eu.samsara.com/me'

# US Region
US_CLIENT_ID = 'your-us-client-id'
US_CLIENT_SECRET = 'your-us-client-secret'
US_REDIRECT_URI = 'http://your-domain/authorize'
US_AUTH_URL = 'https://api.samsara.com/oauth2/authorize'
US_TOKEN_URL = 'https://api.samsara.com/oauth2/token'
US_ME_URL = 'https://api.samsara.com/me'
```

### Email Configuration (for password resets)

```python
EMAIL_SENDER = 'your-email@domain.com'
SMTP_SERVER = 'smtp.domain.com'
SMTP_PORT = 587
SMTP_USERNAME = 'your-email@domain.com'
SMTP_PASSWORD = 'your-password'
```

### Admin Configuration

```python
ADMIN_USERNAME = 'root'
ADMIN_PASSWORD = 'your-secure-password'  # Change this from the default!
```

### Flask Configuration

```python
SECRET_KEY = 'generate-a-secure-random-key-here'
```

## Usage

### User Authentication

1. Start by accessing the portal at `http://localhost:8000`
2. Log in with the admin credentials configured in `config.py`
3. Navigate to the Admin panel to create additional users as needed

### Connecting to Samsara

1. Select EU or US region on the splash page
2. Click "Connect to Samsara"
3. Authorize the application in the Samsara OAuth flow
4. Once connected, you'll be able to access safety settings and driver scores

### Safety Settings

View and manage safety settings for all connected organizations.

### Safety Scores

View driver safety scores with filtering by:
- Organization
- Date range

## Security Notes

- The default admin password should be changed immediately after first login
- All OAuth tokens are encrypted in the database
- Audit logging tracks all significant actions
- Password resets require email configuration

## Deployment for Production

For production deployment, consider the following:

### Using a WSGI Server

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### Systemd Service

Create a systemd service file at `/etc/systemd/system/samsara-partner.service`:

```
[Unit]
Description=Samsara Partner Portal
After=network.target

[Service]
User=yourusername
WorkingDirectory=/path/to/samsara-partner-portal
ExecStart=/path/to/samsara-partner-portal/venv/bin/gunicorn -w 4 -b 0.0.0.0:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable samsara-partner
sudo systemctl start samsara-partner
```

### Nginx Configuration (Optional)

For production, you may want to set up Nginx as a reverse proxy:

```
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Database Issues

If you encounter database errors, try running the database admin tools in the application:
1. Go to Admin > Database
2. Use the VACUUM option to optimize the database
3. Check for any error messages in the logs

### API Connection Issues

If you're having trouble connecting to Samsara's API:
1. Verify your Client ID and Secret in the config.py file
2. Check that your Redirect URI is correctly configured in both the application and Samsara developer portal
3. Ensure you're selecting the correct region (EU vs US)

### Log Files

Check the logs for detailed error messages:
```
logs/samsara_partner.log
```

## License

[Include your license information here]

## Contributing

[Include contribution guidelines here]
