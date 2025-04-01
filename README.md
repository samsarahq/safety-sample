# Samsara Safety Sample Integration

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

## Before you begin

Before using the application, some configuration is required.

Copy the `.env.example` file and update the following values.

```bash
cp .env.example .env
```

### Samsara API Configuration

Register a application in the [Samsara Developer Portal](https://developers.samsara.com/) for both EU and/or US regions. For more
information about the OAuth flow, see this [OAuth guide](https://developers.samsara.com/docs/oauth-20).

```python
# Samsara EU API configuration
SAMSARA_EU_CLIENT_ID=<your samsara app's client ID>
SAMSARA_EU_CLIENT_SECRET=<your samsara app's client secret>
SAMSARA_EU_REDIRECT_URI=http://localhost:8000/authorize
SAMSARA_EU_AUTH_URL=https://api.eu.samsara.com/oauth2/authorize
SAMSARA_EU_TOKEN_URL=https://api.eu.samsara.com/oauth2/token
SAMSARA_EU_ME_URL=https://api.eu.samsara.com/me

# Samsara US API configuration
SAMSARA_US_CLIENT_ID=<your samsara app's client ID>
SAMSARA_US_CLIENT_SECRET=<your samsara app's client secret>
SAMSARA_US_REDIRECT_URI=http://localhost:8000/authorize
SAMSARA_US_AUTH_URL=https://api.samsara.com/oauth2/authorize
SAMSARA_US_TOKEN_URL=https://api.samsara.com/oauth2/token
SAMSARA_US_ME_URL=https://api.samsara.com/me
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
FLASK_SESSION_KEY = 'generate-a-secure-random-key-here'
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/samsarahq/safety-sample.git
cd safety-sample
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

## Usage

### User Authentication

1. Start by accessing the portal at `http://localhost:8000`
2. Log in with the admin credentials configured in `config.py`
3. Navigate to the Admin panel to create additional users as needed `http://localhost:8000/admin`

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

```ini
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

```nginx
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

```bash
less logs/samsara_partner.log
```
