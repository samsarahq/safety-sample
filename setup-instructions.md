# Deployment Guide for Samsara Partner Portal

This guide provides detailed instructions for deploying the Samsara Partner Portal application in a Python 3.11 environment.

## System Requirements

- Python 3.11 or newer
- pip (Python package installer)
- Git (optional, for cloning the repository)
- Recommended: At least 1GB RAM
- Disk space: 100MB minimum

## Step-by-Step Deployment

### 1. Prepare the Environment

#### Install Python 3.11 (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev -y
```

#### Install Python 3.11 (CentOS/RHEL)

```bash
sudo dnf install python3.11 python3.11-devel -y
```

#### Install Python 3.11 (Windows)

Download and install the Python 3.11 installer from the [official Python website](https://www.python.org/downloads/windows/).

### 2. Set Up Project Directory

Create a directory for the application:

```bash
mkdir -p /opt/samsara-partner-portal
cd /opt/samsara-partner-portal
```

### 3. Create and Activate Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 4. Create Project Files

Create the following files in your project directory:

#### app.py
Copy the contents of the app.py file provided in the repository.

#### config.py
Create a config.py file with the following template and fill in your values:

```python
import os

# Flask configuration
SECRET_KEY = 'generate-a-secure-random-key'

# Samsara EU API configuration
CLIENT_ID = ''
CLIENT_SECRET = ''
REDIRECT_URI = ''
AUTH_URL = 'https://api.eu.samsara.com/oauth2/authorize'
TOKEN_URL = 'https://api.eu.samsara.com/oauth2/token'
ME_URL = 'https://api.eu.samsara.com/me'

# Samsara US API configuration
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
ADMIN_PASSWORD = 'Pass1234'  # CHANGE THIS IMMEDIATELY AFTER DEPLOYMENT

# Path configurations
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "samsara.db")
```

#### token_utils.py
Copy the contents of the token_utils.py file provided in the repository.

#### requirements.txt
Use the provided requirements.txt file or create it with the following contents:

```
flask==2.3.3
flask-wtf==1.2.1
werkzeug==2.3.7
requests==2.31.0
cryptography==41.0.4
email-validator==2.0.0.post2
python-dotenv==1.0.0
gunicorn==21.2.0
```

### 5. Create Templates and Static Directories

```bash
mkdir -p templates static static/css static/js logs
```

You will need to create the necessary template files and static assets. The template files should be placed in the `templates` directory and should include at minimum:

- login.html
- splash.html
- safety_settings.html
- safety_scores.html
- admin.html
- manage_orgs.html
- user_management.html
- config_management.html
- database_admin.html
- audit.html
- reset_password.html
- forgot_password.html
- success.html
- error.html

### 6. Install Dependencies

```bash
pip install -r requirements.txt
```

### 7. Initialize the Application

Run the application once to initialize the database:

```bash
python app.py
```

This will create the SQLite database with the necessary tables and start the application on port 8000. You can terminate the process (Ctrl+C) after initialization if you plan to set up a production deployment.

### 8. Production Deployment

For production deployment, we recommend using Gunicorn with a reverse proxy like Nginx.

#### Set Up Gunicorn

Install Gunicorn if it's not already installed:

```bash
pip install gunicorn
```

Create a Gunicorn configuration file `gunicorn_config.py`:

```python
bind = "0.0.0.0:8000"
workers = 4
timeout = 120
```

#### Create Systemd Service

Create a service file at `/etc/systemd/system/samsara-partner.service`:

```
[Unit]
Description=Samsara Partner Portal
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/samsara-partner-portal
ExecStart=/opt/samsara-partner-portal/venv/bin/gunicorn -c gunicorn_config.py app:app
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable samsara-partner
sudo systemctl start samsara-partner
```

#### Set Up Nginx (Optional)

Install Nginx:

```bash
sudo apt install nginx -y
```

Create a Nginx configuration file at `/etc/nginx/sites-available/samsara-partner`:

```
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/samsara-partner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 9. Secure Your Deployment

1. Change the default admin password after first login
2. Set up HTTPS with Let's Encrypt or another SSL provider
3. Configure a firewall to restrict access to the server

```bash
# UFW example (Ubuntu)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

### 10. Regular Maintenance

1. Create a backup script for the SQLite database:

```bash
#!/bin/bash
BACKUP_DIR="/opt/samsara-partner-portal/backup"
mkdir -p $BACKUP_DIR
DATE=$(date +"%Y%m%d_%H%M%S")
cp /opt/samsara-partner-portal/samsara.db $BACKUP_DIR/samsara_$DATE.db
find $BACKUP_DIR -type f -name "samsara_*.db" -mtime +7 -delete
```

2. Set up a cron job to run the backup script:

```bash
0 0 * * * /path/to/backup_script.sh
```

## Troubleshooting

### Application Not Starting

Check the logs:

```bash
sudo journalctl -u samsara-partner.service -n 100
```

Or check the application logs:

```bash
cat /opt/samsara-partner-portal/logs/samsara_partner.log
```

### Database Issues

Use the database management interface at `/admin/database` to check for issues.

### Connection Issues

Verify your Samsara API credentials in the config.py file and ensure your redirect URIs are correctly configured in both the application and Samsara developer portal.

## Updating the Application

To update the application:

1. Back up the database
2. Pull the latest code or replace the necessary files
3. Restart the application:

```bash
sudo systemctl restart samsara-partner
```

## Setting Up Samsara API Access

### 1. Create a Samsara Developer Account

1. Visit the [Samsara Developer Portal](https://developers.samsara.com/)
2. Click on "Sign Up" in the top-right corner
3. Complete the registration form with your details
4. Verify your email address

### 2. Create an OAuth2 Application in Samsara

#### For US Region:

1. Log in to the [Samsara Developer Portal](https://developers.samsara.com/)
2. Navigate to the [Developer Console](https://cloud.samsara.com/developer/portal)
3. Click on "Create application"
4. Fill in the application details:
   - **Name**: Enter a descriptive name (e.g., "Partner Portal - US")
   - **Description**: Provide a brief description of your application
   - **Application Type**: Select "Web Application"
   - **Environment**: Choose "Production" for a production deployment or "Development" for testing
   - **Organization**: Select your organization or create a new one
5. Under "OAuth 2.0 Redirect URIs", click "Add URI" and enter your callback URL:
   - Format: `http://your-domain/authorize` or `https://your-domain/authorize`
   - For local testing: `http://localhost:8000/authorize`
6. Under "Scopes", select the following required scopes:
   - `addresses:read` (Read Addresses)
   - `drivers:read` (Read Drivers)
   - `driver_app_settings:read` (Read Driver App Settings)
   - `camera_media:read` (Read Camera Media)
   - `media_retrieval:read` (Read Media Retrieval)
   - `safety_events_scores:read` (Read Safety Events & Scores)
   - `admin:read` (Read Org Information)
   - `vehicles:read` (Read Vehicles)
   - `vehicle_stats:read` (Read Vehicle Statistics)
   - `vehicle_trips:read` (Read Vehicle Trips)
   - `vehicle_immobilization:read` (Read Vehicle Immobilization)
7. Click "Create application"
8. On the next screen, you'll be shown your:
   - **Client ID**: Copy this to the `US_CLIENT_ID` field in your `config.py`
   - **Client Secret**: Copy this to the `US_CLIENT_SECRET` field in your `config.py`

#### For EU Region:

1. Log in to the [Samsara EU Developer Portal](https://developers.eu.samsara.com/)
2. Navigate to the [Developer Console](https://cloud.eu.samsara.com/developer/portal)
3. Follow the same steps as for the US region, but with a different name (e.g., "Partner Portal - EU")
4. Copy the Client ID and Client Secret to the `CLIENT_ID` and `CLIENT_SECRET` fields in your `config.py`

### 3. Configure Redirect URIs

Make sure to:

1. Use the exact same redirect URI in both:
   - The Samsara Developer Portal (for both US and EU applications)
   - Your `config.py` file (in `REDIRECT_URI` and `US_REDIRECT_URI` fields)

2. Include the full URL path including the protocol (http:// or https://)

3. For production, use HTTPS:
   ```
   https://your-domain.com/authorize
   ```

4. For development/testing, you can use:
   ```
   http://localhost:8000/authorize
   ```

### 4. Verify Your Configuration

Double-check your `config.py` file to ensure all fields are correctly filled:

```python
# EU Region
CLIENT_ID = 'your-eu-client-id'
CLIENT_SECRET = 'your-eu-client-secret'
REDIRECT_URI = 'https://your-domain/authorize'
AUTH_URL = 'https://api.eu.samsara.com/oauth2/authorize'
TOKEN_URL = 'https://api.eu.samsara.com/oauth2/token'
ME_URL = 'https://api.eu.samsara.com/me'

# US Region
US_CLIENT_ID = 'your-us-client-id'
US_CLIENT_SECRET = 'your-us-client-secret'
US_REDIRECT_URI = 'https://your-domain/authorize'
US_AUTH_URL = 'https://api.samsara.com/oauth2/authorize'
US_TOKEN_URL = 'https://api.samsara.com/oauth2/token'
US_ME_URL = 'https://api.samsara.com/me'
```

### 5. Testing the OAuth Integration

After setting up your application:

1. Start your Samsara Partner Portal application
2. Navigate to the splash page (usually the root URL of your application)
3. Choose either the EU or US region
4. Click "Connect to Samsara"
5. You should be redirected to the Samsara login page
6. After logging in, you'll be asked to authorize the application with the requested scopes
7. After authorization, you should be redirected back to your application's success page

## Security Considerations

### Encryption

The application automatically generates an encryption key for token storage. This key is stored in a file called `encryption.key` in the application directory. Make sure to:

1. Set proper file permissions:
   ```bash
   sudo chown www-data:www-data encryption.key
   sudo chmod 600 encryption.key
   ```

2. Back up this key securely. If you lose it, you'll lose access to all stored tokens.

### Password Security

1. Change the default admin password immediately after deployment
2. Set up email configuration for password resets
3. Use strong passwords for all admin accounts

### HTTPS

Always use HTTPS in production. You can set up a free SSL certificate with Let's Encrypt:

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

## Management Tasks

### Adding Users

1. Log in with the admin account
2. Go to Admin > User Management
3. Click "Add User" and fill in the required information

### Managing Organizations

1. Go to Admin > Manage Organizations
2. You can view, delete, and refresh connections

### Backing Up the Database

Manually back up the database:

```bash
cp /opt/samsara-partner-portal/samsara.db /opt/samsara-partner-portal/backup/samsara_$(date +"%Y%m%d_%H%M%S").db
```

### Monitoring Logs

View application logs:

```bash
tail -f /opt/samsara-partner-portal/logs/samsara_partner.log
```

View service logs:

```bash
sudo journalctl -u samsara-partner.service -f
```

## Upgrading Python

If you need to upgrade to a newer Python version in the future:

1. Install the new Python version
2. Create a new virtual environment
3. Reinstall dependencies
4. Update the path in the systemd service file

## Conclusion

Follow this guide to successfully deploy and maintain your Samsara Partner Portal. Remember to keep your system and dependencies updated regularly for security and stability.

For additional help or to report issues, please refer to the project's GitHub repository or contact the maintainers.
