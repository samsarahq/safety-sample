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
3