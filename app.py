from flask import (
	Flask, request, redirect, render_template, session, url_for,
	send_file, Response, stream_with_context, jsonify, make_response
)

# Try to import CSRFProtect, but make it optional for CLI scripts
try:
	from flask_wtf.csrf import CSRFProtect
	csrf_available = True
except ImportError:
	csrf_available = False
	# Create a dummy class that does nothing
	class DummyCSRF:
		def __init__(self, app=None):
			pass
		def exempt(self, view):
			return view
	CSRFProtect = DummyCSRF

from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from logging.handlers import RotatingFileHandler
from urllib.parse import urlencode
from datetime import datetime, timedelta
from config import *
import requests
import logging
import sqlite3
import secrets
import json
import os, sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from token_utils import (
	update_org_tokens, refresh_access_token,
	is_token_expiring_soon, get_valid_token,
	fernet, ENCRYPTION_KEY
)

def get_app_base_dir():
	"""Get the absolute path to the application's base directory"""
	# If running as a script
	if getattr(sys, 'frozen', False):
		# For PyInstaller executable
		return os.path.dirname(sys.executable)
	else:
		# For normal Python execution
		return os.path.dirname(os.path.abspath(__file__))

def get_config_path():
	"""Get the absolute path to config.py"""
	return os.path.join(get_app_base_dir(), 'config.py')

PROTECTED_TABLES = ['admin', 'sqlite_sequence']


# Initialize Flask app first
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.jinja_env.globals.update(min=min)


# Configure logging
if not os.path.exists('logs'):
	os.makedirs('logs')
file_handler = RotatingFileHandler(
	'logs/samsara_partner.log',
	maxBytes=10240,
	backupCount=10
)
file_handler.setFormatter(logging.Formatter(
	'%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Samsara Partner startup')

# Initialize CSRF protection
csrf = CSRFProtect(app)


def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if 'logged_in' not in session:
			return redirect(url_for('login', next=request.url))
		return f(*args, **kwargs)
	return decorated_function


def log_audit_event(action: str, details: str = None, username: str = None):
	"""Log an audit event with the current timestamp and IP address"""
	try:
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()

		# Get IP address if in a web request context, otherwise use CLI indicator
		ip_address = None
		try:
			if request:  # Check if we're in a request context
				ip_address = request.remote_addr
				if request.headers.get('X-Forwarded-For'):
					ip_address = request.headers.get('X-Forwarded-For').split(',')[0]
		except RuntimeError:  # Not in request context
			ip_address = 'CLI_EXECUTION'  # Indicate command-line execution

		c.execute('''
			INSERT INTO audit_log (timestamp, action, ip_address, username, details)
			VALUES (?, ?, ?, ?, ?)
		''', (
			datetime.utcnow().isoformat(),
			action,
			ip_address,
			username,
			details
		))

		conn.commit()
		conn.close()
	except Exception as e:
		app.logger.error(f"Error logging audit event: {str(e)}")


def init_db():
	"""Initialize SQLite database with all required tables"""
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()


	c.execute('''
		CREATE TABLE IF NOT EXISTS safety_settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id TEXT NOT NULL,
			org_name TEXT NOT NULL,
			settings_json TEXT NOT NULL,
			last_updated TIMESTAMP NOT NULL,
			UNIQUE(org_id)
		)
	''')


	# Create organizations table (existing)
	c.execute('''
		CREATE TABLE IF NOT EXISTS organizations (
			org_id TEXT PRIMARY KEY,
			org_name TEXT NOT NULL,
			access_token TEXT NOT NULL,
			refresh_token TEXT NOT NULL,
			last_updated TIMESTAMP NOT NULL,
			expires_at TIMESTAMP,
			region TEXT DEFAULT 'emea'
		)
	''')

	# Create admin table (updated with email and reset fields)
	c.execute('''
		CREATE TABLE IF NOT EXISTS admin (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			reset_token TEXT,
			reset_token_expiry TIMESTAMP
		)
	''')


	# Create audit_log table
	c.execute('''
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			action TEXT NOT NULL,
			ip_address TEXT,
			username TEXT,
			details TEXT
		)
	''')


def update_org_tokens(org_id: str, org_name: str, access_token: str, refresh_token: str, expires_in: int, region: str):
	"""Update organization tokens with expiration time and region"""
	conn = sqlite3.connect(DB_NAME)
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
	conn.close()


# Add helper function to send password reset emails
def send_password_reset_email(recipient_email, reset_link):
	"""Send password reset email with the reset link"""
	try:
		msg = MIMEMultipart()
		msg['From'] = EMAIL_SENDER
		msg['To'] = recipient_email
		msg['Subject'] = "Samsara Partner Portal - Password Reset"

		body = f"""
		<html>
		<body>
			<p>Hello,</p>
			<p>You have requested to reset your password for the Samsara Partner Portal.</p>
			<p>Please click on the following link to reset your password:</p>
			<p><a href="{reset_link}">Reset Password</a></p>
			<p>This link will expire in 1 hour.</p>
			<p>If you did not request this password reset, please ignore this email.</p>
			<p>Thank you,<br>Samsara Partner Portal Team</p>
		</body>
		</html>
		"""

		msg.attach(MIMEText(body, 'html'))

		server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
		server.starttls()
		server.login(SMTP_USERNAME, SMTP_PASSWORD)
		server.send_message(msg)
		server.quit()

		app.logger.info(f"Password reset email sent to {recipient_email}")
		return True

	except Exception as e:
		app.logger.error(f"Error sending reset email to {recipient_email}: {str(e)}")
		return False


def is_token_expiring_soon(expires_at: str, threshold_minutes: int = 30) -> bool:
	"""Check if token is expired or will expire within threshold_minutes"""
	if not expires_at:
		return True

	expiration = datetime.fromisoformat(expires_at)
	return datetime.utcnow() + timedelta(minutes=threshold_minutes) >= expiration

# Update the refresh_access_token function to handle regional token URLs
def refresh_access_token(refresh_token: str, token_url: str, client_id: str, client_secret: str):
	"""
	Use refresh token to get new access token
	Returns tuple of (new_access_token, new_refresh_token, expires_in)
	"""
	try:
		response = requests.post(
			token_url,
			data={
				'client_id': client_id,
				'client_secret': client_secret,
				'refresh_token': refresh_token,
				'grant_type': 'refresh_token'
			}
		)

		if response.status_code != 200:
			print(f"Error refreshing token: {response.text}")
			return None, None, None

		token_info = response.json()
		return (
			token_info['access_token'],
			token_info['refresh_token'],
			token_info['expires_in']
		)

	except Exception as e:
		print(f"Error in token refresh: {str(e)}")
		return None, None, None


def get_connection_status():
	"""Get the current connection status"""
	try:
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()
		c.execute('SELECT org_name, last_updated FROM organizations ORDER BY last_updated DESC LIMIT 1')
		result = c.fetchone()
		conn.close()

		if result:
			return f"Connected to {result[0]} (Last updated: {result[1]})"
		return "Not connected - Click the button above to connect your Samsara account"
	except Exception:
		return "Not connected - Click the button above to connect your Samsara account"

# Update the get_valid_token function to consider region
def get_valid_token(org_id: str):
	"""Get a valid access token for an organization, refreshing if needed"""
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()

	try:
		c.execute('''
			SELECT access_token, refresh_token, expires_at, region
			FROM organizations
			WHERE org_id = ?
		''', (org_id,))
		result = c.fetchone()

		if not result:
			return None

		encrypted_access, encrypted_refresh, expires_at, region = result

		# Decrypt tokens
		access_token = fernet.decrypt(encrypted_access).decode()
		refresh_token = fernet.decrypt(encrypted_refresh).decode()

		# Check if current token is valid
		if not is_token_expiring_soon(expires_at):
			return access_token

		# Token is expired or expiring soon, try to refresh
		# Use appropriate token URL based on region
		token_url = US_TOKEN_URL if region == 'us' else TOKEN_URL
		client_id = US_CLIENT_ID if region == 'us' else CLIENT_ID
		client_secret = US_CLIENT_SECRET if region == 'us' else CLIENT_SECRET

		new_access, new_refresh, expires_in = refresh_access_token(refresh_token, token_url, client_id, client_secret)
		if not new_access or not new_refresh or not expires_in:
			return None

		# Update database with new tokens
		c.execute('SELECT org_name FROM organizations WHERE org_id = ?', (org_id,))
		org_name = c.fetchone()[0]
		update_org_tokens(org_id, org_name, new_access, new_refresh, expires_in, region)

		return new_access

	except Exception as e:
		print(f"Error getting valid token: {str(e)}")
		return None
	finally:
		conn.close()


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgotten password requests"""
    # Check if email configuration is complete
    email_config_complete = all([
        EMAIL_SENDER and EMAIL_SENDER.strip(),
        SMTP_SERVER and SMTP_SERVER.strip(),
        SMTP_PORT,
        SMTP_USERNAME and SMTP_USERNAME.strip(),
        SMTP_PASSWORD and SMTP_PASSWORD.strip()
    ])

    # If email is not configured, redirect to login page
    if not email_config_complete:
        return redirect(url_for('login', error="Password reset is disabled because email settings are not configured"))

    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            return render_template('forgot_password.html', error="Email is required")

        # Check if email exists in admin table
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT username FROM admin WHERE email = ?', (email,))
        user = c.fetchone()

        if user:
            username = user[0]
            # Generate a secure token
            reset_token = secrets.token_urlsafe(32)
            # Set expiry to 1 hour from now
            expiry = datetime.now() + timedelta(hours=1)

            # Save token to database
            c.execute('''
                UPDATE admin
                SET reset_token = ?, reset_token_expiry = ?
                WHERE email = ?
            ''', (reset_token, expiry.isoformat(), email))
            conn.commit()

            # Create reset link
            reset_link = url_for('reset_password', token=reset_token, _external=True)

            # Send email
            if send_password_reset_email(email, reset_link):
                # Log audit event
                log_audit_event(
                    action='password_reset_requested',
                    details=f"Password reset requested for username: {username}",
                    username=username
                )

                conn.close()
                return render_template('forgot_password.html',
                    success="If your email is registered, you will receive password reset instructions shortly.")
            else:
                conn.close()
                return render_template('forgot_password.html',
                    error="Error sending password reset email. Please try again later.")

        # Even if email doesn't exist, show the same message to prevent email enumeration
        conn.close()
        return render_template('forgot_password.html',
            success="If your email is registered, you will receive password reset instructions shortly.")

    return render_template('forgot_password.html')

# Add route for password reset form
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
	"""Handle password reset with token"""
	# Verify token is valid
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute('''
		SELECT username, reset_token_expiry
		FROM admin
		WHERE reset_token = ?
	''', (token,))
	result = c.fetchone()

	# If token not found or expired
	if not result or not result[1]:
		conn.close()
		return render_template('reset_password.html', error="Invalid or expired reset link", token=None)

	username, expiry_str = result
	expiry = datetime.fromisoformat(expiry_str)

	if datetime.now() > expiry:
		# Token expired, invalidate it
		c.execute('UPDATE admin SET reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = ?', (token,))
		conn.commit()
		conn.close()
		return render_template('reset_password.html', error="Reset link has expired", token=None)

	# Handle POST request to reset password
	if request.method == 'POST':
		new_password = request.form.get('new_password')
		confirm_password = request.form.get('confirm_password')

		if not new_password:
			conn.close()
			return render_template('reset_password.html', error="Password is required", token=token)

		if new_password != confirm_password:
			conn.close()
			return render_template('reset_password.html', error="Passwords don't match", token=token)

		if len(new_password) < 8:
			conn.close()
			return render_template('reset_password.html', error="Password must be at least 8 characters", token=token)

		# Hash the new password
		password_hash = generate_password_hash(new_password)

		# Update password and clear reset token
		c.execute('''
			UPDATE admin
			SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL
			WHERE reset_token = ?
		''', (password_hash, token))
		conn.commit()

		# Log audit event
		log_audit_event(
			action='password_reset_completed',
			details=f"Password reset completed for username: {username}",
			username=username
		)

		conn.close()
		return redirect(url_for('login', reset_success=True))

	conn.close()
	return render_template('reset_password.html', token=token)



@app.route('/update-email', methods=['GET', 'POST'])
@login_required
def update_email():
	"""Allow admin to update their email address"""
	if request.method == 'POST':
		new_email = request.form.get('email')
		password = request.form.get('password')

		if not new_email or not password:
			return render_template('update_email.html', error="Email and password are required")

		# Verify password
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()
		username = session.get('username')

		c.execute('SELECT password_hash FROM admin WHERE username = ?', (username,))
		result = c.fetchone()

		if not result or not check_password_hash(result[0], password):
			conn.close()
			return render_template('update_email.html', error="Invalid password")

		# Check if email already exists for another user
		c.execute('SELECT username FROM admin WHERE email = ? AND username != ?', (new_email, username))
		if c.fetchone():
			conn.close()
			return render_template('update_email.html', error="Email already in use by another account")

		# Update email
		c.execute('UPDATE admin SET email = ? WHERE username = ?', (new_email, username))
		conn.commit()

		# Log audit event
		log_audit_event(
			action='email_updated',
			details=f"Email updated for username: {username}",
			username=username
		)

		conn.close()
		return render_template('update_email.html', success="Email updated successfully")

	return render_template('update_email.html')


@app.route('/admin/users')
@login_required
def user_management():
	"""Display user management page with all admin users"""
	try:
		# Get all users from the admin table
		conn = sqlite3.connect(DB_NAME)
		conn.row_factory = sqlite3.Row  # This allows accessing columns by name
		c = conn.cursor()

		c.execute('SELECT username, email FROM admin ORDER BY username')
		users = [dict(row) for row in c.fetchall()]

		conn.close()

		return render_template('user_management.html',
							  users=users,
							  config={'ADMIN_USERNAME': ADMIN_USERNAME})

	except Exception as e:
		app.logger.error(f"Error accessing user management: {str(e)}", exc_info=True)
		return render_template('user_management.html',
							error=f"An error occurred: {str(e)}",
							users=[],
							config={'ADMIN_USERNAME': ADMIN_USERNAME})

@app.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
	"""Add a new admin user"""
	try:
		username = request.form.get('username')
		password = request.form.get('password')
		email = request.form.get('email')

		if not username or not password:
			return redirect(url_for('user_management', error="Username and password are required"))

		# Check if username already exists
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()

		c.execute('SELECT username FROM admin WHERE username = ?', (username,))
		if c.fetchone():
			conn.close()
			return redirect(url_for('user_management', error=f"Username '{username}' already exists"))

		# Check if email is already in use (if provided)
		if email:
			c.execute('SELECT username FROM admin WHERE email = ?', (email,))
			if c.fetchone():
				conn.close()
				return redirect(url_for('user_management', error=f"Email '{email}' is already in use"))

		# Generate password hash
		password_hash = generate_password_hash(password)

		# Insert new user
		c.execute('''
			INSERT INTO admin (username, password_hash, email)
			VALUES (?, ?, ?)
		''', (username, password_hash, email))

		conn.commit()
		conn.close()

		# Log the user creation
		log_audit_event(
			action='user_created',
			username=session.get('username'),
			details=f"Created new user: {username}"
		)

		return redirect(url_for('user_management', success=f"User '{username}' has been created successfully"))

	except Exception as e:
		app.logger.error(f"Error adding user: {str(e)}", exc_info=True)
		return redirect(url_for('user_management', error=f"An error occurred: {str(e)}"))


@app.route('/admin/users/update', methods=['POST'])
@login_required
def update_user():
    """Update an existing admin user with improved connection handling"""
    conn = None
    try:
        original_username = request.form.get('original_username')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not original_username or not username:
            return redirect(url_for('user_management', error="Username is required"))

        conn = sqlite3.connect(DB_NAME, timeout=20)  # Add timeout for busy database
        c = conn.cursor()

        # Check if new username already exists (if changing username)
        if original_username != username:
            c.execute('SELECT username FROM admin WHERE username = ?', (username,))
            if c.fetchone():
                return redirect(url_for('user_management', error=f"Username '{username}' already exists"))

        # Check if email is already in use (if provided and not already associated with this user)
        if email:
            c.execute('SELECT username FROM admin WHERE email = ? AND username != ?', (email, original_username))
            if c.fetchone():
                return redirect(url_for('user_management', error=f"Email '{email}' is already in use"))

        # Build update query
        update_fields = []
        params = []

        # Always update username
        update_fields.append("username = ?")
        params.append(username)

        # Update password if provided
        if password:
            update_fields.append("password_hash = ?")
            params.append(generate_password_hash(password))

        # Update email
        update_fields.append("email = ?")
        params.append(email)

        # Add original username to params
        params.append(original_username)

        # Update user
        c.execute(f'''
            UPDATE admin
            SET {", ".join(update_fields)}
            WHERE username = ?
        ''', params)

        conn.commit()

        # If user updated their own account, update session username
        if session.get('username') == original_username:
            session['username'] = username

        # Log the user update
        log_audit_event(
            action='user_updated',
            username=session.get('username'),
            details=f"Updated user: {original_username} -> {username}"
        )

        return redirect(url_for('user_management', success=f"User '{username}' has been updated successfully"))

    except Exception as e:
        app.logger.error(f"Error updating user: {str(e)}", exc_info=True)
        if conn:
            # Rollback the transaction in case of error
            try:
                conn.rollback()
            except:
                pass
        return redirect(url_for('user_management', error=f"An error occurred: {str(e)}"))
    finally:
        # Ensure connection is closed in all cases
        if conn:
            conn.close()


# Update the delete_user function to remove the admin user restriction
@app.route('/admin/users/delete', methods=['POST'])
@login_required
def delete_user():
    """Delete an admin user"""
    try:
        username = request.form.get('username')

        if not username:
            return redirect(url_for('user_management', error="Username is required"))

        # Prevent self-deletion
        if username == session.get('username'):
            return redirect(url_for('user_management', error="You cannot delete your own account"))

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Check if user exists
        c.execute('SELECT username FROM admin WHERE username = ?', (username,))
        if not c.fetchone():
            conn.close()
            return redirect(url_for('user_management', error=f"User '{username}' not found"))

        # Delete user
        c.execute('DELETE FROM admin WHERE username = ?', (username,))
        conn.commit()
        conn.close()

        # Log the user deletion
        log_audit_event(
            action='user_deleted',
            username=session.get('username'),
            details=f"Deleted user: {username}"
        )

        return redirect(url_for('user_management', success=f"User '{username}' has been deleted successfully"))

    except Exception as e:
        app.logger.error(f"Error deleting user: {str(e)}", exc_info=True)
        return redirect(url_for('user_management', error=f"An error occurred: {str(e)}"))


@app.route('/admin')
@login_required
def admin():
	"""Display main admin control panel with links to admin functions"""
	try:
		# Get basic database stats
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()

		# Format current time for display
		last_backup_date = datetime.now().strftime('%Y-%m-%d %H:%M')

		conn.close()

		return render_template('admin.html', last_backup_date=last_backup_date)

	except Exception as e:
		app.logger.error(f"Error accessing admin panel: {str(e)}", exc_info=True)
		return render_template('admin.html',
							 error=f"An error occurred: {str(e)}",
							 last_backup_date="Not available")



@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login checking config.py for root user and database for other users"""
    error = None
    reset_success = request.args.get('reset_success', False)

    # Check if email configuration is complete
    email_config_complete = all([
        EMAIL_SENDER and EMAIL_SENDER.strip(),
        SMTP_SERVER and SMTP_SERVER.strip(),
        SMTP_PORT,
        SMTP_USERNAME and SMTP_USERNAME.strip(),
        SMTP_PASSWORD and SMTP_PASSWORD.strip()
    ])

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # If username is 'root', only check against config.py credentials
        if username == 'root':
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                session['logged_in'] = True
                session['username'] = username  # Store username in session
                log_audit_event('login_success', username=username)
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('safety_settings'))
            else:
                log_audit_event('login_failed', f"Failed login attempt for root user")
                error = 'Invalid credentials'
        else:
            # For non-root users, check the database
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('SELECT password_hash FROM admin WHERE username = ?', (username,))
            result = c.fetchone()
            conn.close()

            if result and check_password_hash(result[0], password):
                session['logged_in'] = True
                session['username'] = username  # Store username in session
                log_audit_event('login_success', username=username)
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('safety_settings'))
            else:
                log_audit_event('login_failed', f"Failed login attempt for user: {username}")
                error = 'Invalid credentials'

    return render_template('login.html',
                          error=error,
                          reset_success=reset_success,
                          email_config_complete=email_config_complete)

@app.route('/logout')
def logout():
	session.pop('logged_in', None)
	return redirect(url_for('login'))


# Updated region_config_status function with corrected validation logic
@app.route('/api/region-config-status', methods=['GET'])
def region_config_status():
    """
    API endpoint to check if EU and US region configurations are complete.
    Returns JSON with configuration status for each region.

    A region is considered properly configured only if ALL required values
    are present AND non-empty. Any blank fields make the configuration invalid.
    """
    try:
        # Import the config module directly to access its values
        import importlib
        import sys

        # Remove config module from cache if it exists to get fresh values
        if 'config' in sys.modules:
            del sys.modules['config']

        # Re-import the config module
        import config

        # Check EU region configuration
        eu_fields_present = []
        eu_required_fields = ['CLIENT_ID', 'CLIENT_SECRET', 'REDIRECT_URI', 'AUTH_URL', 'TOKEN_URL', 'ME_URL']

        for field in eu_required_fields:
            value = getattr(config, field, '')
            if value and str(value).strip():
                eu_fields_present.append(field)

        # EU config is valid ONLY if ALL fields are present
        eu_config_complete = (len(eu_fields_present) == len(eu_required_fields))

        # Check US region configuration
        us_fields_present = []
        us_required_fields = ['US_CLIENT_ID', 'US_CLIENT_SECRET', 'US_REDIRECT_URI', 'US_AUTH_URL', 'US_TOKEN_URL', 'US_ME_URL']

        for field in us_required_fields:
            value = getattr(config, field, '')
            if value and str(value).strip():
                us_fields_present.append(field)

        # US config is valid ONLY if ALL fields are present
        us_config_complete = (len(us_fields_present) == len(us_required_fields))

        # Log the configuration status with details
        app.logger.info(f"EU config complete: {eu_config_complete} (present: {len(eu_fields_present)} of {len(eu_required_fields)})")
        app.logger.info(f"US config complete: {us_config_complete} (present: {len(us_fields_present)} of {len(us_required_fields)})")

        # Log missing fields for troubleshooting
        if not eu_config_complete and eu_fields_present:
            missing_eu = [field for field in eu_required_fields if field not in eu_fields_present]
            app.logger.info(f"EU config incomplete. Missing fields: {missing_eu}")

        if not us_config_complete and us_fields_present:
            missing_us = [field for field in us_required_fields if field not in us_fields_present]
            app.logger.info(f"US config incomplete. Missing fields: {missing_us}")

        # Return JSON response with configuration status
        return jsonify({
            'eu_config_complete': eu_config_complete,
            'us_config_complete': us_config_complete
        })
    except Exception as e:
        app.logger.error(f"Error checking region config status: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'eu_config_complete': False,
            'us_config_complete': False
        }), 500

# Update the splash function with the same validation logic
@app.route('/')
def splash():
    """
    Render the splash page with region options based on valid configurations.
    A region is valid ONLY if ALL required fields are filled.
    Any blank fields make the configuration invalid.
    """
    try:
        # Import the config module directly to access its values
        import importlib
        import sys

        # Remove config module from cache if it exists to get fresh values
        if 'config' in sys.modules:
            del sys.modules['config']

        # Re-import the config module
        import config

        # Check for valid EU/EMEA region configuration
        eu_fields_present = []
        eu_required_fields = ['CLIENT_ID', 'CLIENT_SECRET', 'REDIRECT_URI', 'AUTH_URL', 'TOKEN_URL', 'ME_URL']

        for field in eu_required_fields:
            value = getattr(config, field, '')
            if value and str(value).strip():
                eu_fields_present.append(field)

        # EU config is valid ONLY if ALL fields are present
        eu_config_valid = (len(eu_fields_present) == len(eu_required_fields))

        # Check for valid US region configuration
        us_fields_present = []
        us_required_fields = ['US_CLIENT_ID', 'US_CLIENT_SECRET', 'US_REDIRECT_URI', 'US_AUTH_URL', 'US_TOKEN_URL','US_ME_URL']

        for field in us_required_fields:
            value = getattr(config, field, '')
            if value and str(value).strip():
                us_fields_present.append(field)

        # US config is valid ONLY if ALL fields are present
        us_config_valid = (len(us_fields_present) == len(us_required_fields))

        app.logger.info(f"Splash page: EU config valid: {eu_config_valid} (present: {len(eu_fields_present)} of {len(eu_required_fields)})")
        app.logger.info(f"Splash page: US config valid: {us_config_valid} (present: {len(us_fields_present)} of {len(us_required_fields)})")

        # Pass configuration validity to the template
        return render_template('splash.html',
                              eu_config_valid=eu_config_valid,
                              us_config_valid=us_config_valid)
    except Exception as e:
        app.logger.error(f"Error in splash route: {str(e)}", exc_info=True)
        # In case of error, show both options as invalid
        return render_template('splash.html',
                              eu_config_valid=False,
                              us_config_valid=False)



# Replace the current authorize route with this more robust version
@app.route('/authorize')
def authorize():
    """Handle OAuth2 callback and token exchange with improved error handling"""
    try:
        # Check for error response
        if 'error' in request.args:
            error_desc = request.args.get('error_description', 'Unknown error')
            log_audit_event('authorize_failed', error_desc)
            return render_template('error.html',
                                 error_title="Authorization Failed",
                                 error_message=error_desc)

        # Get stored region from session
        region = session.get('selected_region', 'emea')

        # Verify state to prevent CSRF
        stored_state = session.pop('oauth_state', None)
        received_state = request.args.get('state')
        if not stored_state or stored_state != received_state:
            log_audit_event('authorize_invalid_state', 'State parameter mismatch')
            return render_template('error.html',
                                 error_title="Security Error",
                                 error_message="Invalid state parameter. Please try again.")

        # Exchange code for tokens
        code = request.args.get('code')
        if not code:
            log_audit_event('authorize_failed', 'No authorization code received')
            return render_template('error.html',
                                 error_title="Missing Code",
                                 error_message="No authorization code received from Samsara")

        # Log authorization attempt start
        log_audit_event('authorize_start', 'Beginning token exchange')

        # Select appropriate credentials based on region
        if region == 'us':
            token_url = US_TOKEN_URL
            client_id = US_CLIENT_ID
            client_secret = US_CLIENT_SECRET
            redirect_uri = US_REDIRECT_URI
            me_url = US_ME_URL
        else:  # EMEA
            token_url = TOKEN_URL
            client_id = CLIENT_ID
            client_secret = CLIENT_SECRET
            redirect_uri = REDIRECT_URI
            me_url = ME_URL

        # Make token exchange request
        app.logger.info("Exchanging code for tokens...")
        token_response = requests.post(
            token_url,
            data={'client_id': client_id,
                  'client_secret': client_secret,
                  'code': code,
                  'grant_type': 'authorization_code',
                  'redirect_uri': redirect_uri
            }
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        app.logger.info("Token exchange successful")
        app.logger.info(f"Token data: {token_data}")

        # Get organization info using the access token
        app.logger.info("Fetching organization info...")
        headers = {
            'Authorization': f"Bearer {token_data['access_token']}",
            'Accept': 'application/json'
        }
        org_response = requests.get(me_url, headers=headers)
        org_response.raise_for_status()
        org_data = org_response.json()
        app.logger.info(f"Organization response: {org_data}")

        # Extract organization details from the nested data structure
        if not org_data.get('data'):
            error_msg = "Unexpected organization data structure"
            app.logger.error(f"{error_msg}: {org_data}")
            log_audit_event('authorize_failed', error_msg)
            return render_template('error.html',
                                 error_title="Data Error",
                                 error_message="Failed to get organization details")

        org_details = org_data['data']
        org_id = org_details.get('id')
        org_name = org_details.get('name')

        if not org_id or not org_name:
            error_msg = "Missing required organization details"
            app.logger.error(f"{error_msg}: {org_details}")
            log_audit_event('authorize_failed', error_msg)
            return render_template('error.html',
                                 error_title="Data Error",
                                 error_message="Required organization details are missing")

        # Store tokens in database with region
        update_org_tokens(
            org_id=org_id,
            org_name=org_name,
            access_token=token_data['access_token'],
            refresh_token=token_data['refresh_token'],
            expires_in=token_data['expires_in'],
            region=region
        )

        # Log successful authorization
        auth_details = {
            'org_id': org_id,
            'org_name': org_name,
            'token_expires_in': token_data['expires_in'],
            'region': region
        }
        log_audit_event('authorize_success', json.dumps(auth_details))

        # Clear region from session after successful authorization
        session.pop('selected_region', None)

        # Return success page directly instead of redirecting
        return render_template('success.html',
                             org_name=org_name,
                             org_id=org_id,
                             region=region,
                             timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    except requests.exceptions.RequestException as e:
        app.logger.error(f"API request error: {str(e)}")
        log_audit_event('authorize_error', f"API request error: {str(e)}")
        return render_template('error.html',
                             error_title="API Error",
                             error_message="Failed to communicate with Samsara API")
    except Exception as e:
        app.logger.error(f"Authorization error: {str(e)}")
        if 'org_response' in locals():
            app.logger.error(f"Organization response content: {org_response.text}")
        log_audit_event('authorize_error', f"Authorization error: {str(e)}")
        return render_template('error.html',
                             error_title="System Error",
                             error_message=f"An unexpected error occurred: {str(e)}")


# Update /api/organizations route to include region
@app.route('/api/organizations')
def get_organizations():
	"""Get all organizations with their token information and region"""
	try:
		conn = sqlite3.connect('samsara.db')
		c = conn.cursor()
		c.execute('''
			SELECT org_id, org_name, last_updated, expires_at, region
			FROM organizations
			ORDER BY last_updated DESC
		''')
		organizations = []
		for row in c.fetchall():
			organizations.append({
				'org_id': row[0],
				'org_name': row[1],
				'last_updated': row[2],
				'expires_at': row[3],
				'region': row[4]
			})
		conn.close()
		return jsonify(organizations)
	except Exception as e:
		print(f"Error getting organizations: {str(e)}")
		return jsonify({'error': str(e)}), 500

@app.route('/audit')
@login_required
def audit():
	"""Display audit log with pagination, sorting, and filtering"""
	try:
		# Get query parameters with defaults
		page = request.args.get('page', 1, type=int)
		per_page = request.args.get('per_page', 10, type=int)
		sort_by = request.args.get('sort', 'timestamp')
		sort_dir = request.args.get('direction', 'desc')
		action_filter = request.args.get('action')
		username_filter = request.args.get('username')

		# Validate per_page parameter
		if per_page != -1 and per_page not in [10, 25, 50]:
			per_page = 10

		# Connect to database
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()

		# First, check if the audit_log table exists
		c.execute("""
			SELECT name
			FROM sqlite_master
			WHERE type='table' AND name='audit_log';
		""")

		if not c.fetchone():
			# Create the audit_log table if it doesn't exist
			app.logger.info("Creating audit_log table")
			c.execute('''
				CREATE TABLE IF NOT EXISTS audit_log (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					timestamp TIMESTAMP NOT NULL,
					action TEXT NOT NULL,
					ip_address TEXT,
					username TEXT,
					details TEXT
				)
			''')
			conn.commit()

		# Build the base query
		base_query = 'SELECT id, timestamp, action, ip_address, username, details FROM audit_log WHERE 1=1'
		params = []

		# Add filters if provided
		if action_filter:
			base_query += ' AND action = ?'
			params.append(action_filter)

		if username_filter:
			base_query += ' AND username = ?'
			params.append(username_filter)

		# Get total count for filtered records
		count_query = f'SELECT COUNT(*) FROM ({base_query})'
		c.execute(count_query, params)
		total_records = c.fetchone()[0]

		# Get unique action values for filter dropdown
		c.execute('SELECT DISTINCT action FROM audit_log WHERE action IS NOT NULL ORDER BY action')
		actions = [row[0] for row in c.fetchall()]

		# Get unique username values for filter dropdown
		c.execute('SELECT DISTINCT username FROM audit_log WHERE username IS NOT NULL ORDER BY username')
		usernames = [row[0] for row in c.fetchall()]

		# Calculate pagination
		if per_page == -1:  # Show all records
			per_page = total_records
		total_pages = (total_records + per_page - 1) // per_page if per_page > 0 else 1
		offset = (page - 1) * per_page if page > 0 else 0

		# Validate and sanitize sort column
		allowed_columns = {'id', 'timestamp', 'action', 'ip_address', 'username', 'details'}
		if sort_by not in allowed_columns:
			sort_by = 'timestamp'
		sort_dir = 'DESC' if sort_dir.lower() == 'desc' else 'ASC'

		# Build and execute query with parameterized values
		query = f'{base_query} ORDER BY {sort_by} {sort_dir} LIMIT ? OFFSET ?'

		app.logger.debug(f"Executing query: {query} with params: {params + [per_page, offset]}")
		c.execute(query, params + [per_page, offset])
		audit_logs = c.fetchall()

		conn.close()

		app.logger.info(f"Successfully retrieved {len(audit_logs)} audit logs")

		return render_template(
			'audit.html',
			audit_logs=audit_logs,
			page=page,
			per_page=per_page,
			total_pages=total_pages,
			total_records=total_records,
			sort_by=sort_by,
			sort_dir=sort_dir.lower(),
			actions=actions,
			usernames=usernames,
			action=action_filter,
			username=username_filter
		)

	except sqlite3.Error as e:
		app.logger.error(f"Database error in audit route: {str(e)}")
		return render_template('audit.html',
							 error=f"Database error: {str(e)}",
							 audit_logs=[],
							 page=1,
							 per_page=10,
							 total_pages=1,
							 total_records=0,
							 sort_by='timestamp',
							 sort_dir='desc')
	except Exception as e:
		app.logger.error(f"Unexpected error in audit route: {str(e)}", exc_info=True)
		return render_template('audit.html',
							 error=f"An unexpected error occurred: {str(e)}",
							 audit_logs=[],
							 page=1,
							 per_page=10,
							 total_pages=1,
							 total_records=0,
							 sort_by='timestamp',
							 sort_dir='desc')


@app.route('/admin/reset', methods=['GET', 'POST'])
@login_required
def reset_app():
    """
    Reset the application by:
    1. Deleting all data from ALL tables (including admin)
    2. Resetting the root password in config.py
    3. Deleting all files in the /logs directory
    4. Deleting all files in the /backup directory
    """
    if request.method == 'GET':
        return render_template('reset_app.html')

    if request.method == 'POST':
        # Verify confirmation text
        confirm_text = request.form.get('confirm')
        if confirm_text != 'RESET':
            return render_template('reset_app.html', error="Please type 'RESET' to confirm this action.")

        try:
            # Store the username before we delete everything
            username = session.get('username')

            # Log the reset operation once before we begin
            try:
                conn = sqlite3.connect(DB_NAME, timeout=60)
                c = conn.cursor()
                c.execute('''
                    INSERT INTO audit_log (timestamp, action, ip_address, username, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.utcnow().isoformat(),
                    'app_reset_initiated',
                    request.remote_addr,
                    username,
                    "Application reset initiated"
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                app.logger.error(f"Error logging reset initialization: {str(e)}")

            # Connect to database for the reset operations
            conn = sqlite3.connect(DB_NAME, timeout=60)
            c = conn.cursor()

            # Get all tables in the database
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [row[0] for row in c.fetchall()]

            # Delete data from all tables including admin
            for table in tables:
                if table.lower() != 'sqlite_sequence':
                    try:
                        # First count the records to be deleted
                        c.execute(f"SELECT COUNT(*) FROM {table}")
                        count = c.fetchone()[0]

                        # Delete all records
                        c.execute(f"DELETE FROM {table}")

                        # Reset auto-increment counters if applicable
                        try:
                            c.execute(f"DELETE FROM sqlite_sequence WHERE name=?", (table,))
                        except sqlite3.Error:
                            # sqlite_sequence table might not exist if no autoincrement has been used
                            pass

                        # Don't log each deletion - this would cause database locks
                        app.logger.info(f"Deleted {count} records from table {table}")
                    except sqlite3.Error as e:
                        app.logger.error(f"Error deleting data from {table}: {str(e)}")

            # Since we deleted all admin users (including the current user),
            # we need to recreate the default root account
            try:
                # Create default root user
                c.execute('''
                    INSERT INTO admin (username, password_hash)
                    VALUES (?, ?)
                ''', ('root', generate_password_hash('Pass1234')))
                conn.commit()

                app.logger.info("Created default root admin user with password 'Pass1234'")
            except Exception as e:
                app.logger.error(f"Error creating default admin user: {str(e)}")

            conn.close()

            # Reset root password in config.py
            config_path = get_config_path()

            # First read the current config
            with open(config_path, 'r') as f:
                config_lines = f.readlines()

            # Update the password
            new_config_lines = []
            password_updated = False

            for line in config_lines:
                if line.strip().startswith('ADMIN_PASSWORD ='):
                    new_config_lines.append("ADMIN_PASSWORD = 'Pass1234'\n")
                    password_updated = True
                else:
                    new_config_lines.append(line)

            # Add the password setting if it doesn't exist
            if not password_updated:
                new_config_lines.append("\n# Admin configuration\n")
                new_config_lines.append("ADMIN_PASSWORD = 'Pass1234'\n")

            # Write the updated config
            with open(config_path, 'w') as f:
                f.writelines(new_config_lines)

            app.logger.info("Reset root password to default in config.py")

            # NEW: Delete files in /logs directory
            logs_dir = os.path.join(get_app_base_dir(), 'logs')
            if os.path.exists(logs_dir):
                app.logger.info(f"Cleaning logs directory: {logs_dir}")
                log_files_count = 0
                for filename in os.listdir(logs_dir):
                    file_path = os.path.join(logs_dir, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                            log_files_count += 1
                    except Exception as e:
                        app.logger.error(f"Error deleting file {file_path}: {str(e)}")
                app.logger.info(f"Deleted {log_files_count} log files")
            else:
                app.logger.info(f"Logs directory {logs_dir} does not exist, creating it")
                os.makedirs(logs_dir, exist_ok=True)

            # NEW: Delete files in /backup directory
            backup_dir = os.path.join(get_app_base_dir(), 'backup')
            if os.path.exists(backup_dir):
                app.logger.info(f"Cleaning backup directory: {backup_dir}")
                backup_files_count = 0
                for filename in os.listdir(backup_dir):
                    file_path = os.path.join(backup_dir, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                            backup_files_count += 1
                    except Exception as e:
                        app.logger.error(f"Error deleting file {file_path}: {str(e)}")
                app.logger.info(f"Deleted {backup_files_count} backup files")
            else:
                app.logger.info(f"Backup directory {backup_dir} does not exist, creating it")
                os.makedirs(backup_dir, exist_ok=True)

            # Clear the session since the current user no longer exists
            session.clear()

            # Return success page - redirecting to login instead of reset_app.html
            # since the user is now logged out
            return redirect(url_for('login', reset_success=True))

        except Exception as e:
            app.logger.error(f"Error during application reset: {str(e)}", exc_info=True)
            return render_template('reset_app.html', error=f"An error occurred during reset: {str(e)}")

@app.route('/admin/config/save', methods=['POST'])
@login_required
def save_config():
    """Save updated configuration values"""
    try:
        # Get form data
        form_data = {
            'SECRET_KEY': request.form.get('secret_key'),
            'CLIENT_ID': request.form.get('client_id', ''),
            'CLIENT_SECRET': request.form.get('client_secret', ''),
            'REDIRECT_URI': request.form.get('redirect_uri', ''),
            'AUTH_URL': request.form.get('auth_url', ''),
            'TOKEN_URL': request.form.get('token_url', ''),
            'ME_URL': request.form.get('me_url', ''),
            'US_CLIENT_ID': request.form.get('us_client_id', ''),
            'US_CLIENT_SECRET': request.form.get('us_client_secret', ''),
            'US_REDIRECT_URI': request.form.get('us_redirect_uri', ''),
            'US_AUTH_URL': request.form.get('us_auth_url', ''),
            'US_TOKEN_URL': request.form.get('us_token_url', ''),
            'US_ME_URL': request.form.get('us_me_url', ''),
            'EMAIL_SENDER': request.form.get('email_sender', ''),
            'SMTP_SERVER': request.form.get('smtp_server', ''),
            'SMTP_PORT': request.form.get('smtp_port', ''),
            'SMTP_USERNAME': request.form.get('smtp_username', ''),
            'SMTP_PASSWORD': request.form.get('smtp_password', ''),
            'ADMIN_USERNAME': request.form.get('admin_username'),
            'ADMIN_PASSWORD': request.form.get('admin_password')
        }

        # Validate required non-API fields - removed email fields from required validation
        required_fields = [
            'ADMIN_USERNAME', 'SECRET_KEY'
        ]

        for field in required_fields:
            if not form_data.get(field):
                return redirect(url_for('config_management', error=f"The field '{field}' is required"))

        # Handle SMTP_PORT special case - set to 0 if empty
        if not form_data['SMTP_PORT']:
            form_data['SMTP_PORT'] = '0'  # Default to 0 if empty

        # Import current config to get values we won't change
        try:
            from config import ADMIN_PASSWORD as CURRENT_ADMIN_PASSWORD
        except ImportError:
            app.logger.error("Could not import config. Using empty string as current admin password.")
            CURRENT_ADMIN_PASSWORD = ""

        # Handle admin password - only update if a new one is provided and it's not a masked value
        if not form_data['ADMIN_PASSWORD']:
            form_data['ADMIN_PASSWORD'] = CURRENT_ADMIN_PASSWORD
        elif form_data['ADMIN_PASSWORD'] == '********' or all(c == '*' for c in form_data['ADMIN_PASSWORD']):
            # If the password is all asterisks, keep the current password
            form_data['ADMIN_PASSWORD'] = CURRENT_ADMIN_PASSWORD

        # Get absolute path to config.py
        config_path = get_config_path()
        app_dir = get_app_base_dir()

        app.logger.info(f"Saving configuration to {config_path}")
        app.logger.info(f"Working directory: {os.getcwd()}")
        app.logger.info(f"App directory: {app_dir}")

        # Create backup directory if it doesn't exist
        backup_dir = os.path.join(app_dir, 'backup')
        os.makedirs(backup_dir, exist_ok=True)

        # Create a timestamped backup of the current config if it exists
        if os.path.exists(config_path):
            import shutil
            from datetime import datetime
            backup_filename = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
            backup_path = os.path.join(backup_dir, backup_filename)
            shutil.copy2(config_path, backup_path)
            app.logger.info(f"Created config backup at {backup_path}")

            # Read the current config file
            with open(config_path, 'r') as f:
                config_lines = f.readlines()
        else:
            # Config file doesn't exist yet, create it
            app.logger.warning(f"Config file not found at {config_path}. Creating new file.")
            config_lines = []

        # If we have no lines (new file), initialize with basic structure
        if not config_lines:
            config_lines = [
                "# Samsara Partner Portal Configuration\n",
                "# Generated on: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n\n"
            ]

        # Update the config file
        new_config_lines = []
        updated_keys = set()

        for line in config_lines:
            # Check if this line defines a config value we want to update
            updated = False
            for key, value in form_data.items():
                # Check if the line starts with key =
                if line.strip().startswith(key + ' ='):
                    # For string values, add quotes
                    if key == 'SMTP_PORT':
                        # Always write SMTP_PORT as a number without quotes
                        new_config_lines.append(f"{key} = {value}\n")
                    elif isinstance(value, str):
                        new_config_lines.append(f"{key} = '{value}'\n")
                    else:
                        new_config_lines.append(f"{key} = {value}\n")
                    updated = True
                    updated_keys.add(key)
                    break

            # If line wasn't updated, keep it as is
            if not updated:
                new_config_lines.append(line)

        # Add any keys that weren't in the original file
        for key, value in form_data.items():
            if key not in updated_keys:
                if key == 'SMTP_PORT':
                    # Always write SMTP_PORT as a number without quotes
                    new_config_lines.append(f"{key} = {value}\n")
                elif isinstance(value, str):
                    new_config_lines.append(f"{key} = '{value}'\n")
                else:
                    new_config_lines.append(f"{key} = {value}\n")

        # Write the updated config back to the file
        try:
            with open(config_path, 'w') as f:
                f.writelines(new_config_lines)

            app.logger.info(f"Successfully updated configuration file at {config_path}")
        except Exception as write_error:
            app.logger.error(f"Error writing to config file: {str(write_error)}")
            # Try writing to a different location as a fallback
            fallback_path = os.path.join(os.getcwd(), 'config.py')
            app.logger.info(f"Attempting to write to fallback location: {fallback_path}")
            with open(fallback_path, 'w') as f:
                f.writelines(new_config_lines)
            app.logger.info(f"Successfully wrote to fallback location: {fallback_path}")

        # Log the config change
        log_audit_event(
            action='config_updated',
            username=session.get('username'),
            details=f"Configuration settings updated at {config_path}"
        )

        return redirect(url_for('config_management', success="Configuration has been updated successfully. Some changes may require restarting the application to take effect."))

    except Exception as e:
        app.logger.error(f"Error saving configuration: {str(e)}", exc_info=True)

        # Try to restore from backup if update failed
        try:
            app_dir = get_app_base_dir()
            backup_dir = os.path.join(app_dir, 'backup')
            config_path = get_config_path()

            # Find the most recent backup
            import glob
            backup_files = sorted(glob.glob(os.path.join(backup_dir, "config_backup_*.py")), reverse=True)

            if backup_files:
                import shutil
                latest_backup = backup_files[0]
                shutil.copy2(latest_backup, config_path)
                error_message = f"Error updating configuration: {str(e)}. Restored from backup {os.path.basename(latest_backup)}."
                app.logger.info(f"Restored config from backup: {latest_backup}")
            else:
                error_message = f"Error updating configuration: {str(e)}. No backup available to restore."
                app.logger.warning("No backups found to restore from")
        except Exception as backup_error:
            error_message = f"Error updating configuration: {str(e)}. Additionally, backup restoration failed: {str(backup_error)}"
            app.logger.error(f"Backup restoration failed: {str(backup_error)}")

        log_audit_event(
            action='config_update_failed',
            username=session.get('username'),
            details=error_message
        )

        return redirect(url_for('config_management', error=error_message))

@app.route('/admin/database', methods=['GET'])
@login_required
def database_admin():
    """Database administration page for viewing table data with pagination"""
    try:
        # Get query parameters
        selected_table = request.args.get('table')
        page = request.args.get('page', 1, type=int)
        per_page = 20  # Fixed at 20 rows per page

        # Connect to database
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Get all table names (excluding SQLite system tables)
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        tables = [row[0] for row in c.fetchall()]

        # Get table statistics - count rows in each table
        table_stats = []
        for table_name in tables:
            c.execute(f"SELECT COUNT(*) FROM '{table_name}'")
            count = c.fetchone()[0]
            table_stats.append({'name': table_name, 'count': count})

        # Get database file size
        import os
        db_path = os.path.abspath(DB_NAME)
        db_size = "Unknown"

        try:
            size_bytes = os.path.getsize(db_path)
            # Format size in human-readable format
            if size_bytes < 1024:
                db_size = f"{size_bytes} bytes"
            elif size_bytes < 1024 * 1024:
                db_size = f"{size_bytes / 1024:.2f} KB"
            else:
                db_size = f"{size_bytes / (1024 * 1024):.2f} MB"
        except OSError as e:
            app.logger.warning(f"Could not get database file size: {str(e)}")

        # Initialize variables
        table_data = []
        columns = []
        total_records = 0
        total_pages = 1

        # If a table is selected, fetch and paginate data
        if selected_table:
            # Sanitize table name to prevent SQL injection
            if selected_table not in tables:
                raise ValueError(f"Invalid table name: {selected_table}")

            # Get column names
            c.execute(f"PRAGMA table_info('{selected_table}')")
            columns = [row[1] for row in c.fetchall()]

            # Get total number of records
            c.execute(f"SELECT COUNT(*) FROM '{selected_table}'")
            total_records = c.fetchone()[0]

            # Calculate pagination values
            total_pages = (total_records + per_page - 1) // per_page if per_page > 0 else 1
            offset = (page - 1) * per_page

            # Fetch paginated data
            query = f"SELECT * FROM '{selected_table}' LIMIT {per_page} OFFSET {offset}"
            c.execute(query)
            table_data = c.fetchall()

            # Log the data access
            log_audit_event(
                action='database_view',
                username=session.get('username'),
                details=f"Viewed table data: {selected_table} (page {page})"
            )

        conn.close()

        return render_template(
            'database_admin.html',
            tables=tables,
            selected_table=selected_table,
            table_data=table_data,
            columns=columns,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            total_records=total_records,
            protected_tables=PROTECTED_TABLES,
            success=request.args.get('success'),
            error=request.args.get('error'),
            vacuum_success=request.args.get('vacuum_success'),
            table_stats=table_stats,
            db_size=db_size,
            db_path=db_path
        )

    except ValueError as e:
        # Handle invalid table name
        return render_template(
            'database_admin.html',
            tables=tables if 'tables' in locals() else [],
            error=str(e),
            protected_tables=PROTECTED_TABLES,
            table_stats=[],
            db_size="Unknown",
            db_path="Unknown"
        )
    except sqlite3.Error as e:
        # Handle database errors
        app.logger.error(f"Database error in database_admin: {str(e)}", exc_info=True)
        return render_template(
            'database_admin.html',
            tables=tables if 'tables' in locals() else [],
            error=f"Database error: {str(e)}",
            protected_tables=PROTECTED_TABLES,
            table_stats=[],
            db_size="Unknown",
            db_path="Unknown"
        )
    except Exception as e:
        # Handle unexpected errors
        app.logger.error(f"Error in database_admin: {str(e)}", exc_info=True)
        return render_template(
            'database_admin.html',
            tables=[],
            error=f"An unexpected error occurred: {str(e)}",
            protected_tables=PROTECTED_TABLES,
            table_stats=[],
            db_size="Unknown",
            db_path="Unknown"
        )


@app.route('/admin/database/vacuum', methods=['POST'])
@login_required
def vacuum_database():
    """Run VACUUM command on the SQLite database to optimize storage"""
    try:
        # Connect to database with immediate transaction mode
        conn = sqlite3.connect(DB_NAME, isolation_level=None)
        c = conn.cursor()

        # Get the size before vacuum
        import os
        size_before = os.path.getsize(DB_NAME)

        # Execute VACUUM command
        app.logger.info("Starting VACUUM operation on database")
        c.execute("VACUUM")
        app.logger.info("VACUUM operation completed")

        # Get the size after vacuum
        size_after = os.path.getsize(DB_NAME)

        # Calculate size difference
        size_diff = size_before - size_after

        # Format sizes in human-readable format
        def format_size(size_bytes):
            if size_bytes < 1024:
                return f"{size_bytes} bytes"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.2f} KB"
            else:
                return f"{size_bytes / (1024 * 1024):.2f} MB"

        size_before_formatted = format_size(size_before)
        size_after_formatted = format_size(size_after)

        # Prepare success message
        if size_diff > 0:
            vacuum_success = f"Database optimized successfully! Size reduced from {size_before_formatted} to {size_after_formatted} (saved {format_size(size_diff)})."
        else:
            vacuum_success = f"Database optimized successfully! Size: {size_after_formatted} (no space reduction)."

        # Log the vacuum operation
        log_audit_event(
            action='database_vacuum',
            username=session.get('username'),
            details=f"Performed VACUUM operation. Size before: {size_before_formatted}, Size after: {size_after_formatted}"
        )

        conn.close()

        # Redirect back to database admin page with success message
        return redirect(url_for('database_admin', vacuum_success=vacuum_success))

    except sqlite3.Error as e:
        app.logger.error(f"Database error during VACUUM: {str(e)}", exc_info=True)
        return redirect(url_for('database_admin', error=f"Database error during VACUUM: {str(e)}"))
    except Exception as e:
        app.logger.error(f"Error during VACUUM: {str(e)}", exc_info=True)
        return redirect(url_for('database_admin', error=f"An unexpected error occurred during VACUUM: {str(e)}"))


@app.route('/admin/database/delete', methods=['POST'])
@login_required
def delete_table_records():
    """Delete all records from a specified table with confirmation"""
    try:
        # Get form data
        table_name = request.form.get('delete_table')

        # Connect to database
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Validate table name exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not c.fetchone():
            conn.close()
            return redirect(url_for('database_admin', error=f"Table '{table_name}' does not exist"))

        # Check if table is protected
        if table_name in PROTECTED_TABLES:
            conn.close()
            return redirect(url_for('database_admin', error=f"Cannot delete records from protected table '{table_name}'"))

        # Get record count before deletion
        c.execute(f"SELECT COUNT(*) FROM {table_name}")
        count_before = c.fetchone()[0]

        # Delete all records
        c.execute(f"DELETE FROM {table_name}")

        # Reset auto-increment counters if table has an INTEGER PRIMARY KEY
        c.execute(f"PRAGMA table_info({table_name})")
        has_autoincrement = False
        for row in c.fetchall():
            if row[5] == 1 and row[2].upper() == 'INTEGER':  # is PK and INTEGER type
                has_autoincrement = True
                break

        if has_autoincrement:
            try:
                c.execute(f"DELETE FROM sqlite_sequence WHERE name=?", (table_name,))
            except sqlite3.Error:
                # sqlite_sequence table might not exist if no autoincrement has been used
                pass

        conn.commit()

        # Log the deletion
        log_audit_event(
            action='database_delete_records',
            username=session.get('username'),
            details=f"Deleted all records ({count_before}) from table: {table_name}"
        )

        conn.close()

        return redirect(url_for('database_admin', success=f"Successfully deleted {count_before} records from table '{table_name}'"))

    except sqlite3.Error as e:
        app.logger.error(f"Database error in delete_table_records: {str(e)}", exc_info=True)
        return redirect(url_for('database_admin', error=f"Database error: {str(e)}"))
    except Exception as e:
        app.logger.error(f"Error in delete_table_records: {str(e)}", exc_info=True)
        return redirect(url_for('database_admin', error=f"An unexpected error occurred: {str(e)}"))

@app.route('/admin/config', methods=['GET'])
@login_required
def config_management():
	"""Display configuration management page with dynamic config reloading"""
	try:
		# Force reload the config module to get fresh values
		import importlib
		import sys

		# Remove the config module from cache if it exists
		if 'config' in sys.modules:
			del sys.modules['config']

		# Re-import the config module to get fresh values
		import config
		importlib.reload(config)

		# Get all configuration values from the freshly loaded module
		config_values = {
			'SECRET_KEY': getattr(config, 'SECRET_KEY', ''),
			'CLIENT_ID': getattr(config, 'CLIENT_ID', ''),
			'CLIENT_SECRET': getattr(config, 'CLIENT_SECRET', ''),
			'REDIRECT_URI': getattr(config, 'REDIRECT_URI', ''),
			'AUTH_URL': getattr(config, 'AUTH_URL', ''),
			'TOKEN_URL': getattr(config, 'TOKEN_URL', ''),
			'ME_URL': getattr(config, 'ME_URL', ''),
			'US_CLIENT_ID': getattr(config, 'US_CLIENT_ID', ''),
			'US_CLIENT_SECRET': getattr(config, 'US_CLIENT_SECRET', ''),
			'US_REDIRECT_URI': getattr(config, 'US_REDIRECT_URI', ''),
			'US_AUTH_URL': getattr(config, 'US_AUTH_URL', ''),
			'US_TOKEN_URL': getattr(config, 'US_TOKEN_URL', ''),
			'US_ME_URL': getattr(config, 'US_ME_URL', ''),
			'EMAIL_SENDER': getattr(config, 'EMAIL_SENDER', ''),
			'SMTP_SERVER': getattr(config, 'SMTP_SERVER', ''),
			'SMTP_PORT': getattr(config, 'SMTP_PORT', ''),
			'SMTP_USERNAME': getattr(config, 'SMTP_USERNAME', ''),
			'SMTP_PASSWORD': getattr(config, 'SMTP_PASSWORD', ''),
			'ADMIN_USERNAME': getattr(config, 'ADMIN_USERNAME', ''),
			'ADMIN_PASSWORD': '********'  # Mask the actual password
		}

		# Log that we've successfully reloaded the config
		app.logger.info(f"Successfully reloaded config module from {get_config_path()}")

		return render_template(
			'config_management.html',
			config=config_values,
			success=request.args.get('success'),
			error=request.args.get('error')
		)

	except ImportError as e:
		# Handle case where config.py doesn't exist or can't be imported
		app.logger.error(f"Error importing config module: {str(e)}")

		# Get the config path
		config_path = get_config_path()
		app.logger.info(f"Checking for config at: {config_path}")

		# Check if the file exists
		if not os.path.exists(config_path):
			app.logger.error(f"Config file not found at {config_path}")
			return render_template(
				'config_management.html',
				error=f"Configuration file not found. Please create a config.py file in {get_app_base_dir()}.",
				config={}
			)

		# If the file exists but can't be imported, there's a syntax error
		return render_template(
			'config_management.html',
			error=f"Error importing from config.py: {str(e)}. Please check the file for syntax errors.",
			config={}
		)

	except Exception as e:
		app.logger.error(f"Error displaying config management: {str(e)}", exc_info=True)
		return render_template(
			'config_management.html',
			error=f"Error loading configuration: {str(e)}",
			config={}
		)


@app.route('/safety-scores')
@login_required
def safety_scores():
	"""Display driver safety scores dashboard"""
	try:
		# Connect to database to get the organizations
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()

		# Get all organizations for dropdown
		c.execute('SELECT org_id, org_name, region FROM organizations ORDER BY org_name')
		organizations = []
		for row in c.fetchall():
			organizations.append({
				'org_id': row[0],
				'org_name': row[1],
				'region': row[2]
			})

		conn.close()

		return render_template('safety_scores.html',
							 organizations=organizations,
							 active_tab='safety_scores')

	except Exception as e:
		app.logger.error(f"Error accessing safety scores page: {str(e)}", exc_info=True)
		return render_template('safety_scores.html',
							 error=f"An error occurred: {str(e)}",
							 organizations=[],
							 active_tab='safety_scores')


@app.route('/api/safety-scores')
@login_required
def get_safety_scores():
	"""API endpoint to get driver safety scores based on filters"""
	try:
		# Get query parameters
		org_ids_param = request.args.get('orgs', '')
		start_date = request.args.get('start_date')
		end_date = request.args.get('end_date')

		# Parse org IDs from comma-separated string
		org_ids = org_ids_param.split(',') if org_ids_param else []

		# Validate required parameters
		if not start_date or not end_date:
			return jsonify({'error': 'Start date and end date are required'})

		# Connect to database
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()

		# If no org_ids specified, get all accessible organizations
		if not org_ids:
			c.execute('SELECT org_id, org_name, region FROM organizations')
			orgs_to_process = c.fetchall()
		else:
			# Only process selected organizations
			placeholders = ','.join(['?' for _ in org_ids])
			c.execute(f'SELECT org_id, org_name, region FROM organizations WHERE org_id IN ({placeholders})',
					 org_ids)
			orgs_to_process = c.fetchall()

		if not orgs_to_process:
			return jsonify({'error': 'No organizations found'})

		# Format dates for API request
		try:
			# Parse the dates and set them to start and end of day
			start_dt = datetime.strptime(start_date, '%Y-%m-%d')
			# Set to beginning of day (midnight)
			start_dt = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)

			end_dt = datetime.strptime(end_date, '%Y-%m-%d')
			# Set to end of day (23:59:59)
			end_dt = end_dt.replace(hour=23, minute=59, second=59, microsecond=999999)

			# Convert to milliseconds for API
			start_ms = int(start_dt.timestamp() * 1000)
			end_ms = int(end_dt.timestamp() * 1000)

			app.logger.info(f"Date range: {start_dt} to {end_dt}")
			app.logger.info(f"Timestamp range: {start_ms} to {end_ms}")
		except ValueError:
			return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'})

		# Initialize response data
		all_drivers = []
		summary = {
			'avgSafetyScore': 0,
			'totalHarshEvents': 0,
			'totalDistanceDrivenMeters': 0,
			'totalTimeDrivenMs': 0
		}

		# Process each organization
		for org_row in orgs_to_process:
			org_id, org_name, region = org_row

			# Get a valid access token
			access_token = get_valid_token(org_id)
			if not access_token:
				app.logger.warning(f"Could not get valid token for organization {org_name}")
				continue

			# Determine API URL based on region
			base_url = "https://api.eu.samsara.com" if region == 'emea' else "https://api.samsara.com"

			# First, get all drivers for this organization
			try:
				app.logger.info(f"Fetching drivers for organization {org_name} (ID: {org_id})")

				# Define headers for all API requests
				headers = {
					"Authorization": f"Bearer {access_token}",
					"Accept": "application/json"
				}

				# Get drivers with pagination
				all_org_drivers = []
				drivers_url = f"{base_url}/fleet/drivers"
				has_more_drivers = True
				after_cursor = None

				while has_more_drivers:
					# Add pagination parameters if we have a cursor
					params = {'limit': 100}
					if after_cursor:
						params['after'] = after_cursor

					drivers_response = requests.get(drivers_url, headers=headers, params=params)

					if drivers_response.status_code != 200:
						app.logger.error(f"Error fetching drivers: {drivers_response.text}")
						break

					drivers_data = drivers_response.json()
					org_drivers_page = drivers_data.get('data', [])
					all_org_drivers.extend(org_drivers_page)

					# Check if there are more pages
					pagination = drivers_data.get('pagination', {})
					after_cursor = pagination.get('endCursor')
					has_more_drivers = pagination.get('hasNextPage', False)

				app.logger.info(f"Found {len(all_org_drivers)} drivers for {org_name}")

				# For each driver, get safety score
				for driver in all_org_drivers:
					# Extract driver information - ensure we properly handle the name
					driver_id = driver.get('id')
					driver_name = driver.get('name', '').strip()

					# If no name is provided, try to construct it from firstName and lastName
					if not driver_name:
						first_name = driver.get('firstName', '')
						last_name = driver.get('lastName', '')
						if first_name or last_name:
							driver_name = f"{first_name} {last_name}".strip()
						else:
							driver_name = f"Driver {driver_id}"

					if not driver_id:
						app.logger.warning(f"Skipping driver with no ID in organization {org_name}")
						continue

					app.logger.info(f"Fetching safety score for driver {driver_name} (ID: {driver_id})")

					# Get safety score for this driver
					# The correct endpoint format: /v1/fleet/drivers/{driverId}/safety/score
					safety_url = f"{base_url}/v1/fleet/drivers/{driver_id}/safety/score"
					params = {
						'startMs': start_ms,
						'endMs': end_ms
					}

					try:
						app.logger.info(f"Accessing safety score API: {safety_url} with params: {params}")
						safety_response = requests.get(safety_url, headers=headers, params=params)

						# Try a third format if needed - some API versions might require this
						if safety_response.status_code != 200:
							app.logger.warning(f"Error getting safety score for driver {driver_id}: {safety_response.text}")

							# Try legacy endpoint without v1 prefix
							alt_safety_url = f"{base_url}/fleet/drivers/{driver_id}/safety/score"
							app.logger.info(f"Trying alternative endpoint: {alt_safety_url}")
							alt_safety_response = requests.get(alt_safety_url, headers=headers, params=params)

							if alt_safety_response.status_code != 200:
								app.logger.warning(f"Alternative endpoint also failed: {alt_safety_response.text}")

								# Try third format with organization ID
								third_safety_url = f"{base_url}/v1/fleet/drivers/safety/score"
								third_params = {
									'driverId': driver_id,
									'startMs': start_ms,
									'endMs': end_ms
								}
								app.logger.info(f"Trying third endpoint format: {third_safety_url} with params: {third_params}")
								third_safety_response = requests.get(third_safety_url, headers=headers, params=third_params)

								if third_safety_response.status_code != 200:
									app.logger.warning(f"Third endpoint format also failed: {third_safety_response.text}")
									continue
								else:
									app.logger.info(f"Third endpoint format succeeded for driver {driver_id}")
									safety_data = third_safety_response.json()
							else:
								app.logger.info(f"Alternative endpoint succeeded for driver {driver_id}")
								safety_data = alt_safety_response.json()
						else:
							safety_data = safety_response.json()

						# Skip if safety score is lower than minimum filter
						# Removed minimum score filter - we'll return all scores

						# Add organization and driver name to the data
						safety_data['orgName'] = org_name
						safety_data['driverName'] = driver_name

						# Add to list of all drivers
						all_drivers.append(safety_data)

						# Update summary statistics
						summary['totalHarshEvents'] += safety_data.get('totalHarshEventCount', 0)
						summary['totalDistanceDrivenMeters'] += safety_data.get('totalDistanceDrivenMeters', 0)
						summary['totalTimeDrivenMs'] += safety_data.get('totalTimeDrivenMs', 0)

					except requests.RequestException as e:
						app.logger.error(f"Request error for driver {driver_id}: {str(e)}")
						continue

			except requests.RequestException as e:
				app.logger.error(f"Error fetching data for organization {org_name}: {str(e)}")
				continue

			app.logger.info(f"Completed processing organization {org_name}: Found {len(all_drivers)} qualifying drivers")

		# Calculate average safety score
		if all_drivers:
			total_score = sum(driver.get('safetyScore', 0) for driver in all_drivers)
			summary['avgSafetyScore'] = total_score / len(all_drivers)

			# Sort drivers by safety score (descending)
			all_drivers.sort(key=lambda x: x.get('safetyScore', 0), reverse=True)

			app.logger.info(f"Final results: {len(all_drivers)} drivers with average score {summary['avgSafetyScore']:.2f}")
		else:
			app.logger.warning("No qualifying drivers found for the selected criteria")

		return jsonify({
			'drivers': all_drivers,
			'summary': summary
		})

	except Exception as e:
		app.logger.error(f"Error getting safety scores: {str(e)}", exc_info=True)
		return jsonify({'error': str(e)}), 500
	finally:
		if 'conn' in locals():
			conn.close()


@app.route('/safety-settings')
@login_required
def safety_settings():
	"""Display safety settings for organizations"""
	try:
		# Connect to database
		conn = sqlite3.connect(DB_NAME)
		conn.row_factory = sqlite3.Row
		c = conn.cursor()

		# Get all organizations
		c.execute('SELECT org_id, org_name, region FROM organizations ORDER BY org_name')
		organizations = [dict(row) for row in c.fetchall()]

		conn.close()

		return render_template('safety_settings.html',
							 organizations=organizations,
							 active_tab='safety_settings')

	except Exception as e:
		app.logger.error(f"Error accessing safety settings: {str(e)}", exc_info=True)
		return render_template('safety_settings.html',
							 error=f"An error occurred: {str(e)}",
							 organizations=[],
							 active_tab='safety_settings')



@app.route('/api/safety-settings/<org_id>')
@login_required
def get_org_safety_settings(org_id):
	"""Fetch safety settings for a specific organization and store in database"""
	try:
		# Get valid token for the organization
		access_token = get_valid_token(org_id)
		if not access_token:
			return jsonify({'error': 'Unable to get valid token for organization'}), 401

		# Get organization details for region
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()
		c.execute('SELECT org_name, region FROM organizations WHERE org_id = ?', (org_id,))
		result = c.fetchone()
		if not result:
			conn.close()
			return jsonify({'error': 'Organization not found'}), 404

		org_name, region = result

		# Determine appropriate API base URL based on region
		if region == 'us':
			base_url = "https://api.samsara.com"
		else:  # EMEA
			base_url = "https://api.eu.samsara.com"

		# Fetch safety settings from Samsara API
		url = f"{base_url}/fleet/settings/safety"
		headers = {
			"accept": "application/json",
			"authorization": f"Bearer {access_token}"
		}

		response = requests.get(url, headers=headers)
		response.raise_for_status()

		# Get the response data
		settings_data = response.json()

		# Save to database - first check if safety_settings table exists
		c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='safety_settings'")
		table_exists = c.fetchone() is not None

		if not table_exists:
			# Create the table if it doesn't exist
			c.execute('''
				CREATE TABLE safety_settings (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					org_id TEXT NOT NULL,
					org_name TEXT NOT NULL,
					settings_json TEXT NOT NULL,
					last_updated TIMESTAMP NOT NULL,
					UNIQUE(org_id)
				)
			''')

		# Delete any existing settings for this org
		c.execute('DELETE FROM safety_settings WHERE org_id = ?', (org_id,))

		# Insert new settings
		c.execute('''
			INSERT INTO safety_settings
			(org_id, org_name, settings_json, last_updated)
			VALUES (?, ?, ?, ?)
		''', (
			org_id,
			org_name,
			json.dumps(settings_data),
			datetime.utcnow().isoformat()
		))

		conn.commit()
		conn.close()

		# Log the API call
		log_audit_event(
			action='safety_settings_api_call',
			username=session.get('username'),
			details=f"Fetched and stored safety settings for organization {org_id}"
		)

		return jsonify(settings_data)

	except requests.RequestException as e:
		app.logger.error(f"API error fetching safety settings: {str(e)}", exc_info=True)
		return jsonify({'error': f"API error: {str(e)}"}), 500
	except Exception as e:
		app.logger.error(f"Error fetching safety settings: {str(e)}", exc_info=True)
		return jsonify({'error': str(e)}), 500

@app.route('/api/stored-safety-settings')
@login_required
def get_stored_safety_settings():
	"""Get the stored safety settings from the database"""
	try:
		conn = sqlite3.connect(DB_NAME)
		conn.row_factory = sqlite3.Row
		c = conn.cursor()

		# First check if safety_settings table exists
		c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='safety_settings'")
		if not c.fetchone():
			conn.close()
			return jsonify({
				'error': 'Error fetching stored settings',
				'last_updated': None,
				'settings': []
			})

		# Get the latest updated timestamp
		c.execute('SELECT MAX(last_updated) as last_updated FROM safety_settings')
		result = c.fetchone()
		last_updated = result['last_updated'] if result and result['last_updated'] else None

		# Get all stored safety settings
		c.execute('''
			SELECT org_id, org_name, settings_json, last_updated
			FROM safety_settings
			ORDER BY org_name
		''')

		settings = []
		for row in c.fetchall():
			try:
				settings.append({
					'org_id': row['org_id'],
					'org_name': row['org_name'],
					'settings': json.loads(row['settings_json']),
					'last_updated': row['last_updated']
				})
			except json.JSONDecodeError as e:
				app.logger.error(f"JSON decode error for org {row['org_name']}: {str(e)}")
				# Include error in settings but don't break the whole request
				continue

		conn.close()

		return jsonify({
			'last_updated': last_updated,
			'settings': settings
		})

	except Exception as e:
		app.logger.error(f"Error retrieving stored safety settings: {str(e)}", exc_info=True)
		return jsonify({
			'error': f"Error fetching stored settings: {str(e)}",
			'last_updated': None,
			'settings': []
		})

@app.route('/admin/config/restart-service', methods=['POST'])
@login_required
def restart_service():
	"""Restart the samsara-partner systemd service"""
	try:
		# Log the restart attempt
		log_audit_event(
			action='service_restart_initiated',
			username=session.get('username'),
			details="Initiated restart of samsara-partner service"
		)

		# Execute the systemctl command
		import subprocess
		result = subprocess.run(
			['sudo', 'systemctl', 'restart', 'samsara-partner'],
			capture_output=True,
			text=True
		)

		# Check if the command was successful
		if result.returncode == 0:
			# Log success
			log_audit_event(
				action='service_restart_success',
				username=session.get('username'),
				details="Successfully restarted samsara-partner service"
			)
			return jsonify({'success': True})
		else:
			# Log error
			error_msg = f"Error restarting service: {result.stderr}"
			app.logger.error(error_msg)
			log_audit_event(
				action='service_restart_failed',
				username=session.get('username'),
				details=error_msg
			)
			return jsonify({
				'success': False,
				'message': f"Error restarting service: {result.stderr}"
			})

	except Exception as e:
		# Log the error
		error_msg = f"Exception during service restart: {str(e)}"
		app.logger.error(error_msg, exc_info=True)
		log_audit_event(
			action='service_restart_error',
			username=session.get('username'),
			details=error_msg
		)

		return jsonify({
			'success': False,
			'message': f"An error occurred: {str(e)}"
		}), 500



@app.route('/admin/orgs/delete', methods=['POST'])
@login_required
def delete_org():
    """
    Handle organization deletion with improved handling of special characters
    and removal of any restrictions on deleting the last organization
    """
    try:
        org_id = request.form.get('org_id')
        if not org_id:
            return redirect(url_for('manage_orgs', error="Organization ID is required"))

        # Connect to database
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Get the organization name before deleting (with proper parameter binding)
        c.execute('SELECT org_name FROM organizations WHERE org_id = ?', (org_id,))
        result = c.fetchone()

        if not result:
            conn.close()
            return redirect(url_for('manage_orgs', error="Organization not found"))

        org_name = result[0]

        # Force delete the organization regardless of how many orgs are left
        # This is the key change - removing any restriction on deleting the last organization
        c.execute('DELETE FROM organizations WHERE org_id = ?', (org_id,))

        # Also delete related safety settings if they exist
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='safety_settings'")
        if c.fetchone():
            c.execute('DELETE FROM safety_settings WHERE org_id = ?', (org_id,))

        # Make sure to commit changes
        conn.commit()
        conn.close()

        # Log the deletion in audit log
        log_audit_event(
            action='organization_deleted',
            username=session.get('username'),
            details=f"Deleted organization: {org_name} (ID: {org_id})"
        )

        # Use HTML-safe org name in the success message
        safe_org_name = org_name.replace("'", "&#39;")
        return redirect(url_for('manage_orgs', success=f"Organization '{safe_org_name}' has been deleted successfully"))

    except Exception as e:
        app.logger.error(f"Error deleting organization: {str(e)}", exc_info=True)
        return redirect(url_for('manage_orgs', error=f"An error occurred: {str(e)}"))


@app.route('/api/organizations/delete/<org_id>', methods=['POST'])
@login_required
def delete_organization_endpoint(org_id):
    """
    Delete an organization's tokens with CSRF protection and improved handling of special characters
    """
    try:
        # Connect to database
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Get the organization name before deleting
        c.execute('SELECT org_name FROM organizations WHERE org_id = ?', (org_id,))
        result = c.fetchone()

        if not result:
            # Organization not found
            conn.close()
            return jsonify({'success': False, 'error': 'Organization not found'}), 404

        org_name = result[0]

        # Delete the organization
        c.execute('DELETE FROM organizations WHERE org_id = ?', (org_id,))

        # Also delete related safety settings if they exist
        # Check if safety_settings table exists first
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='safety_settings'")
        if c.fetchone():
            c.execute('DELETE FROM safety_settings WHERE org_id = ?', (org_id,))

        conn.commit()

        # Log the deletion in audit log
        log_audit_event(
            action='organization_deleted',
            username=session.get('username'),
            details=f"Deleted organization: {org_name} (ID: {org_id})"
        )

        conn.close()

        # HTML-escape the organization name for the response
        safe_org_name = org_name.replace("'", "&#39;")
        return jsonify({'success': True, 'message': f'Organization {safe_org_name} deleted successfully'})

    except Exception as e:
        app.logger.error(f"Error deleting organization {org_id}: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/organizations/<org_id>', methods=['DELETE'])
@login_required  # Add login_required decorator to ensure authentication
def delete_organization(org_id):
    """Delete an organization's tokens"""
    try:
        # Connect to database
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Get the organization name before deleting
        c.execute('SELECT org_name FROM organizations WHERE org_id = ?', (org_id,))
        result = c.fetchone()

        if not result:
            # Organization not found
            conn.close()
            return jsonify({'success': False, 'error': 'Organization not found'}), 404

        org_name = result[0]

        # Delete the organization
        c.execute('DELETE FROM organizations WHERE org_id = ?', (org_id,))

        # Also delete related safety settings if they exist
        # Check if safety_settings table exists first
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='safety_settings'")
        if c.fetchone():
            c.execute('DELETE FROM safety_settings WHERE org_id = ?', (org_id,))

        conn.commit()

        # Log the deletion in audit log
        log_audit_event(
            action='organization_deleted',
            username=session.get('username'),
            details=f"Deleted organization: {org_name} (ID: {org_id})"
        )

        conn.close()
        return jsonify({'success': True, 'message': f'Organization {org_name} deleted successfully'})

    except Exception as e:
        app.logger.error(f"Error deleting organization {org_id}: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/process-status/<session_id>')
def get_process_status(session_id):
	"""Check if all organizations have been processed for a session"""
	try:
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()

		# Get total number of organizations being processed
		c.execute('''
			SELECT COUNT(DISTINCT org_id)
			FROM status_messages
			WHERE session_id = ?
			AND message LIKE 'Starting processing for%'
		''', (session_id,))
		total_orgs = c.fetchone()[0]

		# Get number of completed organizations
		c.execute('''
			SELECT COUNT(DISTINCT org_id)
			FROM status_messages
			WHERE session_id = ?
			AND (
				message LIKE 'Processing completed successfully for%'
				OR message LIKE 'Error processing%'
			)
		''', (session_id,))
		completed_orgs = c.fetchone()[0]

		# Check for final completion message
		c.execute('''
			SELECT EXISTS(
				SELECT 1
				FROM status_messages
				WHERE session_id = ?
				AND message = 'All organizations processed. Generation complete.'
			)
		''', (session_id,))
		has_final_message = c.fetchone()[0]

		all_complete = (total_orgs > 0 and total_orgs == completed_orgs) or has_final_message

		return jsonify({
			'all_complete': all_complete,
			'total_orgs': total_orgs,
			'completed_orgs': completed_orgs
		})

	except Exception as e:
		app.logger.error(f"Error checking process status: {str(e)}")
		return jsonify({'error': str(e)}), 500
	finally:
		if 'conn' in locals():
			conn.close()




@app.route('/admin/orgs')
@login_required
def manage_orgs():
    """Display organization management page with all connected organizations"""
    try:
        # Get query parameters for success/error messages
        success = request.args.get('success')
        error = request.args.get('error')

        # Connect to database
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row  # This allows accessing columns by name
        c = conn.cursor()

        # Get all organizations
        c.execute('''
            SELECT org_id, org_name, last_updated, expires_at, region
            FROM organizations
            ORDER BY org_name
        ''')
        organizations = [dict(row) for row in c.fetchall()]

        conn.close()

        # Log audit event for page access
        log_audit_event(
            action='page_access',
            username=session.get('username'),
            details="Accessed organization management page"
        )

        return render_template('manage_orgs.html',
                              organizations=organizations,
                              success=success,
                              error=error)

    except Exception as e:
        app.logger.error(f"Error accessing organization management: {str(e)}", exc_info=True)
        return render_template('manage_orgs.html',
                              error=f"An error occurred: {str(e)}",
                              organizations=[])

@app.route('/start_auth', methods=['POST'])
def start_auth():
	"""Start OAuth2 authentication flow with correct scopes and region handling"""
	# Get and store the selected region
	region = request.form.get('region', 'emea')
	session['selected_region'] = region

	# Generate and store state parameter to prevent CSRF
	state = secrets.token_hex(16)
	session['oauth_state'] = state

	# Select credentials based on region
	if region == 'us':
		client_id = US_CLIENT_ID
		redirect_uri = US_REDIRECT_URI
		auth_url = US_AUTH_URL
	else:  # EMEA
		client_id = CLIENT_ID
		redirect_uri = REDIRECT_URI
		auth_url = AUTH_URL

	# Build authorization URL with correct scopes
	params = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'response_type': 'code',
		# 'scope': 'admin:read',
    'scope': 'admin:write',
		'state': state
	}

	auth_url = f"{auth_url}?{urlencode(params)}"
	return redirect(auth_url)


if __name__ == '__main__':
	# Initialize database
	init_db()

	app.run(host='0.0.0.0', port=8000)