#!/usr/bin/env python3
"""
SecureNet Backend API with EDNS Integration
Complete authentication system with ML, behavioral biometrics, and DNS security
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from backend.auth_engine import AuthenticationEngine, UserBehavioralProfile
import os
import sys
from datetime import datetime, timedelta, timezone
import jwt
import hashlib
from flask_bcrypt import Bcrypt
import secrets
from flask_socketio import SocketIO, emit
from collections import defaultdict
import threading
import time
import pyotp
import qrcode
import io
import base64
import json
from flask_mail import Mail, Message
import random
from backend.admin_routes import admin_bp
import eventlet
eventlet.monkey_patch(socket=True, select=True, time=True)
# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.edns_integration import EDNSSecurityLayer
from backend.models import DatabaseManager

# Initialize Flask app
app = Flask(__name__, 
            static_folder='../frontend',
            static_url_path='')
socketio = SocketIO(app, cors_allowed_origins="*")

CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
bcrypt = Bcrypt(app) 
# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'securenet220@gmail.com'  # Change this
app.config['MAIL_PASSWORD'] = 'wfdi lrsk fvxr cjkj'     # Change this
app.config['MAIL_DEFAULT_SENDER'] = 'SecureNet <noreply@securenet.com>'

mail = Mail(app)

# Store OTP codes temporarily (use Redis in production)
otp_storage = {}

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_EXPIRATION'] = 3600  # 1 hour
app.config['MAX_FAILED_ATTEMPTS'] = 5

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize components
auth_engine = AuthenticationEngine()
edns_layer = EDNSSecurityLayer()
db = DatabaseManager(
    host='securenet-securenet1.c.aivencloud.com',
    user='avnadmin',
    password='AVNS_DzruYfuj_BgF2aD1K9c',  # Change this!
    database='defaultdb', port=10675
)
app.config['DB'] = db
app.register_blueprint(admin_bp)
# =====================================================================
# UTILITY FUNCTIONS
# =====================================================================

import requests

def get_client_ip():
    """Get real client IP address."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

def get_ip_location(ip_address):
    """Get location from IP using ipinfo.io + IPHub VPN detection"""
    import urllib.request
    import json
    
    # Skip localhost/private IPs
    if ip_address in ['127.0.0.1', '::1', 'localhost', '0.0.0.0'] or \
       ip_address.startswith(('192.168.', '10.', '172.')):
        return {
            'country': 'US',
            'asn': '0',
            'ip_address': ip_address,
            'is_vpn': False
        }
    
    result = {
        'country': 'Unknown',
        'asn': '0',
        'ip_address': ip_address,
        'is_vpn': False
    }
    
    # Get geolocation from ipinfo.io
    try:
        url = f'https://ipinfo.io/{ip_address}/json'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            org = data.get('org', '')
            asn = '0'
            if org and org.startswith('AS'):
                asn = org.split()[0].replace('AS', '')
            
            result['country'] = data.get('country', 'Unknown')
            result['asn'] = asn
            
    except Exception as e:
        print(f"❌ ipinfo error: {type(e).__name__}")
    
    # Check for VPN/proxy using IPHub
    try:
        import requests
        
        iphub_response = requests.get(
            f'https://v2.api.iphub.info/ip/{ip_address}',
            headers={'X-Key': 'MzAzNzE6cDUzQ1pBM2RoRHZXbmdob2JCWmRYNUhoY0IzNXNLcVo='},  # ← Replace with your key
            timeout=5
        )
        
        if iphub_response.ok:
            iphub_data = iphub_response.json()
            block_value = iphub_data.get('block', 0)
            
            # 0 = Residential/safe, 1 = VPN/proxy, 2 = Datacenter/hosting
            if block_value in [1, 2]:
                result['is_vpn'] = True
                vpn_type = 'VPN/Proxy' if block_value == 1 else 'Datacenter'
                print(f"🚨 {vpn_type} detected for {ip_address}")
            else:
                print(f"✓ Residential IP: {ip_address}")
                
    except Exception as e:
        print(f"❌ IPHub error: {type(e).__name__}")
    
    print(f"🌍 {ip_address}: {result['country']}, ASN: {result['asn']}, VPN: {result['is_vpn']}")
    
    return result




def is_vpn_or_datacenter(asn):
    """Check if ASN belongs to known VPN/hosting providers."""
    vpn_hosting_asns = [
        '13335',  # Cloudflare
        '16509',  # Amazon AWS
        '14061',  # DigitalOcean
        '15169',  # Google Cloud
        '8075',   # Microsoft Azure
        '36352',  # ColoCrossing
        '62904',  # Eonix
        '46606',  # Unified Layer (HostGator)
        '19318',  # Interserver
        '20473',  # Choopa (Vultr)
        # Add more as needed
    ]
    return asn in vpn_hosting_asns


def generate_token(user_id):
    """Generate JWT token for authenticated user."""
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(seconds=app.config['JWT_EXPIRATION']),
        'iat': datetime.now(timezone.utc)   
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    """Verify JWT token."""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def hash_password(password):
    """Hash password with SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

# =====================================================================
# ROUTES - Frontend Pages
# =====================================================================

@app.route('/')
def index():
    """Serve landing page."""
    return send_from_directory('../frontend', 'index.html')

@app.route('/register')
def register_page():
    """Serve registration page."""
    return send_from_directory('../frontend', 'register.html')

@app.route('/login')
def login_page():
    """Serve login page."""
    return send_from_directory('../frontend', 'login.html')

@app.route('/dashboard')
def dashboard_page():
    """Serve user dashboard."""
    return send_from_directory('../frontend', 'dashboard.html')

@app.route('/admin')
def admin_page():
    """Serve admin monitoring dashboard."""
    return send_from_directory('../frontend', 'admin.html')

# =====================================================================
# API ROUTES - Authentication
# =====================================================================
@app.route('/api/register', methods=['POST'])
@limiter.limit("3 per hour")
def api_register():
    """Register new user."""
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Validate inputs
        if not username or not email or not password:
            return jsonify({'error': 'All fields required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if user exists
        if db.user_exists(username):
            return jsonify({'error': 'Username already exists'}), 400
        
        # Hash password - CRITICAL: Must be bytes, then decoded to string
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        print(f"✓ Generated hash for '{username}': {password_hash[:20]}...")  # Debug
        print(f"  Hash length: {len(password_hash)}")  # Should be ~60 chars
        
        # Create behavioral profile
        profile_id = username
        profile = UserBehavioralProfile(profile_id)
        
        # Capture registration baseline
        registration_data = {
            'keystroke_timings': data.get('keystroke_timings', []),
            'network_info': data.get('network_info', {})
        }
        profile.capture_registration_baseline(registration_data)
        
        # Save profile
        auth_engine._save_profile(profile)
        
        # Create user in database
        user_id = db.create_user(username, email, password_hash, profile_id)
        
        print(f"✓ User created with ID: {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful! Please login.'
        }), 201
        
    except Exception as e:
        print(f"❌ Registration error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    """Authenticate user with adaptive MFA based on risk level."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        # Validate user
        user = db.get_user(username)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user['is_locked']:
            return jsonify({'error': 'Account locked due to multiple failed attempts'}), 403
        
        # Verify password
        if not bcrypt.check_password_hash(user['password_hash'], password):
            db.increment_failed_attempts(user['id'])
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Get REAL client IP and location from backend
        client_ip = get_client_ip()
        backend_network_info = get_ip_location(client_ip)

# Check for VPN/datacenter
        if backend_network_info.get('is_vpn'):
            edns_boost = 2  # Initialize first
            print(f"⚠️ VPN/Proxy detected via IPHub")
            edns_boost += 2  # Extra penalty for VPN
        elif is_vpn_or_datacenter(backend_network_info['asn']):
            print(f"⚠️ VPN/datacenter ASN detected: {backend_network_info['asn']}")
            edns_boost = 2  # Initialize and set
            edns_boost += 1
        else:
            edns_boost = 0  # Initialize for normal IPs
        
        
        # Merge frontend and backend network info
        frontend_network_info = data.get('network_info', {})
        network_info = {
            'ip_address': backend_network_info['ip_address'],
            'country': backend_network_info['country'],
            'asn': backend_network_info['asn'],
            'user_agent': frontend_network_info.get('user_agent', request.headers.get('User-Agent', ''))
        }
        
        print(f"🌍 Login from: {network_info['country']} | IP: {network_info['ip_address']}")
        
        # EDNS check - Pass BOTH ip_address AND username
        edns_result = edns_layer.check_login_security(network_info['ip_address'], username)
        
        # Debug: See what EDNS returns
        print(f"DEBUG EDNS result: {edns_result}")
        
        # Safe access with multiple possible keys
        threats_detected = (
            edns_result.get('threats_detected', False) or 
            edns_result.get('threat_detected', False) or
            len(edns_result.get('threats', [])) > 0
        )
        
        edns_boost = 2 if threats_detected else 0

        if is_vpn_or_datacenter(backend_network_info['asn']):
            print(f"⚠️ VPN/datacenter ASN detected: {backend_network_info['asn']}")
            edns_boost += 1  # Add extra risk for VPN
        print(f"EDNS boost: {edns_boost}")
        
        # Authentication with REAL network data
        login_data = {
            'keystroke_timings': data.get('keystroke_timings', []),
            'network_info': network_info
        }
        
        auth_result = auth_engine.authenticate_user(user['profile_id'], login_data, edns_boost)
        auth_result['edns_security'] = edns_result
        auth_result['network_info'] = network_info
        
        # Log auth attempt
        status = 'success' if auth_result['success'] else 'blocked'
        db.log_auth_attempt(user['id'], status, auth_result)
        
        # ADAPTIVE MFA BASED ON RISK LEVEL
        risk_level = auth_result.get('final_risk_level', 'Low Risk')
        print(f"🎯 Risk Level: {risk_level}")
        
        if risk_level == 'Low Risk':
            # ============================================
            # LOW RISK: No MFA needed - proceed with login
            # ============================================
            db.reset_failed_attempts(user['id'])
            token = generate_token(user['id'])
            
            update_dashboard_stats('login_success', {
                'username': username,
                'country': network_info['country'],
                'ip_address': network_info['ip_address'],
                'risk_level': risk_level,
                'risk_score': 1
            })
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'username': user['username'],
                    'email': user['email']
                },
                'security_analysis': auth_result
            }), 200
        
        elif risk_level == 'Medium Risk':
            # ============================================
            # MEDIUM RISK: Require Email OTP
            # ============================================
            otp = generate_otp()
            otp_storage[username] = {
                'code': otp,
                'expires': datetime.now() + timedelta(minutes=5),
                'type': 'email',
                'user_id': user['id'],
                'network_info': network_info,
                'auth_result': auth_result
            }
            
            send_email_otp(user['email'], otp, username)
            
            update_dashboard_stats('high_risk', {
                'username': username,
                'country': network_info['country'],
                'ip_address': network_info['ip_address'],
                'risk_level': risk_level,
                'risk_score': 2
            })
            
            return jsonify({
                'success': False,
                'mfa_required': True,
                'mfa_type': 'email',
                'username': username,
                'message': f'Verification code sent to {mask_email(user["email"])}',
                'security_analysis': auth_result
            }), 200
        
        elif risk_level == 'High Risk':
            # ============================================
            # HIGH RISK: Require TOTP (Authenticator App)
            # ============================================
            if not user.get('mfa_enabled'):
                # Force MFA setup for high-risk users
                return jsonify({
                    'success': False,
                    'mfa_required': True,
                    'mfa_setup_required': True,
                    'mfa_type': 'totp',
                    'username': username,
                    'error': 'High risk detected. Authenticator app required for your security.',
                    'security_analysis': auth_result
                }), 403
            
            # User has TOTP enabled - require verification
            update_dashboard_stats('high_risk', {
                'username': username,
                'country': network_info['country'],
                'ip_address': network_info['ip_address'],
                'risk_level': risk_level,
                'risk_score': 2
            })
            
            return jsonify({
                'success': False,
                'mfa_required': True,
                'mfa_type': 'totp',
                'username': username,
                'message': 'Enter code from your authenticator app',
                'security_analysis': auth_result
            }), 200
        
        else:
            # ============================================
            # CRITICAL/EXTREME RISK: Block completely
            # ============================================
            db.increment_failed_attempts(user['id'])
            
            update_dashboard_stats('login_blocked', {
                'username': username,
                'country': network_info['country'],
                'ip_address': network_info['ip_address'],
                'risk_level': risk_level,
                'risk_score': 3
            })
            
            return jsonify({
                'success': False,
                'error': 'Login blocked due to suspicious activity. Please contact support.',
                'security_analysis': auth_result
            }), 403
            
    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

def generate_otp():
    """Generate 6-digit OTP."""
    return str(random.randint(100000, 999999))

def log_alert(user_id, alert_type, message):
    # Store in DB or memory
    db.cursor.execute(
        "INSERT INTO alerts (user_id, type, message) VALUES (%s, %s, %s)",
        (user_id, alert_type, message)
    )
    db.conn.commit()

def send_browser_alert(socketio, user_id, message):
    # Real implementation would use user/session mapping
    socketio.emit('security_alert', {'message': message}, broadcast=True)



def mask_email(email):
    """Mask email for display: abc***@gmail.com"""
    parts = email.split('@')
    if len(parts) == 2:
        name = parts[0]
        masked = name[:3] + '***' if len(name) > 3 else '***'
        return f"{masked}@{parts[1]}"
    return email


def send_email_otp(recipient, otp, username):
    """Send OTP via email."""
    try:
        msg = Message(
            subject='SecureNet - Verification Code',
            recipients=[recipient],
            html=f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px 10px 0 0;">
                    <h2 style="color: white; margin: 0;">🛡️ SecureNet Verification</h2>
                </div>
                <div style="padding: 30px; background: white; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>A login attempt from a new location or device requires verification.</p>
                    <div style="background: #f3f4f6; padding: 25px; border-radius: 10px; text-align: center; margin: 25px 0;">
                        <p style="color: #6b7280; font-size: 0.875rem; margin: 0 0 10px 0;">Your verification code:</p>
                        <h1 style="color: #667eea; font-size: 42px; letter-spacing: 8px; margin: 0; font-weight: 700;">{otp}</h1>
                    </div>
                    <p style="color: #ef4444; font-weight: 600;">⏱️ This code expires in 5 minutes.</p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                    <p style="color: #6b7280; font-size: 0.875rem;">
                        🔒 If you didn't attempt to login, please secure your account immediately by changing your password.
                    </p>
                    <p style="color: #9ca3af; font-size: 0.75rem; margin-top: 20px;">
                        This is an automated message from SecureNet. Please do not reply to this email.
                    </p>
                </div>
            </div>
            '''
        )
        mail.send(msg)
        print(f"✉️ OTP sent to {recipient}: {otp}")
        return True
    except Exception as e:
        print(f"❌ Email send error: {e}")
        return False



@app.route('/api/verify-mfa', methods=['POST'])
@limiter.limit("5 per minute")
def api_verify_mfa():
    """
    Verify MFA code.
    
    Request body:
    {
        "mfa_token": "string",
        "mfa_code": "string"
    }
    """
    try:
        data = request.json
        
        # Verify MFA token
        user_id_str = verify_token(data.get('mfa_token', ''))
        if not user_id_str or not user_id_str.startswith('mfa_'):
            return jsonify({
                'success': False,
                'error': 'Invalid or expired MFA token'
            }), 401
        
        user_id = int(user_id_str.replace('mfa_', ''))
        
        # In production, verify actual MFA code (TOTP, SMS, etc.)
        # For demo, accept any 6-digit code
        mfa_code = data.get('mfa_code', '')
        if len(mfa_code) != 6 or not mfa_code.isdigit():
            return jsonify({
                'success': False,
                'error': 'Invalid MFA code'
            }), 401
        
        # Get user
        user = db.get_user_by_id(user_id)
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Generate session token
        token = generate_token(user['id'])
        
        # Log successful MFA verification
        db.log_auth_attempt(user['id'], 'mfa_success', {'mfa_verified': True})
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"MFA verification error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500
    
# =====================================================================
# MFA ROUTES
# =====================================================================

@app.route('/api/mfa/verify-email-otp', methods=['POST'])
def api_verify_email_otp():
    """Verify email OTP code."""
    try:
        data = request.json
        username = data.get('username')
        code = data.get('code')
        
        # Check if OTP exists
        if username not in otp_storage:
            return jsonify({
                'success': False,
                'error': 'No verification code found. Please login again.'
            }), 400
        
        stored = otp_storage[username]
        
        # Check expiration
        if datetime.now() > stored['expires']:
            del otp_storage[username]
            return jsonify({
                'success': False,
                'error': 'Verification code expired. Please login again.'
            }), 400
        
        # Verify code
        if code == stored['code']:
            # Success - generate token
            user = db.get_user_by_id(stored['user_id'])
            token = generate_token(user['id'])
            
            # Clean up OTP
            del otp_storage[username]
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'username': user['username'],
                    'email': user['email']
                },
                'message': 'Email verification successful!'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid verification code. Please try again.'
            }), 400
        
    except Exception as e:
        print(f"Email OTP verify error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/mfa/setup', methods=['POST'])
def api_mfa_setup():
    """Setup MFA for user - generate secret and QR code."""
    try:
        data = request.json
        username = data.get('username')
        
        user = db.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate secret
        secret = pyotp.random_base32()
        
        # Create TOTP URI for QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name='SecureNet'
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        
        # Store in database (temporarily, until user confirms)
        db.update_user_mfa(user['id'], secret, backup_codes, enabled=False)
        
        return jsonify({
            'success': True,
            'secret': secret,
            'qr_code': f'data:image/png;base64,{img_str}',
            'backup_codes': backup_codes
        }), 200
        
    except Exception as e:
        print(f"MFA setup error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/mfa/verify-setup', methods=['POST'])
def api_mfa_verify_setup():
    """Verify MFA code during setup to enable it."""
    try:
        data = request.json
        username = data.get('username')
        code = data.get('code')
        
        user = db.get_user(username)
        if not user or not user.get('mfa_secret'):
            return jsonify({'error': 'MFA not initialized'}), 400
        
        # Verify code
        totp = pyotp.TOTP(user['mfa_secret'])
        if totp.verify(code, valid_window=1):
            # Enable MFA
            db.enable_user_mfa(user['id'])
            
            return jsonify({
                'success': True,
                'message': 'MFA enabled successfully!'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid code. Please try again.'
            }), 400
        
    except Exception as e:
        print(f"MFA verify setup error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/mfa/verify', methods=['POST'])
def api_mfa_verify():
    """Verify MFA code during login."""
    try:
        data = request.json
        username = data.get('username')
        code = data.get('code')
        
        user = db.get_user(username)
        if not user or not user.get('mfa_enabled'):
            return jsonify({'error': 'MFA not enabled'}), 400
        
        # Check if it's a backup code
        if user.get('backup_codes'):
            try:
                backup_codes = json.loads(user['backup_codes'])
                if code.upper() in backup_codes:
                    # Remove used backup code
                    backup_codes.remove(code.upper())
                    db.update_backup_codes(user['id'], backup_codes)
                    
                    # Generate token
                    token = generate_token(user['id'])
                    
                    return jsonify({
                        'success': True,
                        'token': token,
                        'method': 'backup_code',
                        'message': 'Login successful! Backup code used.',
                        'remaining_codes': len(backup_codes)
                    }), 200
            except:
                pass
        
        # Verify TOTP code
        totp = pyotp.TOTP(user['mfa_secret'])
        if totp.verify(code, valid_window=1):
            # Generate token
            token = generate_token(user['id'])
            
            return jsonify({
                'success': True,
                'token': token,
                'method': 'totp',
                'user': {
                    'username': user['username'],
                    'email': user['email']
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid code. Please try again.'
            }), 400
        
    except Exception as e:
        print(f"MFA verify error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/mfa/disable', methods=['POST'])
def api_mfa_disable():
    """Disable MFA for user."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        user = db.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Verify password
        if not bcrypt.check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid password'}), 401
        
        # Disable MFA
        db.disable_user_mfa(user['id'])
        
        return jsonify({
            'success': True,
            'message': 'MFA disabled successfully'
        }), 200
        
    except Exception as e:
        print(f"MFA disable error: {e}")
        return jsonify({'error': str(e)}), 500


# =====================================================================
# API ROUTES - Dashboard & Monitoring
# =====================================================================

@app.route('/api/user/profile', methods=['GET'])
def api_get_profile():
    """Get user profile information."""
    try:
        # Get token from header
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        user_id = verify_token(token)
        
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Get user data
        user = db.get_user_by_id(user_id)
        profile = auth_engine.get_user_profile(user['profile_id'])
        
        # FIX: Convert last_login safely
        last_login = None
        if profile.last_login:
            if hasattr(profile.last_login, 'isoformat'):
                last_login = profile.last_login.isoformat()
            else:
                last_login = str(profile.last_login)
        
        return jsonify({
            'success': True,
            'user': {
                'username': user['username'],
                'email': user['email'],
                'member_since': str(user['created_at']),
                'mfa_enabled': user.get('mfa_enabled', False)  # ← ADD THIS
            },
            'profile': {
                'successful_logins': profile.successful_logins,
                'last_login': last_login,
                'typical_countries': profile.network_baseline.get('typical_countries', ['US']),
                'typical_devices': len(profile.network_baseline.get('typical_devices', []))
            }
        }), 200
        
    except Exception as e:
        print(f"Profile error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500


    
@app.route('/api/user/auth-history', methods=['GET'])
def api_auth_history():
    """Get user authentication history."""
    try:
        # Temporarily skip auth for testing
        return jsonify({
            'success': True,
            'history': [
                {
                    'timestamp': '2025-11-23 01:03:41',
                    'status': 'success',
                    'risk_level': 'Low Risk',
                    'country': 'US',
                    'ip_address': '127.0.0.1',
                    'keystroke_deviation': '0.0%'
                }
            ]
        }), 200
        
    except Exception as e:
        print(f"History error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/stats', methods=['GET'])
def api_admin_stats():
    """Get system-wide statistics (admin only)."""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        user_id = verify_token(token)
        
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401
        
        # In production, check if user is admin
        
        stats = {
            'total_users': db.get_total_users(),
            'total_logins_today': db.get_logins_today(),
            'blocked_attempts_today': db.get_blocked_today(),
            'mfa_required_today': db.get_mfa_today(),
            'edns_optimizations': edns_layer.get_optimization_stats(),
            'top_risk_countries': db.get_top_risk_countries(),
            'recent_threats': db.get_recent_threats(limit=10)
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin stats error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# =====================================================================
# API ROUTES - EDNS Information
# =====================================================================

@app.route('/api/edns/status', methods=['GET'])
def api_edns_status():
    """Get EDNS optimization status."""
    try:
        status = edns_layer.get_status()
        
        return jsonify({
            'success': True,
            'edns': {
                'enabled': status['enabled'],
                'optimizations_active': status['optimizations'],
                'average_latency_ms': status['avg_latency'],
                'threats_blocked_today': status['threats_blocked_today'],
                'dns_cache_hit_rate': status['cache_hit_rate']
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"EDNS status error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# =====================================================================
# Error Handlers
# =====================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# =====================================================================
# REAL-TIME SECURITY DASHBOARD APIS
# =====================================================================

# In-memory stats (for demo - use Redis in production)
dashboard_stats = {
    'total_logins_today': 0,
    'blocked_today': 0,
    'high_risk_today': 0,
    'active_sessions': 0,
    'recent_activities': [],
    'login_locations': [],
    'risk_timeline': []
}

@app.route('/api/dashboard/stats', methods=['GET'])
def api_dashboard_stats():
    """Get real-time dashboard statistics."""
    try:
        stats = {
            'total_users': 1,  # Simplified for demo
            'logins_today': dashboard_stats['total_logins_today'],
            'blocked_today': dashboard_stats['blocked_today'],
            'high_risk_today': dashboard_stats['high_risk_today'],
            'active_sessions': dashboard_stats['active_sessions'],
            'avg_risk_score': 2.3,
            'edns_threats_blocked': 0,  # Simplified
            'system_health': 98.5
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        print(f"Dashboard stats error: {e}")
        return jsonify({'error': str(e)}), 500



@app.route('/api/dashboard/recent-activity', methods=['GET'])
def api_recent_activity():
    """Get recent login activities."""
    try:
        # Get last 20 activities
        activities = dashboard_stats['recent_activities'][-20:]
        
        return jsonify({
            'success': True,
            'activities': activities
        }), 200
        
    except Exception as e:
        print(f"Recent activity error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/threat-map', methods=['GET'])
def api_threat_map():
    """Get login locations for map visualization."""
    try:
        locations = dashboard_stats['login_locations'][-50:]  # Last 50
        
        return jsonify({
            'success': True,
            'locations': locations
        }), 200
        
    except Exception as e:
        print(f"Threat map error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/risk-timeline', methods=['GET'])
def api_risk_timeline():
    """Get risk score timeline."""
    try:
        timeline = dashboard_stats['risk_timeline'][-100:]  # Last 100 events
        
        return jsonify({
            'success': True,
            'timeline': timeline
        }), 200
        
    except Exception as e:
        print(f"Risk timeline error: {e}")
        return jsonify({'error': str(e)}), 500


# WebSocket for real-time updates
@socketio.on('connect')
def handle_connect():
    print('Dashboard connected')
    emit('connected', {'data': 'Connected to SecureNet'})


@socketio.on('disconnect')
def handle_disconnect():
    print('Dashboard disconnected')


def update_dashboard_stats(activity_type, data):
    """Update dashboard stats and broadcast to connected clients."""
    
    # Update counters
    if activity_type == 'login_success':
        dashboard_stats['total_logins_today'] += 1
    elif activity_type == 'login_blocked':
        dashboard_stats['blocked_today'] += 1
    elif activity_type == 'high_risk':
        dashboard_stats['high_risk_today'] += 1
    
    # Add to recent activities
    activity = {
        'timestamp': datetime.now().isoformat(),
        'type': activity_type,
        **data
    }
    dashboard_stats['recent_activities'].append(activity)
    
    # Keep only last 100
    if len(dashboard_stats['recent_activities']) > 100:
        dashboard_stats['recent_activities'] = dashboard_stats['recent_activities'][-100:]
    
    # Add to login locations
    if 'country' in data and 'ip_address' in data:
        location = {
            'country': data['country'],
            'ip': data['ip_address'],
            'risk_level': data.get('risk_level', 'Low'),
            'timestamp': datetime.now().isoformat()
        }
        dashboard_stats['login_locations'].append(location)
    
    # Add to risk timeline
    if 'risk_score' in data:
        dashboard_stats['risk_timeline'].append({
            'timestamp': datetime.now().isoformat(),
            'score': data['risk_score']
        })
    
    # Broadcast to all connected dashboards
    socketio.emit('stats_update', {
        'activity': activity,
        'stats': {
            'logins_today': dashboard_stats['total_logins_today'],
            'blocked_today': dashboard_stats['blocked_today'],
            'high_risk_today': dashboard_stats['high_risk_today']
        }
    })

@app.route('/api/test-dashboard-update', methods=['GET'])
def test_dashboard_update():
    """Test dashboard update - REMOVE IN PRODUCTION."""
    print("🧪 Generating test data...")
    
    # Simulate 3 successful logins
    for i in range(3):
        update_dashboard_stats('login_success', {
            'username': f'test_user_{i}',
            'country': 'US',
            'ip_address': f'192.168.1.{i}',
            'risk_level': 'Low Risk',
            'risk_score': 1
        })
    
    # Simulate 1 blocked attempt
    update_dashboard_stats('login_blocked', {
        'username': 'hacker',
        'country': 'CN',
        'ip_address': '1.2.3.4',
        'risk_level': 'High Risk',
        'risk_score': 3
    })
    
    print(f"✅ Test data sent! Stats: {dashboard_stats}")
    
    return jsonify({
        'success': True,
        'message': 'Dashboard updated with test data!',
        'current_stats': {
            'logins': dashboard_stats['total_logins_today'],
            'blocked': dashboard_stats['blocked_today'],
            'activities': len(dashboard_stats['recent_activities'])
        }
    })



if __name__ == '__main__':
    print("="*80)
    print("SecureNet Authentication System with EDNS")
    print("="*80)
    print("\n✓ ML Model loaded")
    print("✓ EDNS Security Layer active")
    print("✓ Behavioral Profiling enabled")
    print("\nServer starting on http://localhost:5001")
    print("="*80 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=PORT, debug=True)
