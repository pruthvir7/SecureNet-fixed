#!/usr/bin/env python3
"""
SecureNet Backend API with EDNS Integration
Complete authentication system with ML, behavioral biometrics, and DNS security
"""

import gevent.monkey
gevent.monkey.patch_all()

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
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import random
from backend.admin_routes import admin_bp
import resend
# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.edns_integration import EDNSSecurityLayer
from backend.models import DatabaseManager

# Initialize Flask app
app = Flask(__name__, 
            static_folder='../frontend',
            static_url_path='')

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
bcrypt = Bcrypt(app) 
# Email configuration
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'securenet220@gmail.com'  # Change this
# app.config['MAIL_PASSWORD'] = 'rjfc exxd efle lacj'     # Change this
# app.config['MAIL_DEFAULT_SENDER'] = 'SecureNet <noreply@securenet.com>'

# mail = Mail(app)

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

# Initialize database first
db = DatabaseManager(
    host='securenet-securenet1.c.aivencloud.com',
    user='avnadmin',
    password='AVNS_DzruYfuj_BgF2aD1K9c',
    database='defaultdb',
    port=10675
)

def migrate_database():
    """Run database migrations."""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if 'details' column exists
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM information_schema.COLUMNS 
                WHERE TABLE_SCHEMA = %s
                AND TABLE_NAME = 'auth_logs' 
                AND COLUMN_NAME = 'details'
            """, (db.config['database'],))
            
            result = cursor.fetchone()
            
            if result['count'] == 0:
                print("🔧 Running migration: Adding 'details' column...")
                cursor.execute("""
                    ALTER TABLE auth_logs 
                    ADD COLUMN details JSON NULL
                """)
                print("✅ Migration complete!")
                
    except Exception as e:
        print(f"⚠️ Migration warning: {e}")

migrate_database()

# Initialize auth engine with database
auth_engine = AuthenticationEngine(model_dir='models/securenet_model_all5_20251118_190557', db_manager=db)
edns_layer = EDNSSecurityLayer()

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
    """Get location and VPN detection from IPHub only"""
    import requests
    
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
    
    # Use IPHub for both geolocation AND VPN detection
    try:
        print(f"🔍 Calling IPHub for {ip_address}")
        
        iphub_response = requests.get(
            f'https://v2.api.iphub.info/ip/{ip_address}',
            headers={'X-Key': 'MzAzNzE6cDUzQ1pBM2RoRHZXbmdob2JCWmRYNUhoY0IzNXNLcVo='},
            timeout=5
        )
        
        if iphub_response.ok:
            data = iphub_response.json()
            
            # Get country code
            result['country'] = data.get('countryCode', 'Unknown')
            
            # Get ASN
            result['asn'] = str(data.get('asn', '0'))
            
            # Check VPN/Datacenter
            block_value = data.get('block', 0)
            if block_value in [1, 2]:
                result['is_vpn'] = True
                vpn_type = 'VPN/Proxy' if block_value == 1 else 'Datacenter'
                print(f"🚨 {vpn_type} detected for {ip_address}")
            else:
                print(f"✓ Residential IP: {ip_address}")
            
            print(f"🌍 {ip_address}: {result['country']}, ASN: {result['asn']}, VPN: {result['is_vpn']}")
        else:
            print(f"❌ IPHub returned status {iphub_response.status_code}")
                
    except Exception as e:
        print(f"❌ IPHub error: {type(e).__name__}: {str(e)}")
    
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
        
        # Hash password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        print(f"✓ Generated hash for '{username}': {password_hash[:20]}...")
        print(f"  Hash length: {len(password_hash)}")
        
        # Get client IP and location
        client_ip = get_client_ip()
        backend_network_info = get_ip_location(client_ip)
        
        # Merge frontend and backend network info
        frontend_network_info = data.get('network_info', {})
        network_info = {
            'ip_address': backend_network_info['ip_address'],
            'country': backend_network_info['country'],
            'asn': backend_network_info['asn'],
            'user_agent': frontend_network_info.get('user_agent', ''),
            'device_fingerprint': frontend_network_info.get('device_fingerprint')
        }
        
        # Safe device fingerprint display
        device_fp = network_info.get('device_fingerprint') or 'None'
        device_display = device_fp[:20] if device_fp != 'None' else 'None'
        print(f"📍 Registration from: {network_info['country']} | Device: {device_display}...")
        
        # Create behavioral profile
        profile_id = username
        profile = UserBehavioralProfile(profile_id)
        
        # Capture registration baseline with network info
        registration_data = {
            'keystroke_timings': data.get('keystroke_timings', []),
            'network_info': network_info
        }
        profile.capture_registration_baseline(registration_data)
        
        # Save profile
        auth_engine._save_profile(profile)
        
        # Create user in database
        user_id = db.create_user(username, email, password_hash, profile_id)
        
        print(f"✓ User created with ID: {user_id}")
        
        # Log the registration as the first "auth attempt" to store device/location
        registration_result = {
            'success': True,
            'final_risk_level': 'Low Risk',
            'ml_prediction': 'Registration',
            'keystroke_deviation': 'N/A (Registration)',
            'flags': [],
            'network_info': network_info,
            'edns_security': {}
        }
        
        db.log_auth_attempt(user_id, 'success', registration_result)
        
        print(f"✓ Registration baseline saved: {network_info['country']}, device: {device_display}")
        
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
            
            # === ALERT: Check if account should be locked ===
            failed_attempts = user.get('failed_attempts', 0) + 1
            if failed_attempts >= 5:
                db.lock_user_account(user['id'])
                
                # 🔔 Send account locked alert
                send_security_alert_email(
                    recipient=user['email'],
                    username=username,
                    alert_type='account_locked',
                    details={
                        'failed_attempts': failed_attempts,
                        'ip_address': get_client_ip(),
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                )
            
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Get REAL client IP and location from backend
        client_ip = get_client_ip()
        backend_network_info = get_ip_location(client_ip)
        
        # Merge frontend and backend network info
        frontend_network_info = data.get('network_info', {})
        network_info = {
            'ip_address': backend_network_info['ip_address'],
            'country': backend_network_info['country'],
            'asn': backend_network_info['asn'],
            'user_agent': frontend_network_info.get('user_agent', request.headers.get('User-Agent', '')),
            'device_fingerprint': frontend_network_info.get('device_fingerprint')
        }
        
        print(f"🌍 Login from: {network_info['country']} | IP: {network_info['ip_address']}")
        
        # Initialize edns_boost
        edns_boost = 0
        
        # EDNS threat check
        edns_result = edns_layer.check_login_security(network_info['ip_address'], username)
        print(f"🔍 EDNS Result Details: {json.dumps(edns_result, indent=2)}")
        threats_detected = (
            edns_result.get('threats_detected', False) or 
            edns_result.get('threat_detected', False) or
            len(edns_result.get('threats', [])) > 0
        )
        
        if threats_detected:
            threat_level = edns_result.get('threat_level', 1)
            edns_boost += threat_level
            print(f"⚠️ EDNS threat detected (level {threat_level})")
        
        # VPN detection from IPHub
        if backend_network_info.get('is_vpn'):
            edns_boost += 2
            print(f"🚨 VPN/Proxy detected via IPHub")
            
            # 🔔 Send VPN detected alert
            send_security_alert_email(
                recipient=user['email'],
                username=username,
                alert_type='vpn_detected',
                details={
                    'country': network_info['country'],
                    'ip_address': client_ip,
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            )
        
        print(f"Final EDNS boost: {edns_boost}")
        
        # Authentication with REAL network data
        login_data = {
            'keystroke_timings': data.get('keystroke_timings', []),
            'network_info': network_info
        }
        
        auth_result = auth_engine.authenticate_user(user['profile_id'], login_data, edns_boost)
        auth_result['edns_security'] = edns_result
        auth_result['network_info'] = network_info
        
        # Get initial ML risk level
        ml_risk_level = auth_result.get('final_risk_level', 'Low Risk')
        print(f"🎯 ML Risk Level: {ml_risk_level}")
        
        # === CHECK IF THIS IS FIRST LOGIN ===
        profile = auth_engine.get_user_profile(user['profile_id'])
        print(f"🔍 DEBUG: Profile successful_logins = {profile.successful_logins}")
        is_first_login = profile.successful_logins == 0
        print(f"🔍 DEBUG: is_first_login = {is_first_login}")
        
        if is_first_login:
            print("✅ FIRST LOGIN - Auto-approving to establish baseline (no alerts)")
            
            # Auto-approve first login
            db.reset_failed_attempts(user['id'])
            token = generate_token(user['id'])
            
            # Log as success
            status = 'success'
            db.log_auth_attempt(user['id'], status, auth_result)
            
            update_dashboard_stats('login_success', {
                'username': username,
                'country': network_info['country'],
                'ip_address': network_info['ip_address'],
                'risk_level': 'Low Risk (First Login)',
                'risk_score': 1
            })
            
            print("✅ FIRST LOGIN - Returning success response")
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'username': user['username'],
                    'email': user['email']
                },
                'security_analysis': auth_result,
                'first_login': True
            }), 200
        
        # === ONLY RUNS FOR NON-FIRST LOGINS ===
        print("🔍 Not first login - checking device/location")
        
        device_boost = 0
        location_boost = 0
        risk_boost_reasons = []
        
        # Check for new location
        user_countries = db.get_user_login_countries(user['id'])
        is_new_location = network_info['country'] not in user_countries
        
        if is_new_location:
            location_boost = 1
            risk_boost_reasons.append('New location detected')
            print(f"⚠️ New location detected: {network_info['country']}")
            
            # 🔔 Send new location alert
            send_security_alert_email(
                recipient=user['email'],
                username=username,
                alert_type='new_location',
                details={
                    'country': network_info['country'],
                    'ip_address': client_ip,
                    'city': backend_network_info.get('city', 'Unknown'),
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            )
        user_ips = db.get_user_ips(user['id'])
        current_ip = network_info['ip_address']
        is_new_ip = current_ip not in user_ips

        if is_new_ip:
            device_boost = 1  # Boost risk by 1 level
            risk_boost_reasons.append('New IP address detected')
            print(f"⚠️ New IP detected: {current_ip}")
    
            # 🔔 Send new IP alert
            send_security_alert_email(
                recipient=user['email'],
                username=username,
                alert_type='new_ip',
                details={
                    'ip_address': current_ip,
                    'location': network_info['country'],
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            )
        
        # === ADJUST RISK LEVEL BASED ON NEW DEVICE/LOCATION ===
        total_new_factor_boost = device_boost + location_boost
        
        if total_new_factor_boost > 0:
            risk_levels = {
                'Low Risk': 0,
                'Medium Risk': 1,
                'High Risk': 2,
                'Critical Risk': 3
            }
            
            risk_names = ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk']
            
            current_risk_num = risk_levels.get(ml_risk_level, 0)
            boosted_risk_num = min(current_risk_num + total_new_factor_boost, 3)
            final_risk_level = risk_names[boosted_risk_num]
            
            print(f"📈 Risk boosted: {ml_risk_level} → {final_risk_level} (new device: {device_boost}, new location: {location_boost})")
            
            auth_result['final_risk_level'] = final_risk_level
            auth_result['risk_boost_reasons'] = risk_boost_reasons
            auth_result['original_ml_risk'] = ml_risk_level
        else:
            final_risk_level = ml_risk_level
        
        risk_level = final_risk_level
        print(f"🎯 Final Risk Level: {risk_level}")
        
        # === ALERT: Check for high-risk/suspicious login ===
        if risk_level in ['High Risk', 'Critical Risk']:
            send_security_alert_email(
                recipient=user['email'],
                username=username,
                alert_type='suspicious_login',
                details={
                    'risk_level': risk_level,
                    'reason': ', '.join(risk_boost_reasons) if risk_boost_reasons else auth_result.get('ml_prediction', 'Behavioral anomaly detected'),
                    'location': network_info['country'],
                    'ip_address': client_ip,
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            )
        
        # Log auth attempt with final risk level
        # Treat only full ALLOW as success; MFA as its own status
        if auth_result['action'] == 'ALLOW':
            status = 'success'
        elif auth_result['action'] in ['MFA', 'TOTP']:
            status = 'mfa_required'
        else:
            status = 'blocked'
        db.log_auth_attempt(user['id'], status, auth_result)

        
        # ADAPTIVE MFA BASED ON FINAL RISK LEVEL
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
                return jsonify({
                    'success': False,
                    'mfa_required': True,
                    'mfa_setup_required': True,
                    'mfa_type': 'totp',
                    'username': username,
                    'error': 'High risk detected. Authenticator app required for your security.',
                    'security_analysis': auth_result
                }), 403
            
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


resend.api_key = "re_j4es8ihu_744rriWaTJTsTXanSt1xyifi"

def send_email_otp(recipient, otp, username):
    """Send OTP via Resend."""
    try:
        params = {
            "from": "SecureNet <onboarding@resend.dev>",  # Use resend.dev for testing
            "to": [recipient],
            "subject": "SecureNet - Verification Code",
            "html": f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px 10px 0 0;">
                    <h2 style="color: white; margin: 0;">🛡️ SecureNet Verification</h2>
                </div>
                <div style="padding: 30px; background: white; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>A login attempt from a new location or device requires verification.</p>
                    <div style="background: #f3f4f6; padding: 25px; border-radius: 10px; text-align: center; margin: 25px 0;">
                        <p style="color: #6b7280; font-size: 0.875rem; margin: 0 0 10px 0;">Your verification code:</p>
                        <h1 style="color: #667eea; font-size: 35px; letter-spacing: 8px; margin: 0; font-weight: 700;">{otp}</h1>
                    </div>
                    <p style="color: #ef4444; font-weight: 600;">⏱️ This code expires in 5 minutes.</p>
                    <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                    <p style="color: #6b7280; font-size: 0.875rem;">
                        🔒 If you didn't attempt to login, please secure your account immediately.
                    </p>
                </div>
                </div>
            '''
        }
        
        email = resend.Emails.send(params)
        print(f"✉️ OTP sent to {recipient}: {otp} (Resend ID: {email['id']})")
        return True
    except Exception as e:
        print(f"❌ Email send error: {e}")
        return False

def send_security_alert_email(recipient, username, alert_type, details):
    """
    Send security alert email using Resend.
    
    Alert types:
    - new_device: Login from new device
    - new_location: Login from new country/location
    - suspicious_login: High-risk login attempt
    - account_locked: Account locked due to failed attempts
    - password_changed: Password was changed
    - mfa_enabled: MFA was enabled/disabled
    - bot_detected: Bot attack blocked
    - vpn_detected: VPN/Proxy login
    """
    
    # Alert-specific content
    alert_configs = {
        'new_ip': {
        'emoji': '🌐',
        'title': 'New IP Address Detected',
        'color': 'f59e0b',
        'message': f"A login was detected from a new IP address: {details.get('ip_address', 'Unknown')} ({details.get('location', 'Unknown location')}).",
        'action': "If this was you, no action needed. Otherwise, secure your account immediately."
        },
        'new_location': {
            'emoji': '🌍',
            'title': 'New Location Login',
            'color': '#f59e0b',
            'message': f'A login was detected from {details.get("country", "an unknown location")} ({details.get("ip_address", "unknown IP")}).',
            'action': 'If this was you, no action needed. Otherwise, change your password immediately.'
        },
        'suspicious_login': {
            'emoji': '⚠️',
            'title': 'Suspicious Login Attempt',
            'color': '#ef4444',
            'message': 'A suspicious login attempt was detected and blocked.',
            'action': 'We recommend changing your password and enabling MFA if you haven\'t already.'
        },
        'account_locked': {
            'emoji': '🔒',
            'title': 'Account Locked',
            'color': '#ef4444',
            'message': f'Your account has been locked after {details.get("failed_attempts", 5)} failed login attempts.',
            'action': 'Please contact support to unlock your account or wait 30 minutes.'
        },
        'password_changed': {
            'emoji': '🔑',
            'title': 'Password Changed',
            'color': '#10b981',
            'message': 'Your password was successfully changed.',
            'action': 'If you didn\'t make this change, contact support immediately.'
        },
        'mfa_enabled': {
            'emoji': '🛡️',
            'title': 'MFA Status Changed',
            'color': '#3b82f6',
            'message': f'Multi-factor authentication was {"enabled" if details.get("enabled") else "disabled"} on your account.',
            'action': 'If you didn\'t make this change, contact support immediately.'
        },
        'bot_detected': {
            'emoji': '🤖',
            'title': 'Bot Attack Blocked',
            'color': '#ef4444',
            'message': 'A bot attack targeting your account was detected and blocked.',
            'action': 'Your account is safe. Consider enabling MFA for extra security.'
        },
        'vpn_detected': {
            'emoji': '🔐',
            'title': 'VPN/Proxy Login',
            'color': '#f59e0b',
            'message': f'A login via VPN or proxy was detected from {details.get("country", "unknown location")}.',
            'action': 'We sent a verification code to confirm it\'s you.'
        }
    }
    
    config = alert_configs.get(alert_type, {
        'emoji': '⚠️',
        'title': 'Security Alert',
        'color': '#6b7280',
        'message': 'A security event occurred on your account.',
        'action': 'Please review your recent account activity.'
    })
    
    # Build details table
    details_html = ''
    if details:
        details_html = '<div style="background: #f9fafb; padding: 15px; border-radius: 8px; margin: 20px 0;">'
        details_html += '<h3 style="margin: 0 0 10px 0; font-size: 14px; color: #6b7280;">Event Details:</h3>'
        
        for key, value in details.items():
            if key not in ['enabled']:
                label = key.replace('_', ' ').title()
                details_html += f'<p style="margin: 5px 0; font-size: 13px;"><strong>{label}:</strong> {value}</p>'
        
        details_html += '</div>'
    
    try:
        params = {
            "from": "SecureNet <onboarding@resend.dev>",
            "to": [recipient],
            "subject": f"SecureNet - {config['title']}",
            "html": f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px 10px 0 0;">
                        <h2 style="color: white; margin: 0;">🛡️ SecureNet Security Alert</h2>
                    </div>
                    
                    <div style="padding: 30px; background: white; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                        <div style="background: {config["color"]}; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: center;">
                            <h1 style="margin: 0; font-size: 48px;">{config["emoji"]}</h1>
                            <h2 style="margin: 10px 0 0 0; font-size: 20px;">{config["title"]}</h2>
                        </div>
                        
                        <p>Hello <strong>{username}</strong>,</p>
                        
                        <p style="font-size: 15px; line-height: 1.6;">{config["message"]}</p>
                        
                        {details_html}
                        
                        <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;">
                            <p style="margin: 0; color: #92400e; font-weight: 600;">
                                <strong>What should I do?</strong>
                            </p>
                            <p style="margin: 10px 0 0 0; color: #92400e;">
                                {config["action"]}
                            </p>
                        </div>
                        
                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                        
                        <p style="color: #6b7280; font-size: 13px;">
                            <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                            <strong>Account:</strong> {username}
                        </p>
                        
                        <p style="color: #6b7280; font-size: 12px; margin-top: 20px;">
                            This is an automated security alert from SecureNet. If you have questions, please contact support.
                        </p>
                    </div>
                </div>
            '''
        }
        
        email = resend.Emails.send(params)
        print(f"🔔 Security alert sent to {recipient}: {alert_type} (Resend ID: {email['id']})")
        return True
        
    except Exception as e:
        print(f"❌ Alert email error: {e}")
        return False

@app.route('/api/user/change-password', methods=['POST'])
def api_change_password():
    """Change user password."""
    try:
        data = request.json
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        
        # Verify token
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Get user
        user = db.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Verify old password
        if not bcrypt.check_password_hash(user['password_hash'], old_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password
        if len(new_password) < 6:
            return jsonify({'error': 'New password must be at least 6 characters'}), 400
        
        if old_password == new_password:
            return jsonify({'error': 'New password must be different from current password'}), 400
        
        # Hash new password
        new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # Update password in database
        db.update_user_password(user_id, new_password_hash)
        
        # 🔔 Send password changed alert
        send_security_alert_email(
            recipient=user['email'],
            username=user['username'],
            alert_type='password_changed',
            details={
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': get_client_ip(),
                'device': request.headers.get('User-Agent', 'Unknown')[:80]
            }
        )
        
        print(f"✓ Password changed for user {user['username']}")
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully!'
        }), 200
        
    except Exception as e:
        print(f"Password change error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/change-password')
def change_password_page():
    """Serve password change page."""
    return send_from_directory('../frontend', 'change-password.html')


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
            
            # 🔔 Send MFA enabled alert
            send_security_alert_email(
                recipient=user['email'],
                username=username,
                alert_type='mfa_enabled',
                details={
                    'enabled': True,
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'ip_address': get_client_ip()
                }
            )
            
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
        
        # 🔔 Send MFA disabled alert
        send_security_alert_email(
            recipient=user['email'],
            username=username,
            alert_type='mfa_enabled',
            details={
                'enabled': False,
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': get_client_ip()
            }
        )
        
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
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401

        user = db.get_user_by_id(user_id)
        profile = auth_engine.get_user_profile(user['profile_id'])

        # Use DB last_login, which you update in reset_failed_attempts
        last_login = None
        if user.get('last_login'):
            # user['last_login'] is a datetime from MySQL
            last_login = user['last_login'].isoformat() + 'Z'

        return jsonify({
            'success': True,
            'user': {
                'username': user['username'],
                'email': user['email'],
                'member_since': str(user['created_at']),
                'mfa_enabled': user.get('mfa_enabled', False)
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
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401

        history = db.get_user_auth_history(user_id, limit=10)

        return jsonify({
            'success': True,
            'history': history
        }), 200

    except Exception as e:
        print(f"History error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500



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
    
    socketio.run(app, host='0.0.0.0', port=PORT, debug=False)
