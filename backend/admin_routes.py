"""
SecureNet Admin Control Panel API
Provides admin endpoints for monitoring and management (MySQL version)
"""

from flask import Blueprint, jsonify, request, current_app
from functools import wraps
import json
import os
from datetime import datetime, timedelta

admin_bp = Blueprint('admin', __name__)

# Simple admin authentication (use proper auth in production)
ADMIN_TOKEN = "admin_secret_token_2024"

# Admin credentials (for login demo, not production)
ADMIN_USERS = {
    'admin': {
        'password': 'admin123',
        'email': 'admin@securenet.com'
    }
}

@admin_bp.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin authentication endpoint."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        admin_token = data.get('admin_token')
        if admin_token != ADMIN_TOKEN:
            return jsonify({'error': 'Invalid admin token'}), 401
        if username not in ADMIN_USERS or ADMIN_USERS[username]['password'] != password:
            return jsonify({'error': 'Invalid admin credentials'}), 401
        return jsonify({
            'success': True,
            'admin_token': ADMIN_TOKEN,
            'admin': {
                'username': username,
                'email': ADMIN_USERS[username]['email']
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-Admin-Token')
        if token != ADMIN_TOKEN:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# DASHBOARD STATISTICS
# ============================================================================

@admin_bp.route('/api/admin/stats/overview', methods=['GET'])
@require_admin
def get_overview_stats():
    """Get overview dashboard statistics; all MySQL."""
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor(dictionary=True)

        # Total users
        cursor.execute('SELECT COUNT(*) as count FROM users')
        total_users = cursor.fetchone()['count']

        # Active users (past 7 days)
        seven_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('SELECT COUNT(DISTINCT user_id) as count FROM auth_logs WHERE timestamp > %s', (seven_days_ago,))
        active_users = cursor.fetchone()['count']

        # Logins in last 24h
        yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('SELECT COUNT(*) as count FROM auth_logs WHERE timestamp > %s', (yesterday,))
        recent_logins = cursor.fetchone()['count']

        # Failed attempts (last 24h)
        cursor.execute('SELECT COUNT(*) as count FROM auth_logs WHERE timestamp > %s AND status = %s', (yesterday, "failed"))
        failed_logins = cursor.fetchone()['count']

        # MFA enabled users
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE mfa_enabled = 1')
        mfa_users = cursor.fetchone()['count']

        # Blocked logins (last 24h)
        cursor.execute('SELECT COUNT(*) as count FROM auth_logs WHERE timestamp > %s AND status = %s', (yesterday, "blocked"))
        blocked_logins = cursor.fetchone()['count']

        cursor.close()
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'recent_logins': recent_logins,
            'failed_logins': failed_logins,
            'mfa_enabled_users': mfa_users,
            'blocked_logins': blocked_logins,
            'mfa_adoption_rate': round((mfa_users / total_users * 100) if total_users > 0 else 0, 1),
            'success_rate': round(((recent_logins - failed_logins) / recent_logins * 100) if recent_logins > 0 else 100, 1)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/stats/timeline', methods=['GET'])
@require_admin
def get_timeline_stats():
    """Get login timeline for charts."""
    try:
        db = current_app.config['DB']
        days = int(request.args.get('days', 7))
        cursor = db.conn.cursor(dictionary=True)

        start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as total,
                SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked
            FROM auth_logs
            WHERE timestamp > %s
            GROUP BY DATE(timestamp)
            ORDER BY date
        ''', (start_date,))
        results = cursor.fetchall()
        cursor.close()
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/stats/risk-distribution', methods=['GET'])
@require_admin
def get_risk_distribution():
    """Get risk level distribution."""
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor(dictionary=True)
        yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            SELECT 
                JSON_UNQUOTE(JSON_EXTRACT(analysis, '$.final_risk_level')) as risk_level,
                COUNT(*) as count
            FROM auth_logs
            WHERE timestamp > %s AND analysis IS NOT NULL
            GROUP BY risk_level
        ''', (yesterday,))
        results = cursor.fetchall()
        cursor.close()
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/stats/geographic', methods=['GET'])
@require_admin
def get_geographic_stats():
    """Get login attempts by country."""
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor(dictionary=True)
        yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            SELECT 
                JSON_UNQUOTE(JSON_EXTRACT(analysis, '$.network_info.country')) as country,
                COUNT(*) as count,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked
            FROM auth_logs
            WHERE timestamp > %s AND analysis IS NOT NULL
            GROUP BY country
            ORDER BY count DESC
            LIMIT 10
        ''', (yesterday,))
        results = cursor.fetchall()
        cursor.close()
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# USER MANAGEMENT
# ============================================================================

@admin_bp.route('/api/admin/users', methods=['GET'])
@require_admin
def list_users():
    """List all users with pagination."""
    try:
        db = current_app.config['DB']
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        search = request.args.get('search', '')
        offset = (page - 1) * per_page
        cursor = db.conn.cursor(dictionary=True)

        if search:
            cursor.execute('''
                SELECT id, username, email, mfa_enabled, is_locked, failed_attempts, created_at
                FROM users
                WHERE username LIKE %s OR email LIKE %s
                LIMIT %s OFFSET %s
            ''', (f'%{search}%', f'%{search}%', per_page, offset))
        else:
            cursor.execute('''
                SELECT id, username, email, mfa_enabled, is_locked, failed_attempts, created_at
                FROM users
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            ''', (per_page, offset))
        users = cursor.fetchall()

        cursor.execute('SELECT COUNT(*) as count FROM users')
        total = cursor.fetchone()['count']
        cursor.close()

        return jsonify({
            'users': users,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/users/<int:user_id>', methods=['GET'])
@require_admin
def get_user_details(user_id):
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor(dictionary=True)
        # User info
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if 'password_hash' in user:
            del user['password_hash']

        cursor.execute('''
            SELECT timestamp, status, ip_address, 
                   JSON_UNQUOTE(JSON_EXTRACT(analysis, '$.final_risk_level')) as risk_level,
                   JSON_UNQUOTE(JSON_EXTRACT(analysis, '$.network_info.country')) as country
            FROM auth_logs
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (user_id,))
        recent_logins = cursor.fetchall()

        # Load behavioral profile
        profile_path = f'user_profiles/{user["profile_id"]}.json'
        profile = None
        if os.path.exists(profile_path):
            with open(profile_path, 'r') as f:
                profile = json.load(f)

        cursor.close()
        return jsonify({
            'user': user,
            'recent_logins': recent_logins,
            'profile': profile
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/users/<int:user_id>/unlock', methods=['POST'])
@require_admin
def unlock_user(user_id):
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor()
        cursor.execute('UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE id = %s', (user_id,))
        db.conn.commit()
        cursor.close()
        return jsonify({'message': 'User unlocked successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/users/<int:user_id>/reset-mfa', methods=['POST'])
@require_admin
def reset_user_mfa(user_id):
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor()
        cursor.execute('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = %s', (user_id,))
        db.conn.commit()
        cursor.close()
        return jsonify({'message': 'MFA reset successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# AUTHENTICATION LOGS
# ============================================================================

@admin_bp.route('/api/admin/logs', methods=['GET'])
@require_admin
def get_auth_logs():
    try:
        db = current_app.config['DB']
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        status = request.args.get('status', '')
        user_id = request.args.get('user_id', '')
        offset = (page - 1) * per_page
        cursor = db.conn.cursor(dictionary=True)
        query = '''
            SELECT l.*, u.username
            FROM auth_logs l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE 1=1
        '''
        params = []

        if status:
            query += ' AND l.status = %s'
            params.append(status)
        if user_id:
            query += ' AND l.user_id = %s'
            params.append(user_id)
        query += ' ORDER BY l.timestamp DESC LIMIT %s OFFSET %s'
        params.extend([per_page, offset])
        cursor.execute(query, params)
        logs = cursor.fetchall()
        # Parse JSON fields
        for log in logs:
            if log.get('analysis'):
                try:
                    log['analysis'] = json.loads(log['analysis'])
                except:
                    log['analysis'] = None
        cursor.close()
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# SYSTEM CONFIGURATION
# ============================================================================

@admin_bp.route('/api/admin/config/thresholds', methods=['GET'])
@require_admin
def get_thresholds():
    return jsonify({
        'keystroke_deviation': {'minor': 0.15, 'moderate': 0.30, 'high': 0.50},
        'boost_levels': {'mfa_trigger': 1.0, 'block_trigger': 3.0},
        'network': {'new_device': 1.5, 'new_country': 1.0, 'high_risk_country': 2.0}
    }), 200

@admin_bp.route('/api/admin/config/thresholds', methods=['PUT'])
@require_admin
def update_thresholds():
    return jsonify({'message': 'Thresholds updated (not implemented in demo)'}), 200

# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================

@admin_bp.route('/api/admin/threats/ips', methods=['GET'])
@require_admin
def get_suspicious_ips():
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor(dictionary=True)
        yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            SELECT 
                ip_address,
                COUNT(*) as attempts,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked,
                MAX(timestamp) as last_attempt
            FROM auth_logs
            WHERE timestamp > %s
            GROUP BY ip_address
            HAVING blocked > 2
            ORDER BY blocked DESC
            LIMIT 50
        ''', (yesterday,))
        ips = cursor.fetchall()
        cursor.close()
        return jsonify(ips), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/admin/threats/patterns', methods=['GET'])
@require_admin
def get_attack_patterns():
    try:
        db = current_app.config['DB']
        cursor = db.conn.cursor(dictionary=True)
        yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            SELECT 
                user_id,
                username,
                COUNT(*) as failed_attempts,
                GROUP_CONCAT(ip_address) as ip_addresses
            FROM (
                SELECT l.user_id, u.username, l.ip_address
                FROM auth_logs l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE l.timestamp > %s AND l.status = 'failed'
            ) AS failed_logins
            GROUP BY user_id
            HAVING failed_attempts > 3
            ORDER BY failed_attempts DESC
        ''', (yesterday,))
        patterns = cursor.fetchall()
        cursor.close()
        return jsonify(patterns), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
