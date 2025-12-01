"""
SecureNet Admin Control Panel API
Provides admin endpoints for monitoring and management (MySQL version)
"""

from flask import Blueprint, jsonify, request, current_app
from functools import wraps
import json
import os
from datetime import datetime, timedelta
import pymysql.cursors

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

# ============================================================================
# ADMIN AUTH
# ============================================================================

@admin_bp.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin authentication endpoint."""
    try:
        data = request.json or {}
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
    """Get overview dashboard statistics."""
    try:
        db = current_app.config['DB']
        
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            cursor.execute('SELECT COUNT(*) as count FROM users')
            total_users = cursor.fetchone()['count']
            
            seven_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                'SELECT COUNT(DISTINCT user_id) as count FROM auth_logs WHERE timestamp > %s',
                (seven_days_ago,)
            )
            active_users = cursor.fetchone()['count']
            
            yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                'SELECT COUNT(*) as count FROM auth_logs WHERE timestamp > %s',
                (yesterday,)
            )
            recent_logins = cursor.fetchone()['count']
            
            cursor.execute(
                'SELECT COUNT(*) as count FROM auth_logs WHERE timestamp > %s AND status = %s',
                (yesterday, "failed")
            )
            failed_logins = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM users WHERE mfa_enabled = 1')
            mfa_users = cursor.fetchone()['count']
            
            cursor.execute(
                'SELECT COUNT(*) as count FROM auth_logs WHERE timestamp > %s AND status = %s',
                (yesterday, "blocked")
            )
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
            'success_rate': round(((recent_logins - failed_logins) / recent_logins * 100)
                                  if recent_logins > 0 else 100, 1)
        }), 200
    except Exception as e:
        print(f"❌ Admin stats error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/stats/timeline', methods=['GET'])
@require_admin
def get_timeline_stats():
    """Get login timeline for charts."""
    try:
        db = current_app.config['DB']
        days = int(request.args.get('days', 7))
        
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
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
        print(f"❌ Timeline error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/stats/risk-distribution', methods=['GET'])
@require_admin
def get_risk_distribution():
    """Get risk level distribution."""
    try:
        db = current_app.config['DB']
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                SELECT risk_level, COUNT(*) as count
                FROM auth_logs
                WHERE timestamp > %s AND risk_level IS NOT NULL
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
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                SELECT 
                    country,
                    COUNT(*) as count,
                    SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked
                FROM auth_logs
                WHERE timestamp > %s AND country IS NOT NULL
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
        
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            if search:
                cursor.execute('''
                    SELECT id, username, email, mfa_enabled, is_locked, failed_attempts, created_at
                    FROM users
                    WHERE username LIKE %s OR email LIKE %s
                    ORDER BY created_at DESC
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
        print(f"❌ List users error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/users', methods=['POST'])
@require_admin
def create_user():
    """Create a new user (admin action)."""
    try:
        db = current_app.config['DB']
        data = request.json or {}
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        is_admin = bool(data.get('is_admin', False))

        if not all([username, email, password]):
            return jsonify({'error': 'username, email, password required'}), 400

        password_hasher = current_app.config.get('PASSWORD_HASHER')
        auth_engine = current_app.config.get('AUTH_ENGINE')

        if not password_hasher or not auth_engine:
            return jsonify({'error': 'Server not configured for admin create_user'}), 500

        password_hash = password_hasher(password)
        profile_id = f"profile_{username}"

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, profile_id, is_admin)
                VALUES (%s, %s, %s, %s, %s)
            ''', (username, email, password_hash, profile_id, is_admin))
            user_id = cursor.lastrowid
            cursor.close()

        # Initialize empty behavioral profile
        from auth_engine import UserBehavioralProfile  # adjust path if needed
        profile = UserBehavioralProfile(profile_id)
        db.save_user_profile(profile_id, profile.to_dict())

        return jsonify({'success': True, 'user_id': user_id}), 201
    except Exception as e:
        print(f"❌ Admin create_user error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@require_admin
def update_user(user_id):
    """Update user email / password / is_admin / username."""
    try:
        db = current_app.config['DB']
        data = request.json or {}
        fields = []
        params = []

        if 'username' in data:
            fields.append('username = %s')
            params.append(data['username'])
        if 'email' in data:
            fields.append('email = %s')
            params.append(data['email'])
        if data.get('password'):
            password_hasher = current_app.config.get('PASSWORD_HASHER')
            if not password_hasher:
                return jsonify({'error': 'Password hasher not configured'}), 500
            fields.append('password_hash = %s')
            params.append(password_hasher(data['password']))
        if 'is_admin' in data:
            fields.append('is_admin = %s')
            params.append(bool(data['is_admin']))

        if not fields:
            return jsonify({'error': 'No fields to update'}), 400

        params.append(user_id)

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
                UPDATE users SET {", ".join(fields)} WHERE id = %s
            ''', params)
            affected = cursor.rowcount
            cursor.close()

        if affected == 0:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"❌ Admin update_user error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/users/<int:user_id>', methods=['GET'])
@require_admin
def get_user_details(user_id):
    """Get detailed user information."""
    try:
        db = current_app.config['DB']
        
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if 'password_hash' in user:
                del user['password_hash']
            
            cursor.execute('''
                SELECT timestamp, status, ip_address, risk_level, country
                FROM auth_logs
                WHERE user_id = %s
                ORDER BY timestamp DESC
                LIMIT 20
            ''', (user_id,))
            recent_logins = cursor.fetchall()
            cursor.close()
        
        profile_data = current_app.config['DB'].load_user_profile(user['profile_id'])
        
        return jsonify({
            'user': user,
            'recent_logins': recent_logins,
            'profile': profile_data
        }), 200
    except Exception as e:
        print(f"❌ Get user details error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    """Delete a user."""
    try:
        db = current_app.config['DB']
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
            affected = cursor.rowcount
            cursor.close()

        if affected == 0:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"❌ Admin delete_user error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/users/<int:user_id>/unlock', methods=['POST'])
@require_admin
def unlock_user(user_id):
    """Unlock a locked user account."""
    try:
        db = current_app.config['DB']
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET is_locked = FALSE, failed_attempts = 0 
                WHERE id = %s
            ''', (user_id,))
            affected = cursor.rowcount
            cursor.close()
        
        if affected > 0:
            return jsonify({'success': True, 'message': 'User unlocked successfully'}), 200
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        print(f"❌ Unlock error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/api/admin/users/<int:user_id>/block', methods=['POST'])
@require_admin
def block_user(user_id):
    """Block (lock) a user account."""
    try:
        db = current_app.config['DB']
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET is_locked = TRUE 
                WHERE id = %s
            ''', (user_id,))
            affected = cursor.rowcount
            cursor.close()
        
        if affected > 0:
            return jsonify({'success': True, 'message': 'User blocked'}), 200
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        print(f"❌ Block user error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/api/admin/users/<int:user_id>/reset-mfa', methods=['POST'])
@require_admin
def reset_user_mfa(user_id):
    """Reset MFA for a user."""
    try:
        db = current_app.config['DB']
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET mfa_enabled = FALSE, mfa_secret = NULL, backup_codes = NULL
                WHERE id = %s
            ''', (user_id,))
            affected = cursor.rowcount
            cursor.close()
        
        if affected > 0:
            return jsonify({'success': True, 'message': 'MFA reset successfully'}), 200
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        print(f"❌ Reset MFA error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# AUTHENTICATION LOGS
# ============================================================================

@admin_bp.route('/api/admin/logs', methods=['GET'])
@require_admin
def get_auth_logs():
    """Get authentication logs with filtering."""
    try:
        db = current_app.config['DB']
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        status = request.args.get('status', '')
        user_id = request.args.get('user_id', '')
        offset = (page - 1) * per_page
        
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
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
            cursor.close()
        
        return jsonify({'logs': logs}), 200
    except Exception as e:
        print(f"❌ Get logs error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# SYSTEM CONFIGURATION
# ============================================================================

@admin_bp.route('/api/admin/config/thresholds', methods=['GET'])
@require_admin
def get_thresholds():
    """Get current risk thresholds."""
    return jsonify({
        'keystroke_deviation': {
            'minor': 0.15,
            'moderate': 0.30,
            'high': 0.50
        },
        'boost_levels': {
            'mfa_trigger': 3.0,
            'block_trigger': 4.0
        },
        'network': {
            'new_device': 1.5,
            'new_country': 1.0,
            'high_risk_country': 2.0
        }
    }), 200


@admin_bp.route('/api/admin/config/thresholds', methods=['PUT'])
@require_admin
def update_thresholds():
    """Update risk thresholds (demo - not persisted)."""
    return jsonify({
        'success': True,
        'message': 'Thresholds updated (demo only)'
    }), 200

# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================

@admin_bp.route('/api/admin/threats/ips', methods=['GET'])
@require_admin
def get_suspicious_ips():
    """Get suspicious IP addresses."""
    try:
        db = current_app.config['DB']
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
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
        print(f"❌ Get threats error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/threats/patterns', methods=['GET'])
@require_admin
def get_attack_patterns():
    """Get attack patterns (multiple failed attempts)."""
    try:
        db = current_app.config['DB']
        with db.get_connection() as conn:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            yesterday = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                SELECT 
                    l.user_id,
                    u.username,
                    COUNT(*) as failed_attempts,
                    GROUP_CONCAT(DISTINCT l.ip_address) as ip_addresses
                FROM auth_logs l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE l.timestamp > %s AND l.status = 'failed'
                GROUP BY l.user_id, u.username
                HAVING failed_attempts > 3
                ORDER BY failed_attempts DESC
            ''', (yesterday,))
            patterns = cursor.fetchall()
            cursor.close()
        return jsonify(patterns), 200
    except Exception as e:
        print(f"❌ Get patterns error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# IP BLACKLIST MANAGEMENT
# ============================================================================

@admin_bp.route('/api/admin/block-ip', methods=['POST'])
@require_admin
def block_ip():
    """Add IP to global blacklist."""
    try:
        db = current_app.config['DB']
        data = request.json or {}
        ip = data.get('ip')
        if not ip:
            return jsonify({'error': 'ip required'}), 400

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ''')
            cursor.execute('''
                INSERT INTO blocked_ips (ip_address)
                VALUES (%s)
                ON DUPLICATE KEY UPDATE ip_address = ip_address
            ''', (ip,))
            cursor.close()

        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"❌ Admin block_ip error: {e}")
        return jsonify({'error': str(e)}), 500
