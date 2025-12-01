"""
Database Management for SecureNet - PyMySQL Version
"""

import pymysql
from contextlib import contextmanager
from datetime import datetime
import json

class DatabaseManager:
    """MySQL database manager using PyMySQL."""
    
    def __init__(self, host='localhost', user='root', password='your_password', database='defaultdb', port=10675):
        self.config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database,
            'charset': 'utf8mb4',
            'port': port,
            'cursorclass': pymysql.cursors.DictCursor,
            'autocommit': False
        }
        
        self._create_database_if_not_exists()
        self._init_database()
        print("✓ MySQL Database initialized (PyMySQL)")
    
    def _create_database_if_not_exists(self):
        """Create the database if it doesn't exist."""
        try:
            temp_config = self.config.copy()
            temp_config.pop('database', None)  # Remove database key
            
            # Add SSL config for Aiven
            temp_config['ssl'] = {'ssl_disabled': False}
            temp_config['ssl_verify_cert'] = False
            temp_config['ssl_verify_identity'] = False
            
            conn = pymysql.connect(**temp_config)
            cursor = conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['database']}")
            cursor.close()
            conn.close()
            print(f"✓ Database '{self.config['database']}' ready")
        except Exception as e:
            print(f"Error creating database: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = None
        try:
            conn = pymysql.connect(**self.config)
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    def _init_database(self):
        """Initialize database tables."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    profile_id VARCHAR(255) NOT NULL,
                    failed_attempts INT DEFAULT 0,
                    is_locked BOOLEAN DEFAULT FALSE,
                    is_admin BOOLEAN DEFAULT FALSE,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    mfa_secret VARCHAR(255) NULL,
                    backup_codes TEXT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    INDEX idx_username (username),
                    INDEX idx_email (email)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    risk_level VARCHAR(50),
                    ml_prediction VARCHAR(50),
                    behavioral_deviation FLOAT,
                    flags TEXT,
                    ip_address VARCHAR(45),
                    country VARCHAR(10),
                    user_agent TEXT,
                    edns_threats TEXT,
                    details JSON,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_user_id (user_id),
                    INDEX idx_status (status),
                    INDEX idx_timestamp (timestamp)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_profiles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(255) UNIQUE NOT NULL,
                    profile_data JSON NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_user_id (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_stats (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    date DATE UNIQUE NOT NULL,
                    total_logins INT DEFAULT 0,
                    blocked_attempts INT DEFAULT 0,
                    mfa_required INT DEFAULT 0,
                    threats_detected INT DEFAULT 0,
                    INDEX idx_date (date)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ''')
            
            conn.commit()
    
    def create_user(self, username, email, password_hash, profile_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, profile_id)
                VALUES (%s, %s, %s, %s)
            ''', (username, email, password_hash, profile_id))
            return cursor.lastrowid
    
    def user_exists(self, username):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            return cursor.fetchone() is not None
    
    def get_user(self, username):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            return cursor.fetchone()
    
    def get_user_by_id(self, user_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            return cursor.fetchone()
    
    def increment_failed_attempts(self, user_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = failed_attempts + 1,
                    is_locked = CASE WHEN failed_attempts + 1 >= 5 THEN TRUE ELSE FALSE END
                WHERE id = %s
            ''', (user_id,))
    
    def reset_failed_attempts(self, user_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = 0,
                    is_locked = FALSE,
                    last_login = NOW()
                WHERE id = %s
            ''', (user_id,))
    
    def log_auth_attempt(self, user_id, status, result):
        """Log authentication attempt with safe parsing."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                flags_json = json.dumps(result.get('flags', []))
                edns_threats = json.dumps(result.get('edns_security', {}).get('threats_detected', []))
                
                # Safe parsing of behavioral deviation
                behavioral_dev = result.get('keystroke_deviation', '0%')
                
                if isinstance(behavioral_dev, str):
                    # Handle special cases
                    if ('N/A' in behavioral_dev or 
                        'Registration' in behavioral_dev or 
                        'First Login' in behavioral_dev):
                        behavioral_dev = 0.0
                    else:
                        # Remove % and convert
                        try:
                            behavioral_dev = float(behavioral_dev.rstrip('%'))
                        except ValueError:
                            behavioral_dev = 0.0
                else:
                    behavioral_dev = float(behavioral_dev)
                
                # Store full result in details JSON field
                network_info = result.get('network_info', {})
                details_json = json.dumps({
                    'country': network_info.get('country'),
                    'device_fingerprint': network_info.get('device_fingerprint'),
                    'ip_address': network_info.get('ip_address'),
                    'user_agent': network_info.get('user_agent'),
                    'asn': network_info.get('asn'),
                    'risk_level': result.get('final_risk_level'),
                    'ml_prediction': result.get('ml_prediction'),
                    'edns_boost': result.get('edns_boost', 0),
                    'network_boost': result.get('network_boost', 0),
                    'behavioral_boost': result.get('behavioral_boost', 0),
                    'total_boost': result.get('total_boost', 0)
                })
                
                cursor.execute('''
                    INSERT INTO auth_logs (
                        user_id, status, risk_level, ml_prediction,
                        behavioral_deviation, flags, edns_threats,
                        ip_address, country, user_agent, details
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    user_id, status,
                    result.get('final_risk_level'),
                    result.get('ml_prediction'),
                    behavioral_dev,
                    flags_json, edns_threats,
                    network_info.get('ip_address'),
                    network_info.get('country'),
                    network_info.get('user_agent', '')[:500],
                    details_json
                ))
                
                today = datetime.now().date()
                cursor.execute('''
                    INSERT INTO system_stats (date, total_logins, blocked_attempts, mfa_required)
                    VALUES (%s, 1, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        total_logins = total_logins + 1,
                        blocked_attempts = blocked_attempts + VALUES(blocked_attempts),
                        mfa_required = mfa_required + VALUES(mfa_required)
                ''', (today, 1 if status == 'blocked' else 0, 1 if status == 'mfa_required' else 0))
                
                print(f"✓ Auth attempt logged for user {user_id}: {status}")
                
        except Exception as e:
            print(f"❌ Error logging auth attempt: {e}")
            import traceback
            traceback.print_exc()
    
    def get_auth_history(self, user_id, limit=20):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, status, risk_level, country, ip_address
                FROM auth_logs WHERE user_id = %s
                ORDER BY timestamp DESC LIMIT %s
            ''', (user_id, limit))
            return cursor.fetchall()
    
    def get_total_users(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as count FROM users')
            return cursor.fetchone()['count']
    
    def get_logins_today(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            today = datetime.now().date()
            cursor.execute('SELECT total_logins FROM system_stats WHERE date = %s', (today,))
            row = cursor.fetchone()
            return row['total_logins'] if row else 0
    
    def get_blocked_today(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            today = datetime.now().date()
            cursor.execute('SELECT blocked_attempts FROM system_stats WHERE date = %s', (today,))
            row = cursor.fetchone()
            return row['blocked_attempts'] if row else 0
    
    def get_mfa_today(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            today = datetime.now().date()
            cursor.execute('SELECT mfa_required FROM system_stats WHERE date = %s', (today,))
            row = cursor.fetchone()
            return row['mfa_required'] if row else 0
    
    def get_top_risk_countries(self, limit=5):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT country, COUNT(*) as count
                FROM auth_logs
                WHERE status = 'blocked' AND country IS NOT NULL
                GROUP BY country ORDER BY count DESC LIMIT %s
            ''', (limit,))
            return cursor.fetchall()
    
    def get_recent_threats(self, limit=10):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.username, a.timestamp, a.risk_level, a.country, a.flags
                FROM auth_logs a
                JOIN users u ON a.user_id = u.id
                WHERE a.status IN ('blocked', 'mfa_required')
                ORDER BY a.timestamp DESC LIMIT %s
            ''', (limit,))
            
            rows = cursor.fetchall()
            for row in rows:
                row['flags'] = json.loads(row['flags']) if row['flags'] else []
            return rows
    
    def unlock_user(self, username):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET failed_attempts = 0, is_locked = FALSE 
                WHERE username = %s
            ''', (username,))
            return cursor.rowcount > 0
    
    def get_user_auth_history(self, user_id, limit=10):
        """Get user authentication history."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp, status, risk_level, ip_address, country
                    FROM auth_logs
                    WHERE user_id = %s
                    AND status = 'success'
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, (user_id, limit))
                
                logs = cursor.fetchall()
                
                # Format for frontend
                history = []
                for log in logs:
                    history.append({
                        'timestamp': log['timestamp'].isoformat() + 'Z',
                        'status': log['status'],
                        'risk_level': log.get('risk_level', 'Unknown'),
                        'country': log.get('country', 'Unknown'),
                        'ip_address': log.get('ip_address', 'Unknown')
                    })
                
                return history
                
        except Exception as e:
            print(f"Get auth history error: {e}")
            return []
    
    def update_user_mfa(self, user_id, secret, backup_codes, enabled=False):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET mfa_secret = %s, backup_codes = %s, mfa_enabled = %s
                    WHERE id = %s
                """, (secret, json.dumps(backup_codes), enabled, user_id))
                return True
        except Exception as e:
            print(f"Update MFA error: {e}")
            return False
    
    def enable_user_mfa(self, user_id):
        """Enable MFA for user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET mfa_enabled = TRUE WHERE id = %s", (user_id,))
                return True
        except Exception as e:
            print(f"Enable MFA error: {e}")
            return False
    
    def disable_user_mfa(self, user_id):
        """Disable MFA for user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET mfa_enabled = FALSE, mfa_secret = NULL, backup_codes = NULL
                    WHERE id = %s
                """, (user_id,))
                return True
        except Exception as e:
            print(f"Disable MFA error: {e}")
            return False
    
    def update_backup_codes(self, user_id, backup_codes):
        """Update backup codes."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users SET backup_codes = %s WHERE id = %s
                """, (json.dumps(backup_codes), user_id))
                return True
        except Exception as e:
            print(f"Update backup codes error: {e}")
            return False
    
    def save_user_profile(self, user_id, profile_dict):
        """Save user behavioral profile to database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO user_profiles (user_id, profile_data)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE 
                        profile_data = VALUES(profile_data),
                        updated_at = NOW()
                """, (user_id, json.dumps(profile_dict)))
                
                print(f"✓ Profile saved to database for user {user_id}")
                return True
                
        except Exception as e:
            print(f"❌ Profile save failed for {user_id}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def load_user_profile(self, user_id):
        """Load user behavioral profile from database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT profile_data FROM user_profiles WHERE user_id = %s
                """, (user_id,))
                
                result = cursor.fetchone()
                
                if result:
                    profile_data = json.loads(result['profile_data'])
                    print(f"✓ Profile loaded from database: user={user_id}, logins={profile_data.get('successful_logins', 0)}")
                    return profile_data
                else:
                    print(f"⚠️ No profile found in database for user {user_id}")
                    return None
                    
        except Exception as e:
            print(f"❌ Profile load failed for {user_id}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    # =====================================================================
    # ALERT SYSTEM METHODS
    # =====================================================================
    
    def get_user_login_countries(self, user_id):
        """Get list of countries user has logged in from."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT country 
                    FROM auth_logs 
                    WHERE user_id = %s 
                    AND country IS NOT NULL
                    AND status = 'success'
                """, (user_id,))
                return [row['country'] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting user countries: {e}")
            return []
    
    def get_user_ips(self, user_id):
        """Get list of IP addresses user has logged in from."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT ip_address 
                    FROM auth_logs 
                    WHERE user_id = %s 
                    AND ip_address IS NOT NULL
                    AND status = 'success'
                """, (user_id,))
                return [row['ip_address'] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting user IPs: {e}")
            return []

    
    def lock_user_account(self, user_id):
        """Lock user account after too many failed attempts."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET is_locked = TRUE WHERE id = %s",
                    (user_id,)
                )
                print(f"🔒 Account locked for user {user_id}")
                return True
        except Exception as e:
            print(f"Error locking account: {e}")
            return False
    
    def update_user_password(self, user_id, new_password_hash):
        """Update user's password."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s",
                    (new_password_hash, user_id)
                )
                print(f"✓ Password updated for user {user_id}")
                return True
        except Exception as e:
            print(f"Error updating password: {e}")
            return False
