"""
SecureNet Authentication Engine
Combines ML model, behavioral biometrics, and rule-based security
"""

import numpy as np
import pandas as pd
from datetime import datetime
from tensorflow import keras
import joblib
import json
import os

class UserBehavioralProfile:
    """User behavioral profile for authentication."""
    
    def __init__(self, user_id):
        self.user_id = user_id
        self.created_at = datetime.now().isoformat()
        self.keystroke_baseline = {}
        self.network_baseline = {
            'typical_countries': [],
            'typical_asns': [],
            'typical_devices': [],
            'typical_login_hours': [],
            'country_login_counts': {}  # ← ADD THIS
        }

        self.successful_logins = 0
        self.failed_attempts = 0
        self.last_login = None
    
    def capture_registration_baseline(self, registration_data):
        """Capture initial baseline during registration."""
        keystroke_timings = registration_data.get('keystroke_timings', [])
        network_info = registration_data.get('network_info', {})
    
        # Store device fingerprint
        device_fingerprint = network_info.get('device_fingerprint', 'unknown')
        current_country = network_info.get('country', 'US')
        current_asn = network_info.get('asn', '0')
        
        # Initialize network baseline with ALL needed lists
        self.network_baseline = {
            'registration_ip': network_info.get('ip_address'),
            'registration_country': current_country,
            'typical_countries': [current_country],
            'typical_devices': [device_fingerprint],
            'typical_asns': [current_asn],
            'typical_login_hours': [datetime.now().hour],
            'registration_time': datetime.now().isoformat(),
            'blacklisted_ips': [],
            'country_login_counts': {current_country: 1}  # ← ADD THIS LINE
        }
        
        # Calculate keystroke baseline if data exists
        if keystroke_timings and len(keystroke_timings) > 0:
            self.keystroke_baseline = {
                'avg_timing': float(np.mean(keystroke_timings)),
                'std_timing': float(np.std(keystroke_timings)),
                'cv_timing': float(np.std(keystroke_timings) / (np.mean(keystroke_timings) + 1e-6)),
                'consistency': float(1 / (1 + np.std(keystroke_timings) / (np.mean(keystroke_timings) + 1e-6))),
                'speed_proxy': float(60000.0 / (np.mean(keystroke_timings) + 1.0))
            }
            print(f"✓ Keystroke baseline set: avg={self.keystroke_baseline['avg_timing']:.2f}ms")
        else:
            print("⚠️ No keystroke data - baseline not set")
        
        print(f"✓ Registration baseline captured:")
        print(f"  Device: {device_fingerprint[:16]}...")
        print(f"  Country: {current_country} (count: 1)")  # ← UPDATE THIS
        print(f"  IP: {network_info.get('ip_address', 'Unknown')}")


    
    def compare_to_baseline(self, login_data):
        """Compare login attempt to established baseline with realistic tolerances."""
        keystroke_timings = login_data.get('keystroke_timings', [])
        network_info = login_data.get('network_info', {})
        
        flags = []
        
        # If no baseline yet, return neutral
        if not self.keystroke_baseline or self.successful_logins == 0:
            return {
                'keystroke_deviation': 0,
                'network_deviation': 0,
                'time_deviation': 0,
                'overall_deviation': 0,
                'flags': ['First login - establishing baseline']
            }
        
        # Keystroke analysis with TOLERANCES
        if keystroke_timings:
            current_avg = np.mean(keystroke_timings)
            current_std = np.std(keystroke_timings)
            
            baseline_avg = self.keystroke_baseline['avg_timing']
            baseline_std = self.keystroke_baseline['std_timing']
            
            # Calculate percentage difference
            avg_diff = abs(current_avg - baseline_avg) / baseline_avg
            std_diff = abs(current_std - baseline_std) / (baseline_std + 1e-6)
            
            # TOLERANCE: ±20% is acceptable (people naturally vary)
            if avg_diff > 0.20:
                keystroke_deviation = avg_diff
                flags.append(f'Typing speed {avg_diff:.1%} different from baseline')
            else:
                keystroke_deviation = 0
        else:
            keystroke_deviation = 0
        
        # Network analysis with TOLERANCES
        network_deviation = 0
        current_country = network_info.get('country', 'US')
        
        if current_country not in self.network_baseline['typical_countries']:
            high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'NG']
            if current_country in high_risk_countries:
                network_deviation = 0.5
                flags.append(f'Login from high-risk country: {current_country}')
            else:
                network_deviation = 0.1
                flags.append(f'New location: {current_country}')
        
        # Time analysis with TOLERANCES
        current_hour = datetime.now().hour
        typical_hours = self.network_baseline.get('typical_login_hours', [])
        
        time_deviation = 0
        if typical_hours:
            closest_hour = min(typical_hours, key=lambda h: abs(h - current_hour))
            hour_diff = abs(closest_hour - current_hour)
            
            if hour_diff > 3:
                time_deviation = min(hour_diff / 24, 0.3)
                flags.append(f'Unusual login time: {current_hour}:00')
        
        # Overall deviation with WEIGHTED tolerances
        overall_deviation = (
            keystroke_deviation * 0.6 +
            network_deviation * 0.25 +
            time_deviation * 0.15
        )
        
        return {
            'keystroke_deviation': keystroke_deviation,
            'network_deviation': network_deviation,
            'time_deviation': time_deviation,
            'overall_deviation': overall_deviation,
            'flags': flags if flags else ['Normal behavior']
        }
    
    def _check_network_anomalies(self, network_info):
        """Check for network-based anomalies including device fingerprints."""
        flags = []
        anomaly_score = 0
        
        current_country = network_info.get('country', 'Unknown')
        current_device = network_info.get('device_fingerprint', 'unknown')
        current_asn = str(network_info.get('asn', '0'))
        current_hour = datetime.now().hour
        
        # Check country - differentiate high-risk vs new normal
        if current_country not in self.network_baseline.get('typical_countries', []):
            high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'NG', 'VN']
            if current_country in high_risk_countries:
                flags.append('high_risk_country')
                anomaly_score += 2  # High risk country
                print(f"⚠️ High-risk country: {current_country}")
            else:
                flags.append('new_country')
                anomaly_score += 1  # Normal new country
                print(f"⚠️ New location: {current_country}")
        
        # Check device fingerprint - THIS IS KEY!
        if current_device not in self.network_baseline.get('typical_devices', []):
            flags.append('new_device')
            anomaly_score += 1.5  # New device is significant
            print(f"⚠️ New device detected: {current_device[:16]}...")
            
            # Add device to baseline for future logins
            self.network_baseline['typical_devices'].append(current_device)
        
        # Check ASN (Internet Service Provider)
        if current_asn != '0' and current_asn not in self.network_baseline.get('typical_asns', []):
            flags.append('new_asn')
            anomaly_score += 0.5  # Minor concern
            print(f"⚠️ New ASN/ISP detected: {current_asn}")

        
        # Check login hour (time-based anomaly)
        typical_hours = self.network_baseline.get('typical_login_hours', [])
        if typical_hours and len(typical_hours) > 0:
            avg_hour = np.mean(typical_hours)
            if abs(current_hour - avg_hour) > 6:
                flags.append('unusual_time')
                anomaly_score += 0.5
                print(f"⚠️ Unusual login time: {current_hour}:00")
        
        # Check for blacklisted IPs
        if network_info.get('ip_address') in self.network_baseline.get('blacklisted_ips', []):
            flags.append('blacklisted_ip')
            anomaly_score += 3  # Critical
            print(f"🚨 Blacklisted IP detected!")
        
        return flags, anomaly_score



    
    def update_baseline(self, login_data, successful=True):
        """Update baseline with new login data."""
        keystroke_timings = login_data.get('keystroke_timings', [])
        network_info = login_data.get('network_info', {})
        
        if successful:
            self.successful_logins += 1
            self.last_login = datetime.now().isoformat()
            
            # Update keystroke baseline
            if keystroke_timings:
                current_avg = np.mean(keystroke_timings)
                current_std = np.std(keystroke_timings)
                
                if not self.keystroke_baseline:
                    self.keystroke_baseline = {
                        'avg_timing': float(current_avg),
                        'std_timing': float(current_std),
                        'cv_timing': float(current_std / (current_avg + 1e-6)),
                        'consistency': float(1 / (1 + current_std / (current_avg + 1e-6))),
                        'speed_proxy': float(60000.0 / (current_avg + 1.0))
                    }
                else:
                    # Weighted average: 70% old, 30% new
                    alpha = 0.3
                    self.keystroke_baseline['avg_timing'] = float(
                        (1 - alpha) * self.keystroke_baseline['avg_timing'] + alpha * current_avg
                    )
                    self.keystroke_baseline['std_timing'] = float(
                        (1 - alpha) * self.keystroke_baseline['std_timing'] + alpha * current_std
                    )
                    # Recalculate derived metrics
                    self.keystroke_baseline['cv_timing'] = float(
                        self.keystroke_baseline['std_timing'] / (self.keystroke_baseline['avg_timing'] + 1e-6)
                    )
                    self.keystroke_baseline['consistency'] = float(
                        1 / (1 + self.keystroke_baseline['std_timing'] / (self.keystroke_baseline['avg_timing'] + 1e-6))
                    )
                    self.keystroke_baseline['speed_proxy'] = float(
                        60000.0 / (self.keystroke_baseline['avg_timing'] + 1.0)
                    )
            
            # Update network baseline
            country = network_info.get('country')
            if country and country not in self.network_baseline['typical_countries']:
                self.network_baseline['typical_countries'].append(country)
            
            current_hour = datetime.now().hour
            if current_hour not in self.network_baseline['typical_login_hours']:
                self.network_baseline['typical_login_hours'].append(current_hour)
            
            # ========== ADD THIS SECTION ==========
            # Update country login counts
            if country and country != 'Unknown':
                # Initialize country_login_counts if it doesn't exist (for old profiles)
                if 'country_login_counts' not in self.network_baseline:
                    self.network_baseline['country_login_counts'] = {}
                
                # Increment country count
                if country in self.network_baseline['country_login_counts']:
                    self.network_baseline['country_login_counts'][country] += 1
                else:
                    self.network_baseline['country_login_counts'][country] = 1
                
                print(f"✓ Country login count: {country} = {self.network_baseline['country_login_counts'][country]}")
            # ========== END NEW SECTION ==========
            
            # Update other network info if needed
            device_fingerprint = network_info.get('device_fingerprint')
            if device_fingerprint and device_fingerprint not in self.network_baseline.get('typical_devices', []):
                if 'typical_devices' not in self.network_baseline:
                    self.network_baseline['typical_devices'] = []
                self.network_baseline['typical_devices'].append(device_fingerprint)
                # Keep only last 5 devices
                self.network_baseline['typical_devices'] = self.network_baseline['typical_devices'][-5:]
            
            asn = str(network_info.get('asn', '0'))
            if asn and asn != '0' and asn not in self.network_baseline.get('typical_asns', []):
                if 'typical_asns' not in self.network_baseline:
                    self.network_baseline['typical_asns'] = []
                self.network_baseline['typical_asns'].append(asn)
                # Keep only last 10 ASNs
                self.network_baseline['typical_asns'] = self.network_baseline['typical_asns'][-10:]
        
        else:
            self.failed_attempts += 1

    
    def to_dict(self):
        """Convert profile to dictionary for JSON storage."""
        # Deep copy network baseline to avoid modifying original
        import copy
        network_baseline_copy = copy.deepcopy(self.network_baseline)
        
        # Convert registration_time datetime to string if it exists
        if 'registration_time' in network_baseline_copy:
            reg_time = network_baseline_copy['registration_time']
            if hasattr(reg_time, 'isoformat'):
                network_baseline_copy['registration_time'] = reg_time.isoformat()
            elif not isinstance(reg_time, str):
                network_baseline_copy['registration_time'] = str(reg_time)
        
        return {
            'user_id': self.user_id,
            'created_at': self.created_at if isinstance(self.created_at, str) else self.created_at.isoformat(),
            'last_updated': datetime.now().isoformat(),
            'keystroke_baseline': self.keystroke_baseline,
            'network_baseline': network_baseline_copy,
            'successful_logins': self.successful_logins,
            'failed_attempts': self.failed_attempts,
            'last_login': self.last_login
        }

    
    @classmethod
    def from_dict(cls, data):
        """Create profile from dictionary."""
        profile = cls(data['user_id'])
        profile.created_at = data.get('created_at', profile.created_at)
        profile.keystroke_baseline = data.get('keystroke_baseline', {})
        
        # Load network baseline
        profile.network_baseline = data.get('network_baseline', profile.network_baseline)
        
        # ← ADD MIGRATION: Handle old profiles without country_login_counts
        if 'country_login_counts' not in profile.network_baseline:
            profile.network_baseline['country_login_counts'] = {}
            
            # Estimate counts from typical_countries list (for migration)
            from collections import Counter
            countries = profile.network_baseline.get('typical_countries', [])
            if countries:
                country_counts = Counter(countries)
                profile.network_baseline['country_login_counts'] = dict(country_counts)
                print(f"⚠️ Migrated old profile: estimated country counts from baseline")
        
        profile.successful_logins = data.get('successful_logins', 0)
        profile.failed_attempts = data.get('failed_attempts', 0)
        profile.last_login = data.get('last_login')
        
        return profile


class AuthenticationEngine:
    """Main authentication engine combining all security layers."""
    
    def __init__(self, model_dir='models/securenet_model_all5_20251118_190557', db_manager=None):
        self.model_dir = model_dir
        self.db = db_manager
        
        # Don't load model yet - load on first use
        self.model = None
        self.preprocessor = None
        self.feature_cols = None
        
        print("✓ Authentication Engine initialized (ML model will load on first authentication)")
    
    def _ensure_model_loaded(self):
        """Load ML model on first authentication request."""
        if self.model is None:
            print("🔄 Loading ML model...")
            import time
            start = time.time()
            
            self.model = keras.models.load_model(f"{self.model_dir}/neural_network.h5")
            self.preprocessor = joblib.load(f"{self.model_dir}/preprocess.pkl")
            self.feature_cols = joblib.load(f"{self.model_dir}/feature_columns.pkl")
            
            elapsed = time.time() - start
            print(f"✓ ML model loaded in {elapsed:.2f}s")
    
    def register_user(self, user_id, registration_data):
        """Register new user and capture baseline."""
        profile = UserBehavioralProfile(user_id)
        profile.capture_registration_baseline(registration_data)
        self._save_profile(profile)
        return profile
    
    
    def authenticate_user(self, user_id, login_data, edns_boost=0):
        """Complete authentication with all security layers."""

        self._ensure_model_loaded()
        # Load profile
        profile = self._load_profile(user_id)
        if not profile:
            return {
                'success': False,
                'action': 'BLOCK',
                'reason': 'User profile not found'
            }
        
        # Check if this is first login
        is_first_login = (profile.successful_logins == 0)
        print(f"DEBUG: successful_logins = {profile.successful_logins}, is_first_login = {is_first_login}")
        
        # Compare to baseline
        deviations = profile.compare_to_baseline(login_data)
        
        keystroke_timings = login_data.get('keystroke_timings', [120])
        network_info = login_data.get('network_info', {})

        # Get country frequency from counts dictionary
        country = network_info.get('country', 'Unknown')
        country_freq = profile.network_baseline.get('country_login_counts', {}).get(country, 0)

        features_dict = {
            'avg_timing': np.mean(keystroke_timings),
            'std_timing': np.std(keystroke_timings),
            'cv_timing': np.std(keystroke_timings) / (np.mean(keystroke_timings) + 1e-6),
            'consistency': 1 / (1 + np.std(keystroke_timings) / (np.mean(keystroke_timings) + 1e-6)),
            'speed_proxy': 60000.0 / (np.mean(keystroke_timings) + 1.0),
            'hour_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            'is_weekend': 1 if datetime.now().weekday() >= 5 else 0,
            'is_night': 1 if (datetime.now().hour < 6 or datetime.now().hour >= 22) else 0,
            'country_frequency': country_freq,  # ← FIXED: Use actual count
            'is_unknown_location': 1 if country_freq == 0 else 0,  # ← FIXED: Based on count
            'ip_entropy': len(set(network_info.get('ip_address', '0.0.0.0').split('.'))),
            'asn': int(network_info.get('asn', 0)),
            'is_mobile': 1 if 'Mobile' in network_info.get('user_agent', '') else 0,
            'is_bot': 1 if any(x in network_info.get('user_agent', '').lower() for x in ['bot', 'curl', 'python']) else 0,
            'ua_length': len(network_info.get('user_agent', '')),
            'source_noise_1': 0,
            'source_noise_2': 0,
            'dataset_source': 'RBA'
        }

        print(f"ML input features: {features_dict}")
        print(f"  🌍 Country: {country}, Frequency: {country_freq}, Unknown location: {features_dict['is_unknown_location']}")

        
        features_df = pd.DataFrame([features_dict])
        
        # ML prediction
        X_processed = self.preprocessor.transform(features_df)
        ml_proba = self.model.predict(X_processed, verbose=0)[0]
        ml_prediction = int(np.argmax(ml_proba))
        
        risk_names = ['Low Risk', 'Medium Risk', 'High Risk', 'Blocked']
        
        # FIRST LOGIN: Always allow to establish baseline
        if is_first_login:
            print(f"✓ FIRST LOGIN detected - Auto-allowing to establish baseline")
            print(f"  ML Prediction: {risk_names[ml_prediction]} (ignored for first login)")
            
            # Update profile and save
            profile.update_baseline(login_data, successful=True)
            self._save_profile(profile)
            
            return {
                'success': True,
                'action': 'ALLOW',
                'ml_prediction': risk_names[ml_prediction],
                'ml_confidence': {
                    'low': f"{ml_proba[0]:.1%}",
                    'medium': f"{ml_proba[1]:.1%}",
                    'high': f"{ml_proba[2]:.1%}"
                },
                'keystroke_deviation': 'N/A (First Login)',
                'overall_deviation': 'N/A (First Login)',
                'final_risk_level': 'Low Risk',
                'escalated': False,
                'flags': ['First login - establishing baseline'],
                'total_boost': 0,
                'behavioral_boost': 0,
                'network_boost': 0,
                'edns_boost': 0,
                'is_first_login': True
            }
        
        # ============================================================================
        # SUBSEQUENT LOGINS: Full security analysis
        # ============================================================================
        
        keystroke_dev = deviations['keystroke_deviation']
        behavioral_boost = 0
        
        # Keystroke deviation scoring
        if keystroke_dev > 0.50:      # >50% = Critical
            behavioral_boost = 3
            print(f"⚠️ Major typing deviation: {keystroke_dev:.1%}")
        elif keystroke_dev > 0.35:    # 35-50% = High
            behavioral_boost = 2
            print(f"⚠️ High typing deviation: {keystroke_dev:.1%}")
        elif keystroke_dev > 0.20:    # 20-35% = Moderate
            behavioral_boost = 1.5
            print(f"⚠️ Moderate typing deviation: {keystroke_dev:.1%}")
        elif keystroke_dev > 0.10:    # 10-20% = Minor
            behavioral_boost = 0.5
            print(f"⚠️ Minor typing deviation: {keystroke_dev:.1%}")
        else:
            behavioral_boost = 0
            print(f"✓ Typing pattern matches baseline ({keystroke_dev:.1%} deviation)")
        
        # Network anomaly detection (THIS IS KEY - it detects new devices!)
        network_flags, network_boost = profile._check_network_anomalies(network_info)
        
        ip = network_info.get('ip_address', '')
        test_ips = ['127.0.0.1', '::1', 'localhost', '0.0.0.0']
# Also check for private network ranges
        if ip in test_ips or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            edns_boost = 0
            network_flags, network_boost = [], 0
            print("✓ Local/private IP detected, suppressing EDNS/network boosts.")

        # Total risk boost
        total_boost = behavioral_boost + network_boost + edns_boost
        
        print(f"📊 Risk Calculation:")
        print(f"  Behavioral boost: {behavioral_boost}")
        print(f"  Network boost: {network_boost}")
        print(f"  EDNS boost: {edns_boost}")
        print(f"  Total boost: {total_boost}")
        
        # Calculate final risk with proper MFA zone
        user_has_authenticator = bool(getattr(profile, "mfa_enabled", False))  # Or from user db if easier

        if total_boost >= 4.0:
            if user_has_authenticator:
                final_risk = 2      # BLOCK-like, but your frontend can interpret as requiring TOTP
                print(f"🚫 Total boost {total_boost} >= 4.0 → Authenticator (TOTP) required")
            else:
                final_risk = 3      # Use 3 as a special code for BLOCK due to no MFA option
                print(f"🚫 Total boost {total_boost} >= 4.0, no authenticator → BLOCKED")
        elif total_boost >= 3.0:
            final_risk = 1          # MFA (email OTP)
            print(f"⚠️ Total boost {total_boost} >= 3.0 → Email OTP (MFA) required")
        else:
            final_risk = ml_prediction
            print(f"✓ Total boost {total_boost} < 3.0 → Use ML prediction")

        # BEHAVIORAL OVERRIDE - Only applies when boost is LOW
        if keystroke_dev <= 0.10:  # Within 10% - PERFECT match
            if total_boost >= 2:  # High flags - KEEP MFA
                final_risk = 1  # Require MFA despite good typing
                print(f"✓✓ Excellent typing ({keystroke_dev:.1%}), but suspicious context (boost={total_boost}) - MFA required")
            elif total_boost >= 1:  # Moderate flags - KEEP MFA  # ← FIXED: Lower threshold
                final_risk = 1  # ← FIXED: FORCE MFA
                print(f"✓ Good typing ({keystroke_dev:.1%}), moderate flags (boost={total_boost}) - MFA required")
            else:
                # Only allow when boost < 1 AND perfect typing
                final_risk = 0  # Truly safe
                print(f"✓✓ Excellent behavioral match ({keystroke_dev:.1%}) - Auto-approved")
                
        elif keystroke_dev <= 0.20:  # Within 20% - GOOD match
            # Good typing, but any boost requires MFA
            if total_boost >= 1:
                final_risk = 1  # Keep at MFA
                print(f"✓ Good behavioral match ({keystroke_dev:.1%}), but boost={total_boost} - MFA required")
            else:
                final_risk = min(final_risk, 1)  # Cap at Medium Risk
                print(f"✓ Good behavioral match ({keystroke_dev:.1%}) - Risk capped at Medium")

        
        # Map to action
        if final_risk == 3:
            action = 'BLOCK'
        elif final_risk == 2:
            action = 'TOTP'  # Could also be 'MFA' if you treat TOTP specially in frontend
        elif final_risk == 1:
            action = 'MFA'
        else:
            action = 'ALLOW'
        
        print(f"🎯 Final Decision: {action} (Risk Level: {risk_names[final_risk]})")
        
        # Update profile if allowed or MFA required
        if action in ['ALLOW', 'MFA']:
            profile.update_baseline(login_data, successful=True)
            self._save_profile(profile)
        
        return {
            'success': action in ['ALLOW', 'MFA'],
            'action': action,
            'ml_prediction': risk_names[ml_prediction],
            'ml_confidence': {
                'low': f"{ml_proba[0]:.1%}",
                'medium': f"{ml_proba[1]:.1%}",
                'high': f"{ml_proba[2]:.1%}"
            },
            'keystroke_deviation': f"{keystroke_dev:.1%}",
            'overall_deviation': f"{deviations['overall_deviation']:.1%}",
            'final_risk_level': risk_names[final_risk],
            'escalated': final_risk > ml_prediction,
            'flags': deviations['flags'] + network_flags,  # Include network flags
            'total_boost': total_boost,
            'behavioral_boost': behavioral_boost,
            'network_boost': network_boost,
            'edns_boost': edns_boost,
            'is_first_login': False
        }



    
    def get_user_profile(self, user_id):
        """Get user profile."""
        return self._load_profile(user_id)
    
    def _save_profile(self, profile):
        """Save profile to database."""
        if self.db:
            self.db.save_user_profile(profile.user_id, profile.to_dict())
        else:
            print(f"⚠️ No database manager provided, cannot save profile for {profile.user_id}")

    
    def _load_profile(self, user_id):
        """Load profile from database."""
        if not self.db:
            print(f"⚠️ No database manager provided, cannot load profile for {user_id}")
            return None
        
        profile_data = self.db.load_user_profile(user_id)
        
        if profile_data:
            return UserBehavioralProfile.from_dict(profile_data)
        else:
            print(f"⚠️ Profile not found in database for {user_id}")
            return None

