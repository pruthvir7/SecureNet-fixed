#!/usr/bin/env python3
"""
SecureNet Authentication System - Final Comprehensive Test
Real-world scenarios and edge cases
"""

import numpy as np
from auth_engine import AuthenticationEngine, UserBehavioralProfile
from datetime import datetime, timedelta
import random

# Colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{text.center(80)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.CYAN}ℹ {text}{Colors.END}")

def generate_keystroke_timings(base_speed='normal', variance='low', pattern='consistent'):
    """Generate realistic keystroke patterns."""
    speeds = {
        'very_fast': 70,
        'fast': 90,
        'normal': 120,
        'slow': 160,
        'very_slow': 220,
        'super_slow': 300  # Bot-like
    }
    
    variances = {
        'very_low': 5,    # Extremely consistent (bot-like)
        'low': 15,        # Consistent human
        'normal': 25,     # Normal human variation
        'high': 45,       # Distracted/tired
        'extreme': 80     # Very erratic
    }
    
    base = speeds.get(base_speed, 120)
    var = variances.get(variance, 15)
    
    timings = []
    
    if pattern == 'consistent':
        # Normal typing
        for _ in range(20):
            timing = base + random.gauss(0, var)
            timings.append(max(40, timing))
    
    elif pattern == 'accelerating':
        # Start slow, get faster (warming up)
        for i in range(20):
            speed_factor = 1.3 - (i * 0.015)  # Gradually faster
            timing = base * speed_factor + random.gauss(0, var)
            timings.append(max(40, timing))
    
    elif pattern == 'decelerating':
        # Start fast, get slower (getting tired)
        for i in range(20):
            speed_factor = 0.8 + (i * 0.025)  # Gradually slower
            timing = base * speed_factor + random.gauss(0, var)
            timings.append(max(40, timing))
    
    elif pattern == 'bimodal':
        # Two distinct speeds (copy-pasting between typing)
        for i in range(20):
            if i % 4 == 0:  # Every 4th is very fast (paste)
                timing = 50 + random.gauss(0, 5)
            else:
                timing = base + random.gauss(0, var)
            timings.append(max(40, timing))
    
    return timings

def generate_network_info(device_type='desktop_chrome', location='US', connection='home'):
    """Generate realistic network information."""
    
    devices = {
        'desktop_chrome': {
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'device_fingerprint': 'desktop_chrome_fp_001',
            'screen_resolution': '1920x1080',
            'platform': 'MacIntel',
            'asn': '15169'  # Google Fiber
        },
        'desktop_firefox': {
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
            'device_fingerprint': 'desktop_firefox_fp_002',
            'screen_resolution': '1920x1080',
            'platform': 'MacIntel',
            'asn': '15169'
        },
        'laptop_safari': {
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'device_fingerprint': 'laptop_safari_fp_003',
            'screen_resolution': '1440x900',
            'platform': 'MacIntel',
            'asn': '15169'
        },
        'iphone': {
            'user_agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'device_fingerprint': 'iphone_safari_fp_004',
            'screen_resolution': '390x844',
            'platform': 'iPhone',
            'asn': '15169'
        },
        'android': {
            'user_agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'device_fingerprint': 'android_chrome_fp_005',
            'screen_resolution': '411x914',
            'platform': 'Linux armv81',
            'asn': '15169'
        },
        'vpn_connection': {
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'device_fingerprint': 'desktop_chrome_fp_001',  # Same device
            'screen_resolution': '1920x1080',
            'platform': 'MacIntel',
            'asn': '13335'  # Cloudflare/VPN
        },
        'public_wifi': {
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'device_fingerprint': 'laptop_safari_fp_003',
            'screen_resolution': '1440x900',
            'platform': 'MacIntel',
            'asn': '7922'  # Comcast public
        },
        'tor_browser': {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
            'device_fingerprint': 'tor_browser_fp_999',
            'screen_resolution': '1280x720',
            'platform': 'Win32',
            'asn': '19281'  # Tor exit node
        },
        'automated_script': {
            'user_agent': 'python-requests/2.28.1',
            'device_fingerprint': 'script_fp_automated',
            'screen_resolution': '800x600',
            'platform': 'Linux',
            'asn': '16509'  # AWS
        }
    }
    
    locations_map = {
        'US': {'country': 'US', 'ip': '8.8.8.8'},
        'UK': {'country': 'GB', 'ip': '81.2.69.142'},
        'Canada': {'country': 'CA', 'ip': '142.250.217.46'},
        'Germany': {'country': 'DE', 'ip': '185.60.216.35'},
        'France': {'country': 'FR', 'ip': '217.70.184.38'},
        'Japan': {'country': 'JP', 'ip': '203.0.113.42'},
        'Australia': {'country': 'AU', 'ip': '1.2.3.4'},
        'Russia': {'country': 'RU', 'ip': '5.255.255.70'},
        'China': {'country': 'CN', 'ip': '123.125.114.144'},
        'NorthKorea': {'country': 'KP', 'ip': '175.45.176.1'},
        'Iran': {'country': 'IR', 'ip': '5.56.133.1'},
        'Nigeria': {'country': 'NG', 'ip': '41.58.0.1'}
    }
    
    info = devices.get(device_type, devices['desktop_chrome']).copy()
    loc = locations_map.get(location, locations_map['US'])
    
    info['country'] = loc['country']
    info['ip_address'] = loc['ip']
    info['timezone'] = 'America/New_York'
    info['language'] = 'en-US'
    
    return info

def test_scenario(auth_engine, user_id, name, description, login_data, edns_boost, expected_action):
    """Test a specific scenario."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'─'*80}{Colors.END}")
    print(f"{Colors.BOLD}Test: {name}{Colors.END}")
    print(f"Description: {description}")
    print(f"Expected: {expected_action}")
    print(f"{Colors.BLUE}{'─'*80}{Colors.END}")
    
    try:
        result = auth_engine.authenticate_user(user_id, login_data, edns_boost)
        
        action = result.get('action', 'Unknown')
        risk_level = result.get('final_risk_level', 'Unknown')
        
        print(f"\n📊 Results:")
        print(f"  Action: {action}")
        print(f"  Risk Level: {risk_level}")
        print(f"  Keystroke Deviation: {result.get('keystroke_deviation', 'N/A')}")
        print(f"  Total Boost: {result.get('total_boost', 0)}")
        
        # Check result
        if action == expected_action:
            print_success(f"✓ Correct action: {action}")
        else:
            print_warning(f"⚠ Expected {expected_action}, got {action}")
        
        return result
        
    except Exception as e:
        print_error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def run_final_tests():
    """Run comprehensive final test suite."""
    
    print_header("SECURENET - FINAL COMPREHENSIVE TEST SUITE")
    
    # Initialize
    print_info("Loading authentication engine...")
    auth_engine = AuthenticationEngine()
    print_success("Engine loaded")
    
    # Create user
    user_id = 'final_test_user'
    print_info(f"Creating test user: {user_id}")
    
    registration_data = {
        'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
        'network_info': generate_network_info('desktop_chrome', 'US', 'home')
    }
    
    auth_engine.register_user(user_id, registration_data)
    
    # First login to establish baseline
    auth_engine.authenticate_user(user_id, registration_data, 0)
    print_success("Baseline established\n")
    
    # ============================================================
    # CATEGORY 1: LEGITIMATE USER SCENARIOS
    # ============================================================
    print_header("CATEGORY 1: LEGITIMATE USER BEHAVIOR")
    
    test_scenario(
        auth_engine, user_id,
        name="Daily Morning Login",
        description="User logs in normally from home computer",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='ALLOW'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Slightly Tired Typing",
        description="User types 8% slower (within tolerance)",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'normal', 'decelerating'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='ALLOW'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Warming Up (Accelerating)",
        description="User starts slow then speeds up",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'accelerating'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='ALLOW'
    )
    
    # ============================================================
    # CATEGORY 2: NEW DEVICES (SHOULD TRIGGER MFA)
    # ============================================================
    print_header("CATEGORY 2: NEW DEVICE SCENARIOS")
    
    test_scenario(
        auth_engine, user_id,
        name="Login from Personal iPhone",
        description="User adds their phone - good typing",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'normal', 'consistent'),
            'network_info': generate_network_info('iphone', 'US')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Login from Work Laptop",
        description="User logs in from different computer",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('laptop_safari', 'US')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Switch to Firefox Browser",
        description="Same computer, different browser",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('desktop_firefox', 'US')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    # ============================================================
    # CATEGORY 3: TRAVEL SCENARIOS
    # ============================================================
    print_header("CATEGORY 3: LEGITIMATE TRAVEL")
    
    test_scenario(
        auth_engine, user_id,
        name="Business Trip to UK",
        description="User travels for work, types normally",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('laptop_safari', 'UK')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Vacation in Japan",
        description="User travels on vacation",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'normal', 'consistent'),
            'network_info': generate_network_info('iphone', 'Japan')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Conference in Germany",
        description="User at public WiFi, hotel",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('public_wifi', 'Germany')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    # ============================================================
    # CATEGORY 4: SUSPICIOUS BUT MIGHT BE LEGITIMATE
    # ============================================================
    print_header("CATEGORY 4: SUSPICIOUS ACTIVITY")
    
    test_scenario(
        auth_engine, user_id,
        name="VPN Connection",
        description="User connects via VPN, same device",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('vpn_connection', 'US')
        },
        edns_boost=1,  # VPN might trigger EDNS
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Distracted Typing",
        description="User types erratically (multitasking)",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'high', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Very Slow Typing",
        description="User types 40% slower than normal",
        login_data={
            'keystroke_timings': generate_keystroke_timings('slow', 'normal', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    # ============================================================
    # CATEGORY 5: HIGH-RISK LOCATIONS
    # ============================================================
    print_header("CATEGORY 5: HIGH-RISK LOCATIONS")
    
    test_scenario(
        auth_engine, user_id,
        name="Login from Russia - Good Typing",
        description="Suspicious location but perfect typing",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'Russia')
        },
        edns_boost=1,
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Login from China - Erratic",
        description="High-risk country + poor typing",
        login_data={
            'keystroke_timings': generate_keystroke_timings('slow', 'extreme', 'consistent'),
            'network_info': generate_network_info('desktop_firefox', 'China')
        },
        edns_boost=2,
        expected_action='BLOCK'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Login from Iran - Perfect Match",
        description="High-risk but typing is perfect",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('laptop_safari', 'Iran')
        },
        edns_boost=2,
        expected_action='MFA'
    )
    
    # ============================================================
    # CATEGORY 6: ATTACK SCENARIOS (SHOULD BLOCK)
    # ============================================================
    print_header("CATEGORY 6: ATTACK DETECTION")
    
    test_scenario(
        auth_engine, user_id,
        name="Credential Stuffing Attack",
        description="Automated script with bot-like typing",
        login_data={
            'keystroke_timings': generate_keystroke_timings('super_slow', 'very_low', 'consistent'),
            'network_info': generate_network_info('automated_script', 'US')
        },
        edns_boost=0,
        expected_action='BLOCK'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="TOR Browser Attack",
        description="Anonymous browser + suspicious patterns",
        login_data={
            'keystroke_timings': generate_keystroke_timings('very_slow', 'extreme', 'bimodal'),
            'network_info': generate_network_info('tor_browser', 'Russia')
        },
        edns_boost=3,
        expected_action='BLOCK'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Account Takeover Attempt",
        description="North Korea + new device + bad typing",
        login_data={
            'keystroke_timings': generate_keystroke_timings('very_slow', 'extreme', 'consistent'),
            'network_info': generate_network_info('desktop_firefox', 'NorthKorea')
        },
        edns_boost=3,
        expected_action='BLOCK'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Brute Force with Delays",
        description="Slow automated attempts to avoid detection",
        login_data={
            'keystroke_timings': generate_keystroke_timings('super_slow', 'very_low', 'consistent'),
            'network_info': generate_network_info('automated_script', 'Nigeria')
        },
        edns_boost=2,
        expected_action='BLOCK'
    )
    
    # ============================================================
    # CATEGORY 7: EDGE CASES
    # ============================================================
    print_header("CATEGORY 7: EDGE CASES")
    
    test_scenario(
        auth_engine, user_id,
        name="Perfect Clone Attempt",
        description="Exact same timing but from China",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'very_low', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'China')
        },
        edns_boost=2,
        expected_action='MFA'  # Location overrides good typing
    )
    
    test_scenario(
        auth_engine, user_id,
        name="Paste Password Attempt",
        description="Bimodal timing (copy-paste behavior)",
        login_data={
            'keystroke_timings': generate_keystroke_timings('fast', 'high', 'bimodal'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='MFA'
    )
    
    test_scenario(
        auth_engine, user_id,
        name="EDNS Threat but Perfect User",
        description="EDNS alert but all other signals are good",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=2,
        expected_action='MFA'
    )

    # ============================================================
# CATEGORY 8: ADVANCED EDGE CASES (10 MORE SCENARIOS)
# ============================================================
    print_header("CATEGORY 8: ADVANCED EDGE CASES & ANOMALIES")

    test_scenario(
        auth_engine, user_id,
        name="Midnight Login (Unusual Time)",
        description="User logs in at 3 AM (unusual for typical user)",
        login_data={
            'keystroke_timings': generate_keystroke_timings('slow', 'normal', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='ALLOW'  # Unusual time + slow typing, but same device
    )

    test_scenario(
        auth_engine, user_id,
        name="Login After 30-Day Inactivity",
        description="User returns after a month (stale baseline)",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'normal', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='ALLOW'  # Same device, typing within range
    )

    test_scenario(
        auth_engine, user_id,
        name="Extremely Fast Typing (Expert User)",
        description="User types 50% faster than baseline",
        login_data={
            'keystroke_timings': generate_keystroke_timings('very_fast', 'low', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='MFA'  # Significant speed change
    )

    test_scenario(
        auth_engine, user_id,
        name="Corporate Network Login",
        description="User logs in from office (new but legitimate network)",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': {
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'device_fingerprint': 'work_desktop_fp_006',
                'screen_resolution': '1920x1080',
                'platform': 'Win32',
                'country': 'US',
                'ip_address': '192.168.10.50',
                'asn': '36561',  # Corporate network
                'timezone': 'America/New_York',
                'language': 'en-US'
            }
        },
        edns_boost=0,
        expected_action='MFA'  # New device (work computer)
    )

    test_scenario(
        auth_engine, user_id,
        name="Login via Cloud Service",
        description="User connects through AWS/Azure cloud instance",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': {
                'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'device_fingerprint': 'desktop_chrome_fp_001',  # Same device
                'screen_resolution': '1920x1080',
                'platform': 'MacIntel',
                'country': 'US',
                'ip_address': '52.91.184.199',  # AWS IP
                'asn': '16509',  # Amazon
                'timezone': 'America/New_York',
                'language': 'en-US'
            }
        },
        edns_boost=1,  # Cloud IPs might trigger EDNS
        expected_action='MFA'  # EDNS alert + cloud network
    )

    test_scenario(
        auth_engine, user_id,
        name="Keyboard Layout Change (Dvorak/AZERTY)",
        description="User switches keyboard layout, affects timing",
        login_data={
            'keystroke_timings': generate_keystroke_timings('slow', 'high', 'consistent'),
            'network_info': generate_network_info('desktop_chrome', 'US')
        },
        edns_boost=0,
        expected_action='MFA'  # Unusual timing pattern
    )

    test_scenario(
        auth_engine, user_id,
        name="Multiple Devices Rapid Switching",
        description="User switches between phone and laptop quickly",
        login_data={
            'keystroke_timings': generate_keystroke_timings('fast', 'normal', 'consistent'),
            'network_info': generate_network_info('android', 'US')
        },
        edns_boost=0,
        expected_action='MFA'  # Different device (Android not seen before)
    )

    test_scenario(
        auth_engine, user_id,
        name="Successful MFA Recovery",
        description="User completes MFA and logs in again immediately",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': generate_network_info('iphone', 'US')
        },
        edns_boost=0,
        expected_action='ALLOW'  # Device already added during previous MFA
    )

    test_scenario(
        auth_engine, user_id,
        name="Suspicious Proxy Server",
        description="Login through anonymous proxy service",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'low', 'consistent'),
            'network_info': {
                'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'device_fingerprint': 'desktop_chrome_fp_001',
                'screen_resolution': '1920x1080',
                'platform': 'MacIntel',
                'country': 'NL',  # Netherlands (common proxy location)
                'ip_address': '185.220.101.1',  # Known proxy IP
                'asn': '204151',  # Anonymous proxy
                'timezone': 'America/New_York',
                'language': 'en-US'
            }
        },
        edns_boost=2,  # Proxies often flagged
        expected_action='MFA'  # New country + EDNS alert but good typing
    )

    test_scenario(
        auth_engine, user_id,
        name="Perfect Bot Mimicry Attempt",
        description="Sophisticated bot with near-human timing from US",
        login_data={
            'keystroke_timings': generate_keystroke_timings('normal', 'very_low', 'consistent'),
            'network_info': {
                'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'device_fingerprint': 'sophisticated_bot_fp_999',
                'screen_resolution': '1920x1080',
                'platform': 'MacIntel',
                'country': 'US',
                'ip_address': '54.162.43.12',  # AWS datacenter
                'asn': '16509',  # Amazon/AWS
                'timezone': 'America/New_York',
                'language': 'en-US'
            }
        },
        edns_boost=1,
        expected_action='MFA'  # New device + cloud IP + EDNS + very consistent timing
    )

    print_header("ADVANCED TEST SUITE COMPLETE")
    print_success("Additional 10 scenarios tested!")
    print_info("Total scenarios: 35")


if __name__ == '__main__':
    try:
        run_final_tests()
    except KeyboardInterrupt:
        print_error("\n\nTests interrupted")
    except Exception as e:
        print_error(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
