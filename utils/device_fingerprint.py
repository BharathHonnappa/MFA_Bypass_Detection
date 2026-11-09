import hashlib
from datetime import datetime

class DeviceFingerprint:
    """Device fingerprinting for session tracking"""
    
    def __init__(self):
        # Known device database (simulated)
        self.known_devices = {}
        self.device_history = []
    
    def generate_fingerprint(self, user_agent, accept_language, platform, screen_resolution=None, timezone=None):
        """Generate device fingerprint from browser characteristics"""
        components = [
            user_agent or '',
            accept_language or '',
            platform or '',
            screen_resolution or '',
            timezone or ''
        ]
        
        fingerprint_string = '|'.join(components)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        return {
            'hash': fingerprint_hash,
            'components': {
                'user_agent': user_agent,
                'accept_language': accept_language,
                'platform': platform,
                'screen_resolution': screen_resolution,
                'timezone': timezone
            },
            'created_at': datetime.now().isoformat()
        }
    
    def compare_fingerprints(self, fp1, fp2):
        """Compare two device fingerprints"""
        if not fp1 or not fp2:
            return {'match': False, 'similarity': 0, 'differences': ['missing_fingerprint']}
        
        differences = []
        match_count = 0
        total_fields = 0
        
        components1 = fp1.get('components', {}) if isinstance(fp1, dict) else {}
        components2 = fp2.get('components', {}) if isinstance(fp2, dict) else {}
        
        all_keys = set(list(components1.keys()) + list(components2.keys()))
        
        for key in all_keys:
            total_fields += 1
            if components1.get(key) == components2.get(key):
                match_count += 1
            else:
                differences.append(key)
        
        similarity = (match_count / total_fields * 100) if total_fields > 0 else 0
        
        return {
            'match': similarity == 100,
            'similarity': round(similarity, 2),
            'differences': differences,
            'is_new_device': similarity < 70
        }
    
    def is_known_device(self, user_id, fingerprint_hash):
        """Check if device is known for user"""
        if user_id not in self.known_devices:
            self.known_devices[user_id] = []
        
        return fingerprint_hash in self.known_devices[user_id]
    
    def register_device(self, user_id, fingerprint):
        """Register device for user"""
        if user_id not in self.known_devices:
            self.known_devices[user_id] = []
        
        if fingerprint['hash'] not in self.known_devices[user_id]:
            self.known_devices[user_id].append(fingerprint['hash'])
        
        self.device_history.append({
            'user_id': user_id,
            'fingerprint': fingerprint,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_user_devices(self, user_id):
        """Get all devices registered for user"""
        return self.known_devices.get(user_id, [])
    
    def detect_device_spoofing(self, fingerprint):
        """Detect potential device fingerprint spoofing"""
        spoofing_indicators = []
        
        components = fingerprint.get('components', {})
        
        # Check for inconsistent user agent
        ua = components.get('user_agent', '')
        platform = components.get('platform', '')
        
        if 'Windows' in ua and 'MacIntel' in platform:
            spoofing_indicators.append('platform_ua_mismatch')
        
        if 'iPhone' in ua and 'Win32' in platform:
            spoofing_indicators.append('mobile_desktop_mismatch')
        
        # Check for missing components
        if not ua or len(ua) < 10:
            spoofing_indicators.append('suspicious_user_agent')
        
        return {
            'is_spoofed': len(spoofing_indicators) > 0,
            'indicators': spoofing_indicators
        }
    
    def get_risk_score(self, user_id, current_fingerprint):
        """Calculate risk score based on device fingerprint"""
        risk = 0
        
        # Check if device is known
        if not self.is_known_device(user_id, current_fingerprint['hash']):
            risk += 30
            print(f"[DEVICE] New device detected for user {user_id}")
        
        # Check for spoofing
        spoof_check = self.detect_device_spoofing(current_fingerprint)
        if spoof_check['is_spoofed']:
            risk += 25
            print(f"[DEVICE] Spoofing detected: {spoof_check['indicators']}")
        
        return min(risk, 100)
