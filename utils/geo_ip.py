import hashlib
from datetime import datetime

class GeoIP:
    """Simulated GeoIP lookup for demo purposes"""
    
    def __init__(self):
        # Simulated geo database
        self.geo_data = {
            '127.0.0.1': {
                'city': 'Localhost',
                'country': 'Local',
                'country_code': 'LO',
                'latitude': 0,
                'longitude': 0,
                'timezone': 'UTC',
                'isp': 'Loopback',
                'asn': 'N/A'
            },
            '192.168.1.1': {
                'city': 'New York',
                'country': 'United States',
                'country_code': 'US',
                'latitude': 40.7128,
                'longitude': -74.0060,
                'timezone': 'America/New_York',
                'isp': 'Verizon',
                'asn': 'AS701'
            },
            '10.0.0.1': {
                'city': 'London',
                'country': 'United Kingdom',
                'country_code': 'GB',
                'latitude': 51.5074,
                'longitude': -0.1278,
                'timezone': 'Europe/London',
                'isp': 'Vodafone',
                'asn': 'AS25135'
            },
            '172.16.0.1': {
                'city': 'Tokyo',
                'country': 'Japan',
                'country_code': 'JP',
                'latitude': 35.6762,
                'longitude': 139.6503,
                'timezone': 'Asia/Tokyo',
                'isp': 'NTT Docomo',
                'asn': 'AS9605'
            },
            '192.168.100.1': {
                'city': 'Moscow',
                'country': 'Russia',
                'country_code': 'RU',
                'latitude': 55.7558,
                'longitude': 37.6173,
                'timezone': 'Europe/Moscow',
                'isp': 'MTS',
                'asn': 'AS8359'
            },
            '10.10.10.1': {
                'city': 'Mumbai',
                'country': 'India',
                'country_code': 'IN',
                'latitude': 19.0760,
                'longitude': 72.8777,
                'timezone': 'Asia/Kolkata',
                'isp': 'Jio',
                'asn': 'AS55836'
            },
            '172.20.0.1': {
                'city': 'Sydney',
                'country': 'Australia',
                'country_code': 'AU',
                'latitude': -33.8688,
                'longitude': 151.2093,
                'timezone': 'Australia/Sydney',
                'isp': 'Telstra',
                'asn': 'AS1221'
            }
        }
        
        # Suspicious IP ranges
        self.vpn_ips = ['10.0.0.1', '172.16.0.1']
        self.tor_ips = ['1.2.3.4', '5.6.7.8']
        self.datacenter_ips = ['8.8.8.8', '1.1.1.1']
    
    def lookup(self, ip_address):
        """Get geo data for IP address"""
        if ip_address in self.geo_data:
            return self.geo_data[ip_address]
        
        # Generate random location for unknown IPs
        return self._generate_random_location(ip_address)
    
    def _generate_random_location(self, ip_address):
        """Generate random location data for demo"""
        cities = [
            {'city': 'Paris', 'country': 'France', 'country_code': 'FR', 'lat': 48.8566, 'lon': 2.3522},
            {'city': 'Berlin', 'country': 'Germany', 'country_code': 'DE', 'lat': 52.5200, 'lon': 13.4050},
            {'city': 'Dubai', 'country': 'UAE', 'country_code': 'AE', 'lat': 25.2048, 'lon': 55.2708},
            {'city': 'Singapore', 'country': 'Singapore', 'country_code': 'SG', 'lat': 1.3521, 'lon': 103.8198},
            {'city': 'Toronto', 'country': 'Canada', 'country_code': 'CA', 'lat': 43.6532, 'lon': -79.3832},
        ]
        
        digest = hashlib.sha256(ip_address.encode()).hexdigest()
        city = cities[int(digest[:2], 16) % len(cities)]
        isps = ['Comcast', 'AT&T', 'Deutsche Telekom', 'Orange', 'Airtel']
        isp = isps[int(digest[2:4], 16) % len(isps)]
        asn = 1000 + (int(digest[4:8], 16) % 9000)

        return {
            'city': city['city'],
            'country': city['country'],
            'country_code': city['country_code'],
            'latitude': city['lat'],
            'longitude': city['lon'],
            'timezone': f'Timezone/{city["city"]}',
            'isp': isp,
            'asn': f'AS{asn}'
        }
    
    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """Calculate distance between two coordinates using Haversine formula"""
        import math
        
        R = 6371  # Earth's radius in km
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = (math.sin(delta_lat / 2) ** 2 + 
             math.cos(lat1_rad) * math.cos(lat2_rad) * 
             math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c
    
    def calculate_velocity(self, lat1, lon1, time1, lat2, lon2, time2):
        """Calculate travel velocity in km/h"""
        distance = self.calculate_distance(lat1, lon1, lat2, lon2)
        
        if isinstance(time1, str):
            time1 = datetime.fromisoformat(time1)
        if isinstance(time2, str):
            time2 = datetime.fromisoformat(time2)
        
        time_diff_hours = abs((time2 - time1).total_seconds()) / 3600
        
        if time_diff_hours == 0:
            return 0 if distance == 0 else float('inf')
        
        return distance / time_diff_hours
    
    def is_vpn(self, ip_address):
        """Check if IP is from VPN"""
        return ip_address in self.vpn_ips
    
    def is_tor(self, ip_address):
        """Check if IP is from Tor network"""
        return ip_address in self.tor_ips
    
    def is_datacenter(self, ip_address):
        """Check if IP is from datacenter/hosting"""
        return ip_address in self.datacenter_ips
    
    def is_suspicious(self, ip_address):
        """Check if IP is suspicious (VPN, Tor, or datacenter)"""
        return self.is_vpn(ip_address) or self.is_tor(ip_address) or self.is_datacenter(ip_address)
