"""
Threat Intelligence Module
Enriches incidents with external threat intelligence data.
"""
import requests
import requests_cache
import os
from typing import Dict, Optional
from datetime import timedelta

# Enable caching to avoid hitting rate limits
requests_cache.install_cache(
    'threat_intel_cache',
    backend='sqlite',
    expire_after=timedelta(hours=24)
)

class ThreatIntelligence:
    """Threat intelligence enrichment using multiple sources."""
    
    def __init__(self, abuseipdb_key: Optional[str] = None):
        """
        Initialize threat intelligence.
        
        Args:
            abuseipdb_key: AbuseIPDB API key (optional, from env or config)
        """
        self.abuseipdb_key = abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY')
        self.abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
        
    def check_abuseipdb(self, ip_address: str) -> Dict:
        """
        Check IP reputation using AbuseIPDB.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with reputation data
        """
        if not self.abuseipdb_key:
            return {
                'available': False,
                'error': 'No API key configured'
            }
        
        try:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = requests.get(
                self.abuseipdb_url,
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'available': True,
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country_code': data.get('countryCode'),
                    'usage_type': data.get('usageType'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported_at': data.get('lastReportedAt'),
                    'is_public': data.get('isPublic', True),
                    'is_tor': data.get('isTor', False)
                }
            else:
                return {
                    'available': False,
                    'error': f'API returned {response.status_code}'
                }
                
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }
    
    def get_geoip_info(self, ip_address: str) -> Dict:
        """
        Get geographic information for an IP using free API.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dictionary with geo data
        """
        try:
            # Using ip-api.com (free, no key required, 45 req/min limit)
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'available': True,
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'is_mobile': data.get('mobile', False),
                        'is_proxy': data.get('proxy', False),
                        'is_hosting': data.get('hosting', False)
                    }
                else:
                    return {
                        'available': False,
                        'error': data.get('message', 'Unknown error')
                    }
            else:
                return {
                    'available': False,
                    'error': f'API returned {response.status_code}'
                }
                
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }
    
    def enrich_ip(self, ip_address: str) -> Dict:
        """
        Enrich IP with all available threat intelligence.
        
        Args:
            ip_address: IP address to enrich
            
        Returns:
            Combined threat intelligence data
        """
        enrichment = {
            'ip': ip_address,
            'abuseipdb': {},
            'geoip': {},
            'risk_score': 0,
            'risk_level': 'Unknown'
        }
        
        # Check if IP is private/internal (RFC 1918)
        is_private = (
            ip_address.startswith('192.168.') or
            ip_address.startswith('10.') or
            ip_address.startswith('172.16.') or
            ip_address.startswith('172.17.') or
            ip_address.startswith('172.18.') or
            ip_address.startswith('172.19.') or
            ip_address.startswith('172.20.') or
            ip_address.startswith('172.21.') or
            ip_address.startswith('172.22.') or
            ip_address.startswith('172.23.') or
            ip_address.startswith('172.24.') or
            ip_address.startswith('172.25.') or
            ip_address.startswith('172.26.') or
            ip_address.startswith('172.27.') or
            ip_address.startswith('172.28.') or
            ip_address.startswith('172.29.') or
            ip_address.startswith('172.30.') or
            ip_address.startswith('172.31.') or
            ip_address.startswith('127.') or
            ip_address == 'localhost'
        )
        
        # If private IP, assign default low risk and skip external lookups
        if is_private:
            enrichment['risk_score'] = 5
            enrichment['risk_level'] = 'Low'
            enrichment['geoip'] = {
                'available': False,
                'error': 'Private/Internal IP - not publicly routable'
            }
            enrichment['abuseipdb'] = {
                'available': False,
                'error': 'Private/Internal IP - cannot query external database'
            }
            return enrichment
        
        # Get GeoIP data (always available for public IPs, no key needed)
        geo_data = self.get_geoip_info(ip_address)
        enrichment['geoip'] = geo_data
        
        # Get AbuseIPDB data (if API key available)
        if self.abuseipdb_key:
            abuse_data = self.check_abuseipdb(ip_address)
            enrichment['abuseipdb'] = abuse_data
            
            # Calculate risk score
            if abuse_data.get('available'):
                confidence = abuse_data.get('abuse_confidence_score', 0)
                enrichment['risk_score'] = confidence
                
                # Determine risk level
                if confidence >= 75:
                    enrichment['risk_level'] = 'Critical'
                elif confidence >= 50:
                    enrichment['risk_level'] = 'High'
                elif confidence >= 25:
                    enrichment['risk_level'] = 'Medium'
                else:
                    enrichment['risk_level'] = 'Low'
        else:
            # Use GeoIP proxy/hosting indicators as fallback
            if geo_data.get('available'):
                if geo_data.get('is_proxy') or geo_data.get('is_hosting'):
                    enrichment['risk_score'] = 50
                    enrichment['risk_level'] = 'Medium'
                else:
                    enrichment['risk_score'] = 10
                    enrichment['risk_level'] = 'Low'
        
        return enrichment


def get_threat_intel() -> ThreatIntelligence:
    """Get configured threat intelligence instance."""
    return ThreatIntelligence()


if __name__ == '__main__':
    # Test the module
    intel = get_threat_intel()
    
    # Test with a known malicious IP (example)
    test_ip = '8.8.8.8'  # Google DNS (safe)
    print(f"Testing threat intelligence for {test_ip}...")
    
    result = intel.enrich_ip(test_ip)
    
    print(f"\nGeoIP Data:")
    if result['geoip'].get('available'):
        print(f"  Country: {result['geoip'].get('country')}")
        print(f"  City: {result['geoip'].get('city')}")
        print(f"  ISP: {result['geoip'].get('isp')}")
        print(f"  Proxy: {result['geoip'].get('is_proxy')}")
    
    print(f"\nAbuseIPDB Data:")
    if result['abuseipdb'].get('available'):
        print(f"  Confidence Score: {result['abuseipdb'].get('abuse_confidence_score')}%")
        print(f"  Total Reports: {result['abuseipdb'].get('total_reports')}")
    else:
        print(f"  Not available: {result['abuseipdb'].get('error')}")
    
    print(f"\nRisk Assessment:")
    print(f"  Risk Score: {result['risk_score']}")
    print(f"  Risk Level: {result['risk_level']}")
