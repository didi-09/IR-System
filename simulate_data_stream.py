
import time
import random
import threading
from datetime import datetime
import sys
import os
import math

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'server_backend')))

try:
    from models import Session, SSHEvent, PingMetrics, TrafficStats, Incident
except ImportError:
    # Try alternate path if running from root
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'IR-System/server_backend')))
    from models import Session, SSHEvent, PingMetrics, TrafficStats, Incident

def simulate_ssh():
    users = ['root', 'admin', 'user', 'guest', 'kali', 'service_account', 'postgres']
    ips = ['192.168.1.5', '192.168.1.10', '10.0.0.55', '172.16.5.9', '203.0.113.4', '45.33.22.11']
    
    session = Session()
    try:
        while True:
            # 30% success rate
            is_success = random.random() > 0.7 
            user = random.choice(users)
            ip = random.choice(ips)
            
            event = SSHEvent(
                timestamp=datetime.utcnow(),
                source_ip=ip,
                username=user,
                event_type='SUCCESS' if is_success else 'FAILURE',
                auth_method='password',
                port=22
            )
            session.add(event)
            session.commit()
            print(f"🔑 SSH: {event.event_type} - {user}@{ip}")
            
            time.sleep(random.uniform(1.0, 4.0))
    except Exception as e:
        print(f"SSH Sim Error: {e}")
    finally:
        session.close()

def simulate_ping():
    targets = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
    session = Session()
    try:
        while True:
            for target in targets:
                # Simulate latency with some jitter
                base_latency = 15.0 if target == "8.8.8.8" else (12.0 if target == "1.1.1.1" else 2.0)
                latency = base_latency + random.uniform(-2.0, 10.0)
                
                # Occasional spike
                if random.random() > 0.95:
                    latency += 50.0
                
                metric = PingMetrics(
                    target_ip=target,
                    latency_ms=round(latency, 2),
                    packet_loss_pct=0.0,
                    status='Up',
                    timestamp=datetime.utcnow()
                )
                session.add(metric)
            
            session.commit()
            # print("📶 Ping metrics updated")
            time.sleep(5)
    except Exception as e:
        print(f"Ping Sim Error: {e}")
    finally:
        session.close()

def simulate_traffic():
    session = Session()
    t = 0
    try:
        while True:
            # Use sine wave to create nice charts
            t += 0.5
            pps_in = abs(math.sin(t) * 500) + random.uniform(50, 100)
            pps_out = abs(math.cos(t) * 400) + random.uniform(30, 80)
            
            # Simulate DoS spike occasionally
            dos_score = 0.0
            if random.random() > 0.95:
                pps_in += 2000
                dos_score = 0.85
                print("⚠️  Simulated DoS Spike!")
            
            stats = TrafficStats(
                packet_count_in=int(pps_in),
                packet_count_out=int(pps_out),
                byte_count_in=int(pps_in * 120),
                byte_count_out=int(pps_out * 100),
                cpu_load=round(random.uniform(10.0, 40.0) + (dos_score * 40), 1),
                dos_likelihood_score=dos_score,
                timestamp=datetime.utcnow()
            )
            session.add(stats)
            session.commit()
            # print(f"📡 Traffic: {int(pps_in)} PPS")
            
            time.sleep(2)
    except Exception as e:
        print(f"Traffic Sim Error: {e}")
    finally:
        session.close()

def simulate_incidents():
    severities = ['Low', 'Medium', 'High', 'Critical']
    types = ['Brute Force', 'Malware', 'Data Exfiltration', 'DoS', 'Phishing']
    
    # Import threat intelligence
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'server_backend'))
        from threat_intel import get_threat_intel
        threat_intel = get_threat_intel()
        threat_intel_available = True
        print("✅ Threat Intelligence enabled for simulation")
    except Exception as e:
        threat_intel_available = False
        print(f"⚠️  Threat Intelligence not available for simulation: {e}")
    
    session = Session()
    try:
        while True:
            # Generate incident every 2-8 seconds (Faster for demo)
            time.sleep(random.uniform(2, 8))
            
            ip_address = f"192.168.1.{random.randint(20, 200)}"
            
            # Enrich with threat intelligence
            threat_data = {}
            if threat_intel_available:
                try:
                    threat_data = threat_intel.enrich_ip(ip_address)
                except Exception as e:
                    print(f"Warning: Threat intel enrichment failed: {e}")
            
            inc = Incident(
                ip=ip_address,
                type=random.choice(types),
                severity=random.choice(severities),
                timestamp=datetime.utcnow(),
                rule=f"Rule_{random.randint(100, 999)}",
                source_log="/var/log/auth.log",
                target=f"user_{random.randint(1, 10)}",
                status="Active",
                # Add threat intelligence fields
                geo_country=threat_data.get('geoip', {}).get('country'),
                geo_country_code=threat_data.get('geoip', {}).get('country_code'),
                geo_city=threat_data.get('geoip', {}).get('city'),
                geo_region=threat_data.get('geoip', {}).get('region'),
                geo_lat=str(threat_data.get('geoip', {}).get('lat', '')),
                geo_lon=str(threat_data.get('geoip', {}).get('lon', '')),
                geo_isp=threat_data.get('geoip', {}).get('isp'),
                geo_org=threat_data.get('geoip', {}).get('org'),
                is_proxy=str(threat_data.get('geoip', {}).get('is_proxy', False)),
                is_hosting=str(threat_data.get('geoip', {}).get('is_hosting', False)),
                abuse_confidence_score=threat_data.get('abuseipdb', {}).get('abuse_confidence_score'),
                abuse_total_reports=threat_data.get('abuseipdb', {}).get('total_reports'),
                threat_risk_score=threat_data.get('risk_score'),
                threat_risk_level=threat_data.get('risk_level')
            )
            session.add(inc)
            session.commit()
            print(f"🚨 New Simulation Incident: {inc.type} ({inc.severity}) - Risk: {inc.threat_risk_level}")
            
    except Exception as e:
        print(f"Incident Sim Error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    print("🚀 Starting Network Data Simulation (Demo Mode)...")
    print("Press Ctrl+C to stop.")
    
    t1 = threading.Thread(target=simulate_ssh)
    t2 = threading.Thread(target=simulate_ping)
    t3 = threading.Thread(target=simulate_traffic)
    t4 = threading.Thread(target=simulate_incidents)
    
    t1.daemon = True
    t2.daemon = True
    t3.daemon = True
    t4.daemon = True
    
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Simulation stopped.")
