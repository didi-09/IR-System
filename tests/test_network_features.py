
import sys
import os
import time
import threading
from datetime import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server_backend.models import Session, PingMetrics, SSHEvent, TrafficStats
from detection_engine.network_monitor import PingMonitor, TrafficMonitor
from detection_engine.detection_agent import DetectionAgent

def test_ping_monitor():
    print("Testing PingMonitor...")
    # Use localhost for fast ping
    monitor = PingMonitor(targets=["127.0.0.1"], interval=1)
    monitor.start()
    time.sleep(3)
    monitor.stop()
    monitor.join()
    
    session = Session()
    metrics = session.query(PingMetrics).filter(PingMetrics.target_ip == "127.0.0.1").all()
    session.close()
    
    if len(metrics) > 0:
        print(f"✅ PingMonitor success: Captured {len(metrics)} metrics for 127.0.0.1")
        print(f"   Last latency: {metrics[-1].latency_ms}ms, Status: {metrics[-1].status}")
    else:
        print("❌ PingMonitor failed: No metrics found")

def test_traffic_monitor():
    print("\nTesting TrafficMonitor...")
    monitor = TrafficMonitor(interval=1)
    monitor.start()
    time.sleep(3)
    monitor.stop()
    monitor.join()
    
    session = Session()
    stats = session.query(TrafficStats).order_by(TrafficStats.timestamp.desc()).limit(5).all()
    session.close()
    
    if len(stats) > 0:
        print(f"✅ TrafficMonitor success: Captured {len(stats)} stats records")
        print(f"   Last entry - In: {stats[0].packet_count_in} PPS, Out: {stats[0].packet_count_out} PPS, DoS Score: {stats[0].dos_likelihood_score}")
    else:
        print("❌ TrafficMonitor failed: No stats found")

def test_ssh_event_logging():
    print("\nTesting SSH Event Logging...")
    agent = DetectionAgent(simulation_mode=True)
    
    # Simulate a successful login event
    test_event = {
        'timestamp': datetime.utcnow(),
        'ip': '192.168.1.50',
        'target': 'test_admin',
        'type': 'successful_login',
        'port': 2222
    }
    
    agent.save_ssh_event(test_event)
    
    session = Session()
    event = session.query(SSHEvent).filter(SSHEvent.username == 'test_admin').first()
    session.close()
    
    if event:
        print(f"✅ SSH Event Logging success: Found event for user '{event.username}'")
        print(f"   Type: {event.event_type}, IP: {event.source_ip}")
    else:
        print("❌ SSH Event Logging failed: Event not found in DB")

if __name__ == "__main__":
    print("Starting Network Features Verification...")
    print("=" * 50)
    
    try:
        test_ping_monitor()
        test_traffic_monitor()
        test_ssh_event_logging()
    except Exception as e:
        print(f"❌ Test crashed: {e}")
    
    print("=" * 50)
    print("Verification complete.")
