
import threading
import time
import subprocess
import re
import platform
import sys
import os
from datetime import datetime

# Ensure we can import from server_backend
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server_backend')))

try:
    from models import Session, PingMetrics, TrafficStats
except ImportError:
    # Fallback if path appending didn't work as expected or for testing
    print("Warning: Could not import models. Database storage will be disabled.")
    Session = None

try:
    import psutil
except ImportError:
    print("Warning: psutil not found. DoS analysis and Traffic stats will be limited.")
    psutil = None

# Import ConfigManager
try:
    from config_manager import ConfigManager
except ImportError:
    # Try alternate path if running from root
    try:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'server_backend')))
        from config_manager import ConfigManager
    except ImportError:
        print("Warning: ConfigManager not found. Using defaults.")
        ConfigManager = None

class PingMonitor(threading.Thread):
    """
    Background thread to ping targets and store metrics.
    """
    def __init__(self, targets=None, interval=5):
        super().__init__()
        self.interval = interval
        self.running = False
        self.daemon = True # Daemon thread exits when main program exits
        
        # Load targets from config if available
        self.config_manager = ConfigManager() if ConfigManager else None
        if self.config_manager:
            self.targets = self.config_manager.get("ping_targets", ["8.8.8.8", "1.1.1.1"])
        else:
            self.targets = targets if targets else ["8.8.8.8", "1.1.1.1"]

    def run(self):
        print(f"🔄 PingMonitor started for targets: {self.targets}")
        self.running = True
        while self.running:
            for target in self.targets:
                self.ping_target(target)
            time.sleep(self.interval)

    def ping_target(self, target):
        """Execute ping and parse results."""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', target]
        
        try:
            # Run ping command
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            
            # Parse latency
            latency = 0.0
            status = 'Down'
            
            # Linux/Mac formatting: time=14.2 ms
            time_match = re.search(r'time=([\d.]+)', output)
            if time_match:
                latency = float(time_match.group(1))
                status = 'Up'
            
            # Record metrics
            self.save_metrics(target, latency, 0.0, status) # Assuming 0 packet loss for single success
            
        except subprocess.CalledProcessError:
            self.save_metrics(target, 0.0, 100.0, 'Down')
        except Exception as e:
            print(f"Error pinging {target}: {e}")

    def save_metrics(self, target, latency, packet_loss, status):
        """Save metrics to database."""
        if not Session:
            return

        session = Session()
        try:
            metric = PingMetrics(
                target_ip=target,
                latency_ms=latency,
                packet_loss_pct=packet_loss,
                status=status,
                timestamp=datetime.utcnow()
            )
            session.add(metric)
            session.commit()
            # print(f"Ping {target}: {latency}ms ({status})") # Debug
        except Exception as e:
            print(f"Error saving ping metrics: {e}")
            session.rollback()
        finally:
            session.close()

    def stop(self):
        self.running = False

class TrafficMonitor(threading.Thread):
    """
    Background thread to monitor network traffic and calculate DoS likelihood.
    """
    def __init__(self, interval=5):
        super().__init__()
        self.interval = interval
        self.running = False
        self.daemon = True
        
        # Baselines (updated dynamically)
        self.baseline_pps_in = 100.0 
        self.alpha_smoothing = 0.1 # For moving average
        
        # Load thresholds
        self.config_manager = ConfigManager() if ConfigManager else None
        self.thresholds = {
            "cpu_percent": 80.0,
            "pps_in": 1000,
            "pps_out_ratio": 10.0
        }
        if self.config_manager:
            self.thresholds = self.config_manager.get("dos_thresholds", self.thresholds)

    def run(self):
        if not psutil:
            print("TrafficMonitor disabled: psutil not installed.")
            return

        print("🔄 TrafficMonitor started")
        self.running = True
        
        last_net = psutil.net_io_counters()
        last_time = time.time()
        
        while self.running:
            time.sleep(self.interval)
            
            current_net = psutil.net_io_counters()
            current_time = time.time()
            dt = current_time - last_time
            
            if dt <= 0: continue
            
            # Calculate rates
            pkts_in = (current_net.packets_recv - last_net.packets_recv) / dt
            pkts_out = (current_net.packets_sent - last_net.packets_sent) / dt
            bytes_in = (current_net.bytes_recv - last_net.bytes_recv) / dt
            bytes_out = (current_net.bytes_sent - last_net.bytes_sent) / dt
            
            # CPU Load
            cpu = psutil.cpu_percent()
            
            # Calculate DoS Score
            monitor_score = self.calculate_dos_score(pkts_in, pkts_out, cpu)
            
            # Save stats
            self.save_stats(pkts_in, pkts_out, bytes_in, bytes_out, cpu, monitor_score)
            
            # update baseline
            self.baseline_pps_in = (self.baseline_pps_in * (1 - self.alpha_smoothing)) + (pkts_in * self.alpha_smoothing)
            
            last_net = current_net
            last_time = current_time

    def calculate_dos_score(self, pps_in, pps_out, cpu):
        """
        Calculate DoS likelihood score (0-1.0).
        Logic: Spikes in PPS combined with high CPU.
        """
        score = 0.0
        
        # 1. PPS Anomaly
        if pps_in > (self.baseline_pps_in * 3) and pps_in > 500: # Threshold of 500 PPS min
            score += 0.5
        elif pps_in > (self.baseline_pps_in * 2):
            score += 0.2
            
        # 2. CPU Correlation
        if cpu > self.thresholds.get("cpu_percent", 80.0):
            score += 0.3
        elif cpu > self.thresholds.get("cpu_percent", 50.0) * 0.6: # 60% of threshold
            score += 0.1
            
        # 3. Outbound ratio (amplification attack?)
        ratio_threshold = self.thresholds.get("pps_out_ratio", 10.0)
        if pps_out > 0 and (pps_in / pps_out) > ratio_threshold:
             score += 0.2

        return min(round(score, 2), 1.0)

    def save_stats(self, pps_in, pps_out, bytes_in, bytes_out, cpu, score):
        if not Session: return
        
        session = Session()
        try:
            stats = TrafficStats(
                packet_count_in=int(pps_in),
                packet_count_out=int(pps_out),
                byte_count_in=int(bytes_in),
                byte_count_out=int(bytes_out),
                cpu_load=cpu,
                dos_likelihood_score=score,
                timestamp=datetime.utcnow()
            )
            session.add(stats)
            session.commit()
            
            if score > 0.7:
                 print(f"⚠️  High Traffic Alert: DoS Likelihood {score*100}% (PPS In: {int(pps_in)}, CPU: {cpu}%)")
                 
        except Exception as e:
            print(f"Error saving traffic stats: {e}")
            session.rollback()
        finally:
            session.close()

    def stop(self):
        self.running = False
