# system_info.py (Bayoumy's Detection Engine - Day 2 & 3: System Information Collection)
"""
System information collection module.
Implements Day 2: psutil for running processes
Implements Day 3: System Info (OS, Users, Uptime) and Network Connections
"""
import platform
import getpass
import socket
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional

def get_running_processes(limit: int = 10) -> List[Dict]:
    """
    Day 2: Get current running processes using psutil.
    
    Args:
        limit: Maximum number of processes to return (default: 10)
        
    Returns:
        List of process dictionaries with PID, name, status, etc.
    """
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = proc.info
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'status': proc_info['status'],
                    'cpu_percent': proc_info.get('cpu_percent', 0),
                    'memory_percent': proc_info.get('memory_percent', 0)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage (highest first) and limit
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        return processes[:limit]
        
    except Exception as e:
        print(f"Warning: Could not retrieve processes: {e}")
        return []


def get_system_info() -> Dict:
    """
    Day 3: Capture System Info (OS, Users, Uptime).
    
    Returns:
        Dictionary containing system information
    """
    try:
        # Get OS information
        os_info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }
        
        # Get current user
        current_user = getpass.getuser()
        
        # Get all users (Linux/Unix)
        users = []
        try:
            import pwd
            for user in pwd.getpwall():
                users.append({
                    'username': user.pw_name,
                    'uid': user.pw_uid,
                    'home': user.pw_dir,
                    'shell': user.pw_shell
                })
        except (ImportError, AttributeError):
            # Windows or fallback
            users = [{'username': current_user, 'uid': None, 'home': None, 'shell': None}]
        
        # Get system uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        uptime_delta = timedelta(seconds=int(uptime_seconds))
        
        uptime_info = {
            'boot_time': boot_time.isoformat(),
            'uptime_seconds': int(uptime_seconds),
            'uptime_formatted': str(uptime_delta),
            'uptime_days': uptime_delta.days,
            'uptime_hours': uptime_delta.seconds // 3600,
            'uptime_minutes': (uptime_delta.seconds % 3600) // 60
        }
        
        # Get CPU and memory info
        cpu_info = {
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'cpu_per_core': psutil.cpu_percent(interval=1, percpu=True)
        }
        
        memory = psutil.virtual_memory()
        memory_info = {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'used_gb': round(memory.used / (1024**3), 2),
            'percent': memory.percent
        }
        
        return {
            'os': os_info,
            'current_user': current_user,
            'users': users[:10],  # Limit to first 10 users
            'uptime': uptime_info,
            'cpu': cpu_info,
            'memory': memory_info,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        print(f"Warning: Could not retrieve system info: {e}")
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


def get_network_connections() -> List[Dict]:
    """
    Day 3: Get Active Network Connections using socket and psutil.
    
    Returns:
        List of network connection dictionaries
    """
    connections = []
    try:
        # Get all network connections
        net_conns = psutil.net_connections(kind='inet')
        
        for conn in net_conns:
            try:
                conn_info = {
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                
                # Get process name if PID is available
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        conn_info['process_name'] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        conn_info['process_name'] = 'Unknown'
                else:
                    conn_info['process_name'] = None
                
                connections.append(conn_info)
                
            except (psutil.AccessDenied, AttributeError) as e:
                continue
        
        return connections
        
    except Exception as e:
        print(f"Warning: Could not retrieve network connections: {e}")
        return []


def get_local_ip_addresses() -> List[str]:
    """
    Get all local IP addresses using socket.
    
    Returns:
        List of local IP addresses
    """
    ip_addresses = []
    try:
        # Get hostname
        hostname = socket.gethostname()
        
        # Get IP addresses
        ip_addresses.append(socket.gethostbyname(hostname))
        
        # Get all network interfaces
        addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in addrs.items():
            for addr in interface_addresses:
                if addr.family == socket.AF_INET:  # IPv4
                    if addr.address not in ip_addresses:
                        ip_addresses.append(addr.address)
        
        return ip_addresses
        
    except Exception as e:
        print(f"Warning: Could not retrieve IP addresses: {e}")
        return []


def collect_incident_context() -> Dict:
    """
    Day 3: Collect comprehensive system context when an incident is detected.
    This function combines all system information for incident enrichment.
    
    Returns:
        Dictionary containing all system context information
    """
    return {
        'system_info': get_system_info(),
        'network_connections': get_network_connections(),
        'local_ips': get_local_ip_addresses(),
        'top_processes': get_running_processes(limit=10),
        'collection_timestamp': datetime.now().isoformat()
    }


def print_system_info_summary():
    """
    Day 2: Print a summary of system information (for testing/debugging).
    """
    print("\n" + "=" * 60)
    print("🖥️  SYSTEM INFORMATION")
    print("=" * 60)
    
    # System Info
    sys_info = get_system_info()
    if 'os' in sys_info:
        print(f"OS: {sys_info['os']['system']} {sys_info['os']['release']}")
        print(f"Current User: {sys_info['current_user']}")
        if 'uptime' in sys_info:
            print(f"Uptime: {sys_info['uptime']['uptime_formatted']}")
        if 'cpu' in sys_info:
            print(f"CPU Usage: {sys_info['cpu']['cpu_percent']}%")
        if 'memory' in sys_info:
            print(f"Memory Usage: {sys_info['memory']['percent']}%")
    
    # Network Connections
    print("\n" + "-" * 60)
    print("🌐 ACTIVE NETWORK CONNECTIONS")
    print("-" * 60)
    connections = get_network_connections()
    if connections:
        print(f"Total Connections: {len(connections)}")
        for conn in connections[:5]:  # Show first 5
            print(f"  {conn['local_address']} -> {conn['remote_address']} ({conn['status']})")
    else:
        print("No connections found or access denied")
    
    # Running Processes
    print("\n" + "-" * 60)
    print("⚙️  TOP RUNNING PROCESSES (by CPU)")
    print("-" * 60)
    processes = get_running_processes(limit=5)
    if processes:
        for proc in processes:
            print(f"  PID {proc['pid']}: {proc['name']} (CPU: {proc['cpu_percent']}%, Memory: {proc['memory_percent']:.1f}%)")
    else:
        print("No processes found or access denied")
    
    print("=" * 60 + "\n")


if __name__ == '__main__':
    # Test the functions
    print_system_info_summary()

