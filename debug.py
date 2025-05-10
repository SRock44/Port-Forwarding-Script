#!/usr/bin/env python3
"""
Fixed Router Port Scanner

This script addresses issues with gateway IP detection on Windows and provides
improved scanning functionality to find your router's admin interface.
"""

import os
import sys
import socket
import subprocess
import re
from typing import List, Optional, Dict, Tuple

try:
    import nmap
except ImportError:
    print("Error: python-nmap module not found. Install it with: pip install python-nmap")
    sys.exit(1)

class ImprovedRouterScanner:
    """Router scanner with enhanced gateway detection for Windows"""
    
    def __init__(self):
        self.local_ip = self._get_local_ip()
        print(f"Local IP: {self.local_ip}")
        
        # Try multiple methods to find the gateway
        self.gateway_candidates = self._find_all_potential_gateways()
        
        if not self.gateway_candidates:
            print("WARNING: Could not find any gateway candidates. Will try common IP addresses.")
            # Add common router IPs as fallback
            self.gateway_candidates = [
                "192.168.0.1",
                "192.168.1.1", 
                "192.168.1.254",
                "10.0.0.1",
                "10.1.1.1"
            ]
    
    def _get_local_ip(self) -> str:
        """Get the local IP address of this machine"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = '127.0.0.1'
        finally:
            s.close()
        return local_ip
    
    def _find_all_potential_gateways(self) -> List[str]:
        """Find all potential gateway IPs using multiple methods"""
        gateway_ips = []
        
        # Method 1: Use ipconfig output parsing for Windows
        if sys.platform == 'win32':
            print("\nSearching for gateways using ipconfig...")
            try:
                # Run ipconfig and capture output
                output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
                
                # Look for Default Gateway entries
                for line in output.split('\n'):
                    if "Default Gateway" in line and ":" in line:
                        potential_gateway = line.split(":")[-1].strip()
                        
                        # Filter out non-IPv4 addresses and interface IDs
                        if potential_gateway and not '%' in potential_gateway and re.match(r'\d+\.\d+\.\d+\.\d+', potential_gateway):
                            print(f"Found potential gateway from ipconfig: {potential_gateway}")
                            if potential_gateway not in gateway_ips:
                                gateway_ips.append(potential_gateway)
            except Exception as e:
                print(f"Error processing ipconfig output: {e}")
        
        # Method 2: Use route print for Windows
        if sys.platform == 'win32':
            print("\nSearching for gateways using route print...")
            try:
                output = subprocess.check_output("route print", shell=True).decode('utf-8', errors='ignore')
                
                # Look for the default route (0.0.0.0)
                lines = output.split('\n')
                for i, line in enumerate(lines):
                    if "0.0.0.0" in line:
                        parts = re.split(r'\s+', line.strip())
                        # Try to find the gateway IP in the line
                        for part in parts:
                            if re.match(r'\d+\.\d+\.\d+\.\d+', part) and part != "0.0.0.0" and part != "255.255.255.255":
                                print(f"Found potential gateway from route print: {part}")
                                if part not in gateway_ips:
                                    gateway_ips.append(part)
            except Exception as e:
                print(f"Error processing route print output: {e}")
        
        # Method 3: Use /proc/net/route for Linux
        elif sys.platform.startswith('linux'):
            print("\nSearching for gateways using /proc/net/route...")
            try:
                with open('/proc/net/route') as f:
                    for line in f.readlines():
                        parts = line.strip().split()
                        if parts[1] == '00000000':  # Default route
                            gateway = socket.inet_ntoa(bytes.fromhex(parts[2].zfill(8))[::-1])
                            print(f"Found gateway from /proc/net/route: {gateway}")
                            if gateway not in gateway_ips:
                                gateway_ips.append(gateway)
            except Exception as e:
                print(f"Error reading route table: {e}")
        
        # Method 4: Use netstat for macOS
        elif sys.platform == 'darwin':
            print("\nSearching for gateways using netstat...")
            try:
                output = subprocess.check_output("netstat -nr | grep default", shell=True).decode('utf-8')
                for line in output.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) > 1:
                            gateway = parts[1]
                            if re.match(r'\d+\.\d+\.\d+\.\d+', gateway):
                                print(f"Found gateway from netstat: {gateway}")
                                if gateway not in gateway_ips:
                                    gateway_ips.append(gateway)
            except Exception as e:
                print(f"Error processing netstat output: {e}")
        
        # Method 5: Try common gateways based on local IP
        if self.local_ip != '127.0.0.1':
            print("\nGenerating potential gateways based on local IP...")
            ip_parts = self.local_ip.split('.')
            if len(ip_parts) == 4:
                # Common last octets for gateway IPs
                common_last_octets = ['1', '254', '100', '101', '250', '253']
                
                for last_octet in common_last_octets:
                    potential_gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{last_octet}"
                    if potential_gateway != self.local_ip:
                        print(f"Generated potential gateway: {potential_gateway}")
                        if potential_gateway not in gateway_ips:
                            gateway_ips.append(potential_gateway)
        
        return gateway_ips
        
    def check_direct_http(self, ip: str) -> List[Tuple[int, str]]:
        """Directly check if common HTTP ports are open"""
        found_ports = []
        common_ports = [80, 443, 8080, 8443, 8081, 8082, 8088, 8888, 9000, 9090]
        
        print(f"\nChecking common HTTP ports on {ip}...")
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    protocol = "https" if port in [443, 8443] else "http"
                    print(f"  Port {port}/tcp is OPEN - Try: {protocol}://{ip}:{port}")
                    found_ports.append((port, protocol))
                sock.close()
            except Exception as e:
                print(f"  Error checking port {port}: {e}")
        
        return found_ports
    
    def scan_with_nmap(self, ip: str) -> List[Tuple[int, str]]:
        """Scan ports using nmap"""
        found_ports = []
        common_admin_ports = [80, 443, 8080, 8443, 8081, 8082, 8088, 8888, 9000, 9090]
        
        print(f"\nScanning {ip} with nmap...")
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments=f'-n -T4 -p {",".join(map(str, common_admin_ports))}')
            
            if ip in nm.all_hosts():
                for port in nm[ip].get('tcp', {}):
                    if nm[ip]['tcp'][port]['state'] == 'open':
                        protocol = "https" if port in [443, 8443] else "http"
                        print(f"  Port {port}/tcp is OPEN - Try: {protocol}://{ip}:{port}")
                        found_ports.append((port, protocol))
        except Exception as e:
            print(f"  Error during nmap scan: {e}")
        
        return found_ports
    
    def check_ping(self, ip: str) -> bool:
        """Check if the IP responds to ping"""
        print(f"Pinging {ip}...")
        try:
            ping_param = "-n 1" if sys.platform == "win32" else "-c 1"
            timeout_param = "-w 1000" if sys.platform == "win32" else "-W 1"
            ping_cmd = f"ping {ping_param} {timeout_param} {ip}"
            
            result = subprocess.call(
                ping_cmd, 
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result == 0:
                print(f"  {ip} responded to ping")
                return True
            else:
                print(f"  {ip} did not respond to ping")
                return False
        except Exception as e:
            print(f"  Error pinging {ip}: {e}")
            return False
    
    def scan_all_candidates(self) -> None:
        """Scan all gateway candidates for open admin ports"""
        print("\n================================")
        print("FIXED ROUTER PORT SCANNER")
        print("================================")
        
        if not self.gateway_candidates:
            print("ERROR: No gateway candidates found.")
            return
        
        print(f"\nFound {len(self.gateway_candidates)} potential gateway addresses to scan.")
        
        results = {}
        
        for ip in self.gateway_candidates:
            print(f"\n--------------------------------")
            print(f"Testing candidate gateway: {ip}")
            print(f"--------------------------------")
            
            # Check if IP responds to ping
            pingable = self.check_ping(ip)
            
            # Check for open ports with direct socket connections
            direct_ports = self.check_direct_http(ip)
            
            # Scan with nmap if available
            nmap_ports = self.scan_with_nmap(ip)
            
            # Combine results
            all_ports = direct_ports.copy()
            for port in nmap_ports:
                if port not in all_ports:
                    all_ports.append(port)
            
            # Store results
            results[ip] = {
                'pingable': pingable,
                'open_ports': all_ports
            }
        
        # Print summary
        print("\n================================")
        print("SCAN RESULTS SUMMARY")
        print("================================")
        
        found_admin = False
        for ip, data in results.items():
            ping_status = "Responds to ping" if data['pingable'] else "Does not respond to ping"
            
            if data['open_ports']:
                found_admin = True
                print(f"\n{ip} - {ping_status}")
                print(f"  Admin interfaces found:")
                for port, protocol in data['open_ports']:
                    print(f"  * {protocol}://{ip}:{port}")
        
        if not found_admin:
            print("\nNo admin interfaces were detected. Possible reasons:")
            print("1. Your router may be blocking scan requests")
            print("2. The router might be using non-standard ports")
            print("3. The gateway detection may not have found your router's actual IP")
            print("\nSuggestions:")
            print("- Check your router's documentation for the admin interface URL")
            print("- Try accessing these common router URLs directly in your browser:")
            
            # Suggest common router URLs
            common_urls = [
                "http://192.168.0.1",
                "http://192.168.1.1", 
                "http://192.168.1.254",
                "http://10.0.0.1",
                "http://10.1.1.1",
                "http://admin.router",
                "http://router.home"
            ]
            
            for url in common_urls:
                print(f"  * {url}")
        
        print("\nDo you want to try one more method? (y/n)")
        response = input().strip().lower()
        if response == 'y' or response == 'yes':
            print("\nTrying to access common router URLs in your default web browser...")
            self.open_common_urls_in_browser()
    
    def open_common_urls_in_browser(self):
        """Try to open common router URLs in the default web browser"""
        import webbrowser
        
        common_urls = [
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://router.home",
            "http://admin.router"
        ]
        
        # Also include the detected gateway candidates
        for ip in self.gateway_candidates:
            common_urls.append(f"http://{ip}")
        
        for url in common_urls:
            print(f"Trying to open {url}...")
            webbrowser.open(url, new=2)  # Open in new tab
            
            print("Did this URL work? (y/n/q to quit)")
            response = input().strip().lower()
            if response == 'y' or response == 'yes':
                print(f"Great! Your router admin URL is: {url}")
                return
            elif response == 'q' or response == 'quit':
                return

if __name__ == "__main__":
    scanner = ImprovedRouterScanner()
    scanner.scan_all_candidates()