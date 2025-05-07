#!/usr/bin/env python3
"""
Router Port Forwarding GUI

A graphical user interface for managing port forwarding on routers 
using UPnP or NAT-PMP protocols.

Requirements:
- Python 3.6+
- miniupnpc (pip install miniupnpc)
- python-nmap (pip install python-nmap)
"""

import os
import sys
import time
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ipaddress
from typing import Dict, List, Optional, Tuple, Union

try:
    import miniupnpc
except ImportError:
    print("Error: miniupnpc module not found. Install it with: pip install miniupnpc")
    sys.exit(1)

try:
    import nmap
except ImportError:
    print("Error: python-nmap module not found. Install it with: pip install python-nmap")
    sys.exit(1)


class RedirectText:
    """Class to redirect stdout to a tkinter Text widget"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = ""

    def write(self, string):
        self.buffer += string
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")
        
    def flush(self):
        pass


class RouterAdmin:
    """Class to handle router administration tasks"""
    
    def __init__(self):
        self.local_ip = self._get_local_ip()
        self.gateway_ip = self._get_gateway_ip()
        self.upnp = None
        
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
    
    def _get_gateway_ip(self) -> Optional[str]:
        """Get the gateway/router IP address"""
        if sys.platform.startswith('linux'):
            try:
                with open('/proc/net/route') as f:
                    for line in f.readlines():
                        parts = line.strip().split()
                        if parts[1] == '00000000':  # Default route
                            return socket.inet_ntoa(bytes.fromhex(parts[2].zfill(8))[::-1])
            except:
                pass
        
        elif sys.platform == 'darwin':  # macOS
            try:
                output = subprocess.check_output("netstat -nr | grep default", shell=True).decode('utf-8')
                return output.split()[1]
            except:
                pass
        
        elif sys.platform == 'win32':  # Windows
            try:
                output = subprocess.check_output("ipconfig", shell=True).decode('utf-8')
                for line in output.split('\n'):
                    if "Default Gateway" in line:
                        return line.split(":")[-1].strip()
            except:
                pass
                
        # Fallback: try to guess the gateway by modifying the last octet of local IP
        ip_parts = self.local_ip.split('.')
        common_gateway_last_octets = ['1', '254']
        
        for last_octet in common_gateway_last_octets:
            potential_gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{last_octet}"
            if potential_gateway != self.local_ip:
                return potential_gateway
                
        return None
    
    def initialize_upnp(self) -> bool:
        """Initialize UPnP and try to discover the router"""
        try:
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 10
            
            print("Discovering UPnP devices...")
            devices_found = upnp.discover()
            print(f"Found {devices_found} UPnP device(s)")
            
            if devices_found > 0:
                try:
                    upnp.selectigd()  # Select the IGD (Internet Gateway Device)
                    print(f"Selected IGD: {upnp.lanaddr}")
                    self.upnp = upnp
                    return True
                except Exception as e:
                    print(f"Error selecting IGD: {e}")
            else:
                print("No UPnP devices found. Your router may not support UPnP.")
        except Exception as e:
            print(f"Error initializing UPnP: {e}")
        
        return False
    
    def add_port_mapping(self, external_port: int, internal_port: int, protocol: str, description: str) -> bool:
        """Add a port mapping using UPnP"""
        if not self.upnp:
            print("UPnP not initialized. Run initialize_upnp() first.")
            return False
        
        protocol = protocol.upper()
        if protocol not in ['TCP', 'UDP']:
            print("Invalid protocol. Use 'TCP' or 'UDP'.")
            return False
        
        try:
            # Add port mapping: (external_port, protocol, internal_ip, internal_port, description, remote_host)
            result = self.upnp.addportmapping(
                external_port, protocol, self.local_ip, internal_port, description, ''
            )
            if result:
                print(f"Successfully mapped external port {external_port} to {self.local_ip}:{internal_port} ({protocol})")
                return True
            else:
                print(f"Failed to map port {external_port}")
                return False
        except Exception as e:
            print(f"Error adding port mapping: {e}")
            return False
    
    def remove_port_mapping(self, external_port: int, protocol: str) -> bool:
        """Remove a port mapping using UPnP"""
        if not self.upnp:
            print("UPnP not initialized. Run initialize_upnp() first.")
            return False
        
        protocol = protocol.upper()
        if protocol not in ['TCP', 'UDP']:
            print("Invalid protocol. Use 'TCP' or 'UDP'.")
            return False
        
        try:
            result = self.upnp.deleteportmapping(external_port, protocol, '')
            if result:
                print(f"Successfully removed port mapping for port {external_port} ({protocol})")
                return True
            else:
                print(f"Failed to remove port mapping for port {external_port}")
                return False
        except Exception as e:
            print(f"Error removing port mapping: {e}")
            return False
    
    def list_port_mappings(self) -> List[Dict[str, str]]:
        """List all port mappings using UPnP"""
        if not self.upnp:
            print("UPnP not initialized. Run initialize_upnp() first.")
            return []
        
        mappings = []
        try:
            i = 0
            while True:
                mapping = self.upnp.getgenericportmapping(i)
                if mapping is None:
                    break
                
                ext_port, protocol, int_ip, int_port, desc, enabled, _, lease = mapping
                
                mappings.append({
                    'external_port': ext_port,
                    'protocol': protocol,
                    'internal_ip': int_ip,
                    'internal_port': int_port,
                    'description': desc,
                    'enabled': enabled,
                    'lease_duration': lease
                })
                
                i += 1
                
            return mappings
        except Exception as e:
            print(f"Error listing port mappings: {e}")
            return []
    
    def scan_router(self) -> None:
        """Scan router ports to identify potential admin panels"""
        if not self.gateway_ip:
            print("Gateway IP not found.")
            return
        
        common_admin_ports = [80, 443, 8080, 8443, 8081, 8888]
        
        print(f"Scanning router at {self.gateway_ip} for admin panels...")
        nm = nmap.PortScanner()
        nm.scan(hosts=self.gateway_ip, arguments=f'-p {",".join(map(str, common_admin_ports))}')
        
        if self.gateway_ip in nm.all_hosts():
            print("\nOpen ports that might be admin panels:")
            for port in nm[self.gateway_ip]['tcp']:
                if nm[self.gateway_ip]['tcp'][port]['state'] == 'open':
                    service = nm[self.gateway_ip]['tcp'][port]['name']
                    print(f"  Port {port}/tcp is open (service: {service})")
                    if port in [80, 443, 8080, 8443]:
                        protocol = "https" if port in [443, 8443] else "http"
                        print(f"  Try accessing: {protocol}://{self.gateway_ip}:{port}")
        else:
            print("No common admin ports found open on your router.")

    def get_system_info(self) -> str:
        """Get system information relevant to networking"""
        info = f"Platform: {sys.platform}\n"
        info += f"Local IP: {self.local_ip}\n"
        info += f"Gateway IP: {self.gateway_ip}\n\n"
        
        # Get network interfaces
        if sys.platform.startswith('linux') or sys.platform == 'darwin':
            try:
                output = subprocess.check_output("ifconfig", shell=True).decode('utf-8')
                info += "Network Interfaces:\n" + output
            except:
                try:
                    output = subprocess.check_output("ip addr", shell=True).decode('utf-8')
                    info += "Network Interfaces:\n" + output
                except:
                    info += "Could not retrieve network interface information"
        elif sys.platform == 'win32':
            try:
                output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8')
                info += "Network Interfaces:\n" + output
            except:
                info += "Could not retrieve network interface information"
                
        return info


class PortForwardingGUI:
    """Main GUI class for the port forwarding application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Router Port Forwarding Tool")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        self.router_admin = RouterAdmin()
        self.upnp_initialized = False
        
        self.create_widgets()
        self.setup_layout()
        
        # Display local and gateway IPs
        self.update_status_bar()
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        
        # Create tabs
        self.tab_port_mapping = ttk.Frame(self.notebook)
        self.tab_port_list = ttk.Frame(self.notebook)
        self.tab_router_scan = ttk.Frame(self.notebook)
        self.tab_system_info = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_port_mapping, text="Port Mapping")
        self.notebook.add(self.tab_port_list, text="List Mappings")
        self.notebook.add(self.tab_router_scan, text="Router Scan")
        self.notebook.add(self.tab_system_info, text="System Info")
        
        # ==== Port Mapping Tab ====
        frame_mapping = ttk.LabelFrame(self.tab_port_mapping, text="Add/Remove Port Mapping")
        frame_mapping.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # External port
        ttk.Label(frame_mapping, text="External Port:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.external_port = ttk.Entry(frame_mapping, width=10)
        self.external_port.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Internal port
        ttk.Label(frame_mapping, text="Internal Port:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.internal_port = ttk.Entry(frame_mapping, width=10)
        self.internal_port.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Protocol
        ttk.Label(frame_mapping, text="Protocol:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.protocol_var = tk.StringVar(value="tcp")
        protocol_frame = ttk.Frame(frame_mapping)
        protocol_frame.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(protocol_frame, text="TCP", variable=self.protocol_var, value="tcp").pack(side=tk.LEFT)
        ttk.Radiobutton(protocol_frame, text="UDP", variable=self.protocol_var, value="udp").pack(side=tk.LEFT)
        ttk.Radiobutton(protocol_frame, text="Both", variable=self.protocol_var, value="both").pack(side=tk.LEFT)
        
        # Description
        ttk.Label(frame_mapping, text="Description:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.description = ttk.Entry(frame_mapping, width=30)
        self.description.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        self.description.insert(0, "Port Forwarding")
        
        # Buttons frame
        button_frame = ttk.Frame(frame_mapping)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        self.init_btn = ttk.Button(button_frame, text="Initialize UPnP", command=self.initialize_upnp)
        self.init_btn.pack(side=tk.LEFT, padx=5)
        
        self.add_btn = ttk.Button(button_frame, text="Add Mapping", command=self.add_mapping, state=tk.DISABLED)
        self.add_btn.pack(side=tk.LEFT, padx=5)
        
        self.remove_btn = ttk.Button(button_frame, text="Remove Mapping", command=self.remove_mapping, state=tk.DISABLED)
        self.remove_btn.pack(side=tk.LEFT, padx=5)
        
        # ==== Port List Tab ====
        frame_list = ttk.Frame(self.tab_port_list)
        frame_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.list_btn = ttk.Button(frame_list, text="Refresh List", command=self.refresh_port_list, state=tk.DISABLED)
        self.list_btn.pack(pady=10)
        
        # Treeview for port mapping list
        columns = ("external_port", "protocol", "internal_ip", "internal_port", "description", "enabled", "lease")
        self.port_tree = ttk.Treeview(frame_list, columns=columns, show="headings", selectmode="browse")
        
        # Configure headings
        self.port_tree.heading("external_port", text="External Port")
        self.port_tree.heading("protocol", text="Protocol")
        self.port_tree.heading("internal_ip", text="Internal IP")
        self.port_tree.heading("internal_port", text="Internal Port")
        self.port_tree.heading("description", text="Description")
        self.port_tree.heading("enabled", text="Enabled")
        self.port_tree.heading("lease", text="Lease Duration")
        
        # Configure columns width
        self.port_tree.column("external_port", width=100)
        self.port_tree.column("protocol", width=80)
        self.port_tree.column("internal_ip", width=120)
        self.port_tree.column("internal_port", width=100)
        self.port_tree.column("description", width=200)
        self.port_tree.column("enabled", width=80)
        self.port_tree.column("lease", width=100)
        
        # Add a scrollbar
        tree_scroll = ttk.Scrollbar(frame_list, orient="vertical", command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=tree_scroll.set)
        
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # ==== Router Scan Tab ====
        frame_scan = ttk.Frame(self.tab_router_scan)
        frame_scan.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.scan_btn = ttk.Button(frame_scan, text="Scan Router", command=self.scan_router)
        self.scan_btn.pack(pady=10)
        
        # ==== System Info Tab ====
        frame_info = ttk.Frame(self.tab_system_info)
        frame_info.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.refresh_info_btn = ttk.Button(frame_info, text="Refresh Info", command=self.refresh_system_info)
        self.refresh_info_btn.pack(pady=10)
        
        # System info text area
        self.system_info_text = scrolledtext.ScrolledText(frame_info, wrap=tk.WORD, height=20)
        self.system_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.system_info_text.config(state=tk.DISABLED)
        
        # ==== Common output console ====
        self.console_frame = ttk.LabelFrame(self.root, text="Console Output")
        self.console = scrolledtext.ScrolledText(self.console_frame, wrap=tk.WORD, height=10)
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.console.config(state=tk.DISABLED)
        
        # Redirect stdout to console
        self.stdout_redirect = RedirectText(self.console)
        sys.stdout = self.stdout_redirect
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="", relief=tk.SUNKEN, anchor=tk.W)
    
    def setup_layout(self):
        """Set up the layout of widgets"""
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.console_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 10))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_status_bar(self):
        """Update the status bar with network information"""
        status_text = f"Local IP: {self.router_admin.local_ip} | Gateway IP: {self.router_admin.gateway_ip} | UPnP: {'Initialized' if self.upnp_initialized else 'Not Initialized'}"
        self.status_bar.config(text=status_text)
    
    def initialize_upnp(self):
        """Initialize UPnP in a separate thread"""
        def init_thread():
            if self.router_admin.initialize_upnp():
                self.upnp_initialized = True
                self.enable_buttons()
                self.update_status_bar()
                print("UPnP initialized successfully.")
            else:
                print("Failed to initialize UPnP.")
            
        thread = threading.Thread(target=init_thread)
        thread.daemon = True
        thread.start()
    
    def enable_buttons(self):
        """Enable buttons that require UPnP initialization"""
        self.add_btn.config(state=tk.NORMAL)
        self.remove_btn.config(state=tk.NORMAL)
        self.list_btn.config(state=tk.NORMAL)
    
    def add_mapping(self):
        """Add a port mapping"""
        try:
            ext_port = int(self.external_port.get())
            int_port = int(self.internal_port.get())
            protocol = self.protocol_var.get()
            desc = self.description.get()
            
            if protocol == "both":
                protocols = ["tcp", "udp"]
            else:
                protocols = [protocol]
            
            for proto in protocols:
                self.router_admin.add_port_mapping(ext_port, int_port, proto, desc)
            
            self.refresh_port_list()
        except ValueError:
            messagebox.showerror("Error", "Please enter valid port numbers.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    
    def remove_mapping(self):
        """Remove a port mapping"""
        try:
            ext_port = int(self.external_port.get())
            protocol = self.protocol_var.get()
            
            if protocol == "both":
                protocols = ["tcp", "udp"]
            else:
                protocols = [protocol]
            
            for proto in protocols:
                self.router_admin.remove_port_mapping(ext_port, proto)
            
            self.refresh_port_list()
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid external port number.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    
    def refresh_port_list(self):
        """Refresh the port mapping list"""
        def refresh_thread():
            # Clear existing items
            for item in self.port_tree.get_children():
                self.port_tree.delete(item)
                
            # Get and display mappings
            mappings = self.router_admin.list_port_mappings()
            for mapping in mappings:
                self.port_tree.insert("", tk.END, values=(
                    mapping["external_port"],
                    mapping["protocol"],
                    mapping["internal_ip"],
                    mapping["internal_port"],
                    mapping["description"],
                    "Yes" if mapping["enabled"] else "No",
                    f"{mapping['lease_duration']} sec"
                ))
                
            print(f"Retrieved {len(mappings)} port mappings.")
        
        thread = threading.Thread(target=refresh_thread)
        thread.daemon = True
        thread.start()
    
    def scan_router(self):
        """Scan router for admin panels"""
        def scan_thread():
            self.router_admin.scan_router()
        
        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()
    
    def refresh_system_info(self):
        """Refresh system information"""
        def info_thread():
            info = self.router_admin.get_system_info()
            self.system_info_text.config(state=tk.NORMAL)
            self.system_info_text.delete(1.0, tk.END)
            self.system_info_text.insert(tk.END, info)
            self.system_info_text.config(state=tk.DISABLED)
            print("System information refreshed.")
        
        thread = threading.Thread(target=info_thread)
        thread.daemon = True
        thread.start()


def main():
    """Main function to start the GUI application"""
    root = tk.Tk()
    
    # Set theme - try to use a more modern theme if available
    try:
        style = ttk.Style()
        available_themes = style.theme_names()
        
        preferred_themes = ["clam", "alt", "vista", "xpnative"]
        for theme in preferred_themes:
            if theme in available_themes:
                style.theme_use(theme)
                break
    except:
        pass  # If theme setting fails, continue with default
    
    app = PortForwardingGUI(root)
    
    # Set window icon (platform-specific)
    try:
        if sys.platform == "win32":
            import ctypes
            # Use default application icon
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("RouterPortForwarding")
    except:
        pass
    
    root.mainloop()
    
    # Restore stdout before exit
    sys.stdout = sys.__stdout__


if __name__ == "__main__":
    main()