"""
Port Scanner
This script scans a target host for open ports within a specified range.
For educational purposes only. Only use on authorized targets.

Author: [Your Name]
Date: April 20, 2025
"""

import socket
import argparse
import sys
import time
from datetime import datetime
import ipaddress

# Default configuration
DEFAULT_TIMEOUT = 1.0  # Socket timeout in seconds
DEFAULT_PORT_RANGE = '1-1024'  # Default port range to scan
DEFAULT_HOST = '127.0.0.1'  # Default host to scan
DELAY = 0.1  # Delay between scan attempts (to be courteous)
AUTHORIZED_HOSTS = ['127.0.0.1', 'localhost', 'scanme.nmap.org']  # Only scan these hosts


def validate_host(host):
    """
    Validate if the host is allowed to be scanned.
    
    Args:
        host (str): The hostname or IP address to validate
        
    Returns:
        bool: True if host is authorized, False otherwise
    """
    # Check if host is in authorized list
    if host in AUTHORIZED_HOSTS:
        return True
    
    # Try to resolve hostname to check if it matches an authorized IP
    try:
        ip = socket.gethostbyname(host)
        if ip in AUTHORIZED_HOSTS:
            return True
    except socket.gaierror:
        # Unable to resolve hostname
        pass
    
    return False


def validate_port_range(port_range):
    """
    Validate and parse the port range.
    
    Args:
        port_range (str): Port range in format 'start-end' or single port or comma-separated ports
        
    Returns:
        list: List of port numbers to scan, or None if invalid
    """
    try:
        ports_to_scan = []
        
        # Handle comma-separated port ranges
        if ',' in port_range:
            parts = port_range.split(',')
            for part in parts:
                if '-' in part:
                    # Range in format '1-100'
                    start, end = map(int, part.split('-'))
                    if start < 1 or end > 65535 or start > end:
                        print(f"[!] Invalid port range {part}. Ports must be between 1-65535 and start must be <= end.")
                        return None
                    ports_to_scan.extend(range(start, end + 1))
                else:
                    # Single port
                    port = int(part)
                    if port < 1 or port > 65535:
                        print(f"[!] Invalid port {port}. Port must be between 1-65535.")
                        return None
                    ports_to_scan.append(port)
        elif '-' in port_range:
            # Single range format '1-100'
            start, end = map(int, port_range.split('-'))
            if start < 1 or end > 65535 or start > end:
                print("[!] Invalid port range. Ports must be between 1-65535 and start must be <= end.")
                return None
            ports_to_scan = list(range(start, end + 1))
        else:
            # Single port format
            port = int(port_range)
            if port < 1 or port > 65535:
                print("[!] Invalid port. Port must be between 1-65535.")
                return None
            ports_to_scan = [port]
            
        return ports_to_scan
    except ValueError:
        print("[!] Invalid port range format. Use 'start-end', comma-separated list, or a single port.")
        return None


def scan_port(host, port, timeout):
    """
    Scan a single port on the target host.
    
    Args:
        host (str): Target hostname or IP address
        port (int): Port number to scan
        timeout (float): Socket timeout in seconds
        
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # Create socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            
            # Try to connect to the port
            result = s.connect_ex((host, port))
            
            # If result is 0, the port is open
            return result == 0
            
    except socket.gaierror:
        print(f"[!] Hostname '{host}' could not be resolved.")
        return False
    except socket.error as e:
        print(f"[!] Socket error: {e}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        return False


def main():
    """
    Main function to parse arguments and run the port scanner.
    """
    # Create argument parser
    parser = argparse.ArgumentParser(
        description='Simple port scanner for educational purposes.',
        epilog='IMPORTANT: Only scan authorized hosts (localhost and scanme.nmap.org).'
    )
    
    # Add arguments
    parser.add_argument(
        '-t', '--target',
        default=DEFAULT_HOST,
        help=f'Target host to scan (default: {DEFAULT_HOST})'
    )
    parser.add_argument(
        '-p', '--ports',
        default=DEFAULT_PORT_RANGE,
        help=f'Port range to scan (e.g., 1-100 or 80 or 21,22,80,443) (default: {DEFAULT_PORT_RANGE})'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f'Socket timeout in seconds (default: {DEFAULT_TIMEOUT})'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Get current timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"Port Scanner started at {timestamp}")
    print("-" * 60)
    
    # Validate target
    if not validate_host(args.target):
        print(f"[!] ERROR: Unauthorized host: {args.target}")
        print("[!] For security and legal reasons, you can only scan:")
        print("    - localhost (127.0.0.1)")
        print("    - scanme.nmap.org")
        return
    
    # Validate port range
    ports_to_scan = validate_port_range(args.ports)
    if ports_to_scan is None:
        return
    
    # Scan ports
    try:
        # Get first and last port for display purposes
        start_port, end_port = min(ports_to_scan), max(ports_to_scan)
        
        # Initialize results and counters
        results = {}
        open_count = 0
        
        # Try to resolve hostname before scanning
        try:
            ip = socket.gethostbyname(args.target)
            print(f"[*] Target IP: {ip}")
        except socket.gaierror:
            print(f"[!] Could not resolve hostname '{args.target}'")
            return
            
        # Start time
        start_time = time.time()
        print(f"[*] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Scanning {args.target} for {len(ports_to_scan)} ports")
        print("-" * 60)
        
        # Scan each port
        for i, port in enumerate(sorted(ports_to_scan)):
            sys.stdout.write(f"\r[*] Scanning port {port} ({i+1}/{len(ports_to_scan)})")
            sys.stdout.flush()
            
            # Scan the port
            is_open = scan_port(args.target, port, args.timeout)
            results[port] = is_open
            
            # Count open ports
            if is_open:
                open_count += 1
                
            # Add delay to avoid overwhelming target
            time.sleep(DELAY)
        
        # End time
        end_time = time.time()
        duration = end_time - start_time
        
        # Clear the current line
        sys.stdout.write("\r" + " " * 80 + "\r")
        
        # Print summary
        print("-" * 60)
        print(f"[*] Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Scan duration: {duration:.2f} seconds")
        print(f"[*] Ports scanned: {len(ports_to_scan)}")
        print(f"[*] Open ports found: {open_count}")
        print("-" * 60)
        
        # Print open ports
        if open_count > 0:
            print("Open ports:")
            for port in sorted(ports_to_scan):
                if results.get(port, False):
                    try:
                        # Try to get service name for the port
                        service = socket.getservbyport(port)
                    except (socket.error, OSError):
                        service = "unknown"
                        
                    print(f"Port {port}: Open ({service})")
        else:
            print("No open ports found.")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return


if __name__ == "__main__":
    main()