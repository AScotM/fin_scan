#!/usr/bin/env python3
import socket
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import argparse
from tqdm import tqdm
import os
import time
import struct
import random

def create_fin_packet(src_port: int, dst_port: int) -> bytes:
    """Create a TCP packet with FIN flag set."""
    # TCP header fields
    seq_num = random.randint(0, 0xFFFFFFFF)
    ack_num = 0
    data_offset = 5 << 4  # 5 words (20 bytes)
    fin_flag = 0x01       # FIN flag
    window = 0
    checksum = 0
    urg_ptr = 0

    # Pack TCP header
    tcp_header = struct.pack('!HHLLBBHHH', 
                            src_port,    # source port
                            dst_port,    # destination port
                            seq_num,     # sequence number
                            ack_num,     # acknowledgement number
                            data_offset, # data offset
                            fin_flag,    # flags (FIN)
                            window,      # window size
                            checksum,    # checksum
                            urg_ptr)     # urgent pointer
    return tcp_header

def fin_scan_port(host: str, port: int, timeout: float = 2.0, family: int = socket.AF_INET) -> dict:
    """Perform FIN scan on a single port and return results."""
    result = {
        "host": host,
        "port": port,
        "status": "closed",  # Default to closed (we expect RST for closed ports)
        "service": "unknown",
        "protocol": "IPv4" if family == socket.AF_INET else "IPv6",
        "scan_type": "FIN"
    }
    
    try:
        # Create raw socket for FIN scanning
        if family == socket.AF_INET:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
        s.settimeout(timeout)
        
        # Create FIN packet with random source port
        src_port = random.randint(1024, 65535)
        fin_packet = create_fin_packet(src_port, port)
        
        # Send FIN packet
        if family == socket.AF_INET:
            s.sendto(fin_packet, (host, port))
        else:
            s.sendto(fin_packet, (host, port, 0, 0))
        
        # Try to receive response
        try:
            response = s.recv(1024)
            
            if response:
                # Check if RST flag is set in response (port is closed)
                # RST flag is at offset 33 (0x04) in TCP header
                if len(response) > 33 and (response[33] & 0x04):
                    result["status"] = "closed"
                else:
                    # Any other response means the port is open
                    result["status"] = "open"
                    
        except socket.timeout:
            # No response - this typically means the port is OPEN
            # (stealthy systems don't respond to FIN packets on open ports)
            result["status"] = "open"
            
    except socket.error as e:
        if e.errno == 1:  # Operation not permitted (need root)
            result["error"] = "Root privileges required for raw socket operations"
            result["status"] = "error"
        elif e.errno == 13:  # Permission denied
            result["error"] = "Permission denied for raw socket operations"
            result["status"] = "error"
        else:
            result["error"] = f"Socket error: {str(e)}"
            result["status"] = "error"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        result["status"] = "error"
    finally:
        try:
            s.close()
        except:
            pass
    
    # Try to get service name for open ports
    if result["status"] == "open":
        try:
            result["service"] = socket.getservbyport(port, "tcp")
        except:
            pass
    
    return result

def port_scanner(host: str, start_port: int, end_port: int, max_threads: int = 20, timeout: float = 2.0) -> list:
    """Scan a range of ports using multithreading with FIN scan."""
    results = []
    families = [socket.AF_INET]
    
    # Check for IPv6 support
    try:
        socket.getaddrinfo(host, None, socket.AF_INET6)
        families.append(socket.AF_INET6)
    except:
        pass
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for family in families:
            futures = [executor.submit(fin_scan_port, host, port, timeout, family) 
                      for port in range(start_port, end_port + 1)]
            for future in tqdm(futures, total=len(futures), desc=f"FIN Scanning ports ({family})"):
                results.append(future.result())
                
                # Small delay to avoid flooding the network and being detected
                time.sleep(0.02)
    
    return results

def export_to_json(data: list, filename: str = "fin_scan_results.json", force: bool = False) -> None:
    """Export scan results to JSON with timestamp."""
    if os.path.exists(filename) and not force:
        raise FileExistsError(f"File {filename} already exists. Use --force to overwrite.")
    
    # Filter out entries with errors for the main report
    valid_results = [r for r in data if r["status"] != "error"]
    error_results = [r for r in data if r["status"] == "error"]
    
    open_ports = [r for r in valid_results if r["status"] == "open"]
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "host": valid_results[0]["host"] if valid_results else "unknown",
        "scan_type": "FIN Scan",
        "total_ports_scanned": len(valid_results),
        "open_ports_count": len(open_ports),
        "closed_ports_count": len(valid_results) - len(open_ports),
        "open_ports": [{"port": r["port"], "service": r["service"]} for r in open_ports],
        "scan_results": valid_results,
        "errors": error_results
    }
    
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FIN Port Scanner - Find Open Ports Stealthily")
    parser.add_argument("host", help="Target host (e.g., 127.0.0.1 or example.com)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=20, help="Max threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    parser.add_argument("--output", help="JSON output filename")
    parser.add_argument("--verbose", action="store_true", help="Show all scanned ports")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output file")
    args = parser.parse_args()

    # Check for root privileges (required for raw sockets)
    if os.geteuid() != 0:
        print("ERROR: FIN scanning requires root privileges for raw socket operations.")
        print("Please run with sudo or as administrator.")
        exit(1)

    # Validate inputs
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        parser.error("Invalid port range. Ports must be between 1-65535 and start <= end.")
    if args.threads < 1 or args.threads > 100:
        parser.error("Threads must be between 1 and 100.")
    try:
        socket.getaddrinfo(args.host, None)
    except socket.gaierror:
        parser.error(f"Cannot resolve host {args.host}")

    # Warn about stealth scanning
    print("FIN Scan - Stealth Port Detection")
    print("   - No response: Port is OPEN (stealthy)")
    print("   - RST response: Port is CLOSED")
    print("   - Scanning large ranges may be detected")
    
    if args.end - args.start + 1 > 1000:
        if input("Scan large port range? (y/n): ").lower() != 'y':
            exit(1)

    print(f"\nFIN Scanning {args.host} (ports {args.start}-{args.end})...")
    results = port_scanner(args.host, args.start, args.end, args.threads, args.timeout)
    
    output_file = args.output or f"fin_scan_{args.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    export_to_json(results, output_file, args.force)

    # Print summary
    open_ports = [r for r in results if r["status"] == "open"]
    closed_ports = [r for r in results if r["status"] == "closed"]
    errors = [r for r in results if r["status"] == "error"]
    
    print(f"\nFIN Scan Results:")
    print(f"Open ports: {len(open_ports)}")
    print(f"Closed ports: {len(closed_ports)}")
    print(f"Errors: {len(errors)}")
    
    if open_ports:
        print(f"\nOpen ports found:")
        for port in sorted(open_ports, key=lambda x: x["port"]):
            print(f"   Port {port['port']}/tcp - {port['service']}")
    
    if args.verbose:
        print(f"\nDetailed results:")
        for r in results:
            if r["status"] == "open":
                print(f"   Port {r['port']}: OPEN ({r['service']})")
            elif r["status"] == "closed":
                print(f"   Port {r['port']}: CLOSED")
            else:
                print(f"   Port {r['port']}: ERROR - {r.get('error', 'Unknown error')}")
