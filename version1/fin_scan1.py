#!/usr/bin/env python3
import socket
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse
from tqdm import tqdm
import os
import time
import struct
import random
import sys


def create_fin_packet(src_port: int, dst_port: int) -> bytes:
    """Create a minimal TCP header with FIN flag set."""
    seq_num = random.randint(0, 0xFFFFFFFF)
    ack_num = 0
    data_offset = 5 << 4  # 5 words (20 bytes)
    fin_flag = 0x01       # FIN
    window = 0
    checksum = 0
    urg_ptr = 0

    tcp_header = struct.pack(
        '!HHLLBBHHH',
        src_port, dst_port,
        seq_num, ack_num,
        data_offset, fin_flag,
        window, checksum, urg_ptr
    )
    return tcp_header


def parse_tcp_flags(response: bytes) -> int | None:
    """Extract TCP flags from a raw IP/TCP packet."""
    if len(response) < 40:  # minimal IPv4 + TCP header
        return None
    ip_header_len = (response[0] & 0x0F) * 4
    if len(response) < ip_header_len + 20:
        return None
    tcp_header = response[ip_header_len:ip_header_len + 20]
    return tcp_header[13]  # flags byte


def fin_scan_port(host: str, port: int, timeout: float = 2.0, family: int = socket.AF_INET) -> dict:
    """Perform FIN scan on a single port."""
    result = {
        "host": host,
        "port": port,
        "status": "filtered",  # default: no response
        "service": "unknown",
        "protocol": "IPv4" if family == socket.AF_INET else "IPv6",
        "scan_type": "FIN"
    }

    try:
        if family == socket.AF_INET:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)

        s.settimeout(timeout)

        src_port = random.randint(1024, 65535)
        fin_packet = create_fin_packet(src_port, port)

        if family == socket.AF_INET:
            s.sendto(fin_packet, (host, port))
        else:
            s.sendto(fin_packet, (host, port, 0, 0))

        try:
            response = s.recv(1024)
            flags = parse_tcp_flags(response)
            if flags is not None:
                if flags & 0x04:  # RST
                    result["status"] = "closed"
                else:
                    result["status"] = "open"
            else:
                result["status"] = "filtered"
        except socket.timeout:
            # No response → could be OPEN or FILTERED
            result["status"] = "open|filtered"

    except socket.error as e:
        if getattr(e, "errno", None) in (1, 13):
            result["error"] = "Root/admin privileges required for raw sockets"
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

    if result["status"].startswith("open"):
        try:
            result["service"] = socket.getservbyport(port, "tcp")
        except:
            pass

    return result


def port_scanner(host: str, start_port: int, end_port: int, max_threads: int = 20,
                 timeout: float = 2.0, delay: float = 0.02) -> list:
    """Scan a range of ports using multithreading with FIN scan."""
    results = []
    families = [socket.AF_INET]

    try:
        socket.getaddrinfo(host, None, socket.AF_INET6)
        families.append(socket.AF_INET6)
    except:
        pass

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for family in families:
            for port in range(start_port, end_port + 1):
                futures.append(executor.submit(fin_scan_port, host, port, timeout, family))
                if delay > 0:
                    time.sleep(delay)

        for future in tqdm(as_completed(futures), total=len(futures), desc="FIN Scanning"):
            results.append(future.result())

    return results


def export_to_json(data: list, filename: str = "fin_scan_results.json", force: bool = False) -> None:
    """Export scan results to JSON with timestamp."""
    if os.path.exists(filename) and not force:
        raise FileExistsError(f"File {filename} already exists. Use --force to overwrite.")

    valid_results = [r for r in data if r["status"] not in ("error",)]
    error_results = [r for r in data if r["status"] == "error"]

    open_ports = [r for r in valid_results if r["status"].startswith("open")]

    report = {
        "timestamp": datetime.now().isoformat(),
        "host": valid_results[0]["host"] if valid_results else "unknown",
        "scan_type": "FIN Scan",
        "total_ports_scanned": len(valid_results),
        "open_ports_count": len(open_ports),
        "closed_ports_count": len([r for r in valid_results if r["status"] == "closed"]),
        "filtered_ports_count": len([r for r in valid_results if "filtered" in r["status"]]),
        "open_ports": [{"port": r["port"], "service": r["service"]} for r in open_ports],
        "scan_results": valid_results,
        "errors": error_results
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"Results saved to {filename}")


def check_privileges() -> bool:
    """Check if program is running with privileges required for raw sockets."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    # Windows fallback (must run as Administrator)
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FIN Port Scanner - Find Open Ports Stealthily")
    parser.add_argument("host", help="Target host (e.g., 127.0.0.1 or example.com)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=20, help="Max threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between sending packets (seconds)")
    parser.add_argument("--output", help="JSON output filename")
    parser.add_argument("--verbose", action="store_true", help="Show all scanned ports")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output file")
    args = parser.parse_args()

    if not check_privileges():
        print("ERROR: FIN scanning requires root/administrator privileges for raw socket operations.")
        sys.exit(1)

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        parser.error("Invalid port range. Ports must be between 1-65535 and start <= end.")
    if args.threads < 1 or args.threads > 100:
        parser.error("Threads must be between 1 and 100.")
    try:
        socket.getaddrinfo(args.host, None)
    except socket.gaierror:
        parser.error(f"Cannot resolve host {args.host}")

    print("FIN Scan - Stealth Port Detection")
    print("   - No response: Port is OPEN or FILTERED")
    print("   - RST response: Port is CLOSED")
    print("   - Scanning large ranges may be detected")

    if args.end - args.start + 1 > 1000:
        if input("Scan large port range? (y/n): ").lower() != 'y':
            sys.exit(1)

    print(f"\nFIN Scanning {args.host} (ports {args.start}-{args.end})...")
    results = port_scanner(args.host, args.start, args.end, args.threads, args.timeout, args.delay)

    output_file = args.output or f"fin_scan_{args.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    export_to_json(results, output_file, args.force)

    open_ports = [r for r in results if r["status"].startswith("open")]
    closed_ports = [r for r in results if r["status"] == "closed"]
    filtered_ports = [r for r in results if "filtered" in r["status"]]
    errors = [r for r in results if r["status"] == "error"]

    print(f"\nFIN Scan Results:")
    print(f"Open ports: {len(open_ports)}")
    print(f"Closed ports: {len(closed_ports)}")
    print(f"Filtered/unknown: {len(filtered_ports)}")
    print(f"Errors: {len(errors)}")

    if open_ports:
        print(f"\nOpen ports found:")
        for port in sorted(open_ports, key=lambda x: x["port"]):
            print(f"   Port {port['port']}/tcp - {port['service']}")

    if args.verbose:
        print(f"\nDetailed results:")
        for r in results:
            status = r["status"]
            if status.startswith("open"):
                print(f"   Port {r['port']}: {status.upper()} ({r['service']})")
            elif status == "closed":
                print(f"   Port {r['port']}: CLOSED")
            elif "filtered" in status:
                print(f"   Port {r['port']}: FILTERED/NO RESPONSE")
            else:
                print(f"   Port {r['port']}: ERROR - {r.get('error', 'Unknown error')}")
