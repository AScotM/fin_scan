#!/usr/bin/env python3
"""
FIN Port Scanner (IPv4 full-packet crafting + improved reply matching)

Requires root privileges for raw sockets.
"""

import argparse
import ctypes
import json
import os
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from tqdm import tqdm

# -----------------------------------------------------------------------------
# Utility: checksum helpers
# -----------------------------------------------------------------------------
def ip_checksum(data: bytes) -> int:
    """Compute IPv4 header checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    # add carries
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_header: bytes, payload: bytes = b"") -> int:
    """
    Compute TCP checksum using IPv4 pseudo-header.
    src_ip, dst_ip: packed 4-byte addresses
    tcp_header: TCP header with checksum field = 0
    """
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_header) + len(payload))
    to_check = pseudo + tcp_header + payload
    if len(to_check) % 2:
        to_check += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(to_check) // 2), to_check))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


# -----------------------------------------------------------------------------
# Packet builders
# -----------------------------------------------------------------------------
def build_ipv4_header(src_ip: str, dst_ip: str, total_length: int, identification: int = None) -> bytes:
    """Build IPv4 header with checksum 0 (we compute then insert)."""
    version_ihl = (4 << 4) | 5  # version=4, IHL=5 (20 bytes)
    tos = 0
    tot_len = total_length
    ident = identification if identification is not None else random.randint(0, 0xFFFF)
    flags_fragment = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    checksum = 0
    src_packed = socket.inet_aton(src_ip)
    dst_packed = socket.inet_aton(dst_ip)

    header = struct.pack("!BBHHHBBH4s4s",
                         version_ihl, tos, tot_len, ident, flags_fragment,
                         ttl, proto, checksum, src_packed, dst_packed)
    chksum = ip_checksum(header)
    header = struct.pack("!BBHHHBBH4s4s",
                         version_ihl, tos, tot_len, ident, flags_fragment,
                         ttl, proto, chksum, src_packed, dst_packed)
    return header


def build_tcp_header(src_port: int, dst_port: int, seq: int = None, ack: int = 0,
                     flags: int = 0x01, window: int = 65535, payload: bytes = b"", src_ip: str = "", dst_ip: str = "") -> bytes:
    """
    Build TCP header with computed checksum. Flags is the byte containing flags (e.g. FIN=0x01).
    Returns full 20-byte header with checksum set.
    """
    seq = seq if seq is not None else random.randint(0, 0xFFFFFFFF)
    data_offset_reserved = (5 << 4)  # 5 words => 20 bytes, reserved=0
    urg_ptr = 0
    checksum = 0

    # initially pack with checksum=0
    tcp_hdr = struct.pack("!HHLLBBHHH",
                          src_port, dst_port,
                          seq, ack,
                          data_offset_reserved, flags,
                          window, checksum, urg_ptr)

    # compute checksum using pseudo-header
    src_packed = socket.inet_aton(src_ip)
    dst_packed = socket.inet_aton(dst_ip)
    chksum = tcp_checksum(src_packed, dst_packed, tcp_hdr, payload)
    tcp_hdr = struct.pack("!HHLLBBHHH",
                          src_port, dst_port,
                          seq, ack,
                          data_offset_reserved, flags,
                          window, chksum, urg_ptr)
    return tcp_hdr


# -----------------------------------------------------------------------------
# Packet parsing helpers
# -----------------------------------------------------------------------------
def parse_ipv4_packet(packet: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse minimal IPv4 + TCP header to extract source/dest IPs and ports and TCP flags.
    Returns dict or None if parsing fails.
    """
    if len(packet) < 20:
        return None
    # Unpack IPv4 header (first 20 bytes)
    version_ihl = packet[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(packet) < ihl + 20:
        return None
    # IPv4 addresses at offsets 12..16 and 16..20
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])

    # TCP header starts at ihl
    tcp_offset = ihl
    tcp_header = packet[tcp_offset:tcp_offset + 20]
    if len(tcp_header) < 20:
        return None
    src_port, dst_port, seq, ack, offset_reserved, flags_byte, window, checksum, urg = struct.unpack("!HHLLBBHHH", tcp_header)
    flags = flags_byte
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "seq": seq,
        "ack": ack,
    }


# -----------------------------------------------------------------------------
# Scanner core (IPv4)
# -----------------------------------------------------------------------------
def fin_scan_ipv4_single(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    FIN scan a single IPv4 port by constructing a full IPv4 + TCP packet with FIN flag.
    Listens for a reply on a raw TCP socket and classifies port.
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "status": "filtered",
        "service": "unknown",
        "protocol": "IPv4",
        "scan_type": "FIN",
    }

    try:
        dst_addr = socket.gethostbyname(host)
    except socket.gaierror as e:
        result["status"] = "error"
        result["error"] = f"DNS resolution failed: {e}"
        return result

    # Determine local outbound IP to target (create UDP socket to get route)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_temp:
            s_temp.connect((dst_addr, port if port else 80))
            local_ip = s_temp.getsockname()[0]
    except Exception:
        local_ip = "0.0.0.0"  # fallback - OS will choose

    src_port = random.randint(1024, 65535)
    seq = random.randint(0, 0xFFFFFFFF)

    # Build TCP header (FIN flag)
    fin_flag = 0x01
    tcp_hdr = build_tcp_header(src_port, port, seq=seq, ack=0, flags=fin_flag,
                               window=65535, payload=b"", src_ip=local_ip, dst_ip=dst_addr)

    # Build IPv4 header
    total_len = 20 + len(tcp_hdr)  # IP header + TCP header (no payload)
    ip_hdr = build_ipv4_header(local_ip, dst_addr, total_len)

    packet = ip_hdr + tcp_hdr

    # sending socket: raw IP (we provide IP header)
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        result["status"] = "error"
        result["error"] = "Root/admin privileges required for raw sockets"
        return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Failed to create send socket: {e}"
        return result

    # receiving socket: raw TCP to capture TCP packets
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
    except Exception as e:
        send_sock.close()
        result["status"] = "error"
        result["error"] = f"Failed to create recv socket: {e}"
        return result

    try:
        # Send the crafted packet
        send_sock.sendto(packet, (dst_addr, 0))

        start = time.time()
        while True:
            try:
                remaining = max(0.01, timeout - (time.time() - start))
                recv_sock.settimeout(remaining)
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                # no reply
                # Per FIN scan semantics: no response -> open|filtered
                result["status"] = "open|filtered"
                break

            parsed = parse_ipv4_packet(data)
            if not parsed:
                continue

            # match replies: source IP must be the destination we probed, and port must match dst/src accordingly
            if parsed["src_ip"] != dst_addr:
                continue
            # reply's dst_port must be our src_port
            if parsed["dst_port"] != src_port:
                continue
            # reply's src_port must be the port we probed
            if parsed["src_port"] != port:
                continue

            flags = parsed["flags"]
            # RST bit (0x04) means closed
            if flags & 0x04:
                result["status"] = "closed"
            else:
                # other replies may indicate open (unexpected), treat as open
                result["status"] = "open"
            break

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Runtime error while sending/receiving: {e}"
    finally:
        try:
            send_sock.close()
        except:
            pass
        try:
            recv_sock.close()
        except:
            pass

    if result["status"].startswith("open"):
        try:
            result["service"] = socket.getservbyport(port, "tcp")
        except OSError:
            result["service"] = "unknown"

    return result


# -----------------------------------------------------------------------------
# Wrapper to decide IPv4 / IPv6 scanning; IPv6 left as a fallback (not fully implemented)
# -----------------------------------------------------------------------------
def fin_scan_port(host: str, port: int, timeout: float = 2.0, family: int = socket.AF_INET) -> Dict[str, Any]:
    """
    Top-level port scan call. For now, prefer IPv4 full-packet method.
    If family==AF_INET6, try a simpler send (best-effort) but reliability will vary by platform.
    """
    if family == socket.AF_INET:
        return fin_scan_ipv4_single(host, port, timeout)
    else:
        # Best-effort IPv6 attempt: use raw TCP socket send of minimal TCP header (may not work)
        result = {
            "host": host,
            "port": port,
            "status": "filtered",
            "service": "unknown",
            "protocol": "IPv6",
            "scan_type": "FIN",
        }
        try:
            info = socket.getaddrinfo(host, None, socket.AF_INET6)
            dst = info[0][4][0]
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"IPv6 resolution failed: {e}"
            return result

        try:
            # create raw TCP socket (may be restricted)
            s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(timeout)
            # craft minimal TCP header (no IPv6 pseudo-header checksum here)
            src_port = random.randint(1024, 65535)
            tcp_hdr = create_minimal_tcp_header(src_port, port, flags=0x01)  # create_minimal_tcp_header not implemented here
            # best-effort send; many systems will reject or OS will fill headers
            s.sendto(tcp_hdr, (dst, port))
            try:
                resp = s.recv(4096)
                flags = parse_tcp_flags(resp)
                if flags is None:
                    result["status"] = "filtered"
                elif flags & 0x04:
                    result["status"] = "closed"
                else:
                    result["status"] = "open"
            except socket.timeout:
                result["status"] = "open|filtered"
            s.close()
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"IPv6 raw socket error: {e}"
        return result


# -----------------------------------------------------------------------------
# Threaded port range scanner
# -----------------------------------------------------------------------------
def port_scanner(host: str, start_port: int, end_port: int, max_threads: int = 20,
                 timeout: float = 2.0, delay: float = 0.0) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    # Only IPv4 in this robust implementation
    families = [socket.AF_INET]

    tasks = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for family in families:
            for port in range(start_port, end_port + 1):
                tasks.append(executor.submit(fin_scan_port, host, port, timeout, family))
                if delay > 0:
                    time.sleep(delay)

        # use tqdm to report progress
        for fut in tqdm(as_completed(tasks), total=len(tasks), desc="FIN Scanning"):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"host": host, "port": -1, "status": "error", "error": str(e)})

    return results


# -----------------------------------------------------------------------------
# Export / report helpers
# -----------------------------------------------------------------------------
def export_to_json(data: List[Dict[str, Any]], filename: str = "fin_scan_results.json", force: bool = False) -> None:
    if os.path.exists(filename) and not force:
        raise FileExistsError(f"File {filename} already exists. Use --force to overwrite.")

    valid_results = [r for r in data if r.get("status") != "error"]
    error_results = [r for r in data if r.get("status") == "error"]

    open_ports = [r for r in valid_results if r["status"].startswith("open")]

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": valid_results[0]["host"] if valid_results else "unknown",
        "scan_type": "FIN Scan",
        "total_ports_scanned": len(valid_results),
        "open_ports_count": len(open_ports),
        "closed_ports_count": len([r for r in valid_results if r["status"] == "closed"]),
        "filtered_ports_count": len([r for r in valid_results if "filtered" in r["status"]]),
        "open_ports": [{"port": r["port"], "service": r.get("service", "unknown")} for r in open_ports],
        "scan_results": valid_results,
        "errors": error_results,
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"Results saved to {filename}")


# -----------------------------------------------------------------------------
# Privilege check
# -----------------------------------------------------------------------------
def check_privileges() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore
    except Exception:
        return False


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="FIN Port Scanner (IPv4 full-packet)")
    parser.add_argument("host", help="Target host (IPv4)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=20, help="Max threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between sending packets (seconds)")
    parser.add_argument("--output", help="JSON output filename")
    parser.add_argument("--verbose", action="store_true", help="Show all scanned ports")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output file")
    args = parser.parse_args()

    if not check_privileges():
        print("ERROR: FIN scanning requires root/administrator privileges for raw socket operations.")
        sys.exit(1)

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        parser.error("Invalid port range. Ports must be between 1-65535 and start <= end.")
    if args.threads < 1 or args.threads > 200:
        parser.error("Threads must be between 1 and 200.")

    try:
        socket.getaddrinfo(args.host, None)
    except socket.gaierror:
        parser.error(f"Cannot resolve host {args.host}")

    print("FIN Scan - Stealth Port Detection (IPv4 full-packet)")
    print("   - RST reply: port is CLOSED")
    print("   - No reply within timeout: OPEN or FILTERED (open|filtered)")
    print("   - Other replies: treated as OPEN")

    total_ports = args.end - args.start + 1
    if total_ports > 2000:
        resp = input(f"Scanning {total_ports} ports may take long and be noisy. Proceed? (y/N): ").strip().lower()
        if resp != "y":
            print("Aborting.")
            sys.exit(0)

    print(f"\nScanning {args.host} ports {args.start}-{args.end} with {args.threads} threads...")
    start_time = time.time()
    results = port_scanner(args.host, args.start, args.end, args.threads, args.timeout, args.delay)
    elapsed = time.time() - start_time
    print(f"Scan completed in {elapsed:.2f}s")

    output_file = args.output or f"fin_scan_{args.host}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    export_to_json(results, output_file, args.force)

    open_ports = [r for r in results if r["status"].startswith("open")]
    closed_ports = [r for r in results if r["status"] == "closed"]
    filtered_ports = [r for r in results if "filtered" in r["status"]]
    errors = [r for r in results if r["status"] == "error"]

    print("\nFIN Scan Summary:")
    print(f"Open ports: {len(open_ports)}")
    print(f"Closed ports: {len(closed_ports)}")
    print(f"Filtered/unknown: {len(filtered_ports)}")
    print(f"Errors: {len(errors)}")

    if open_ports:
        print("\nOpen ports found:")
        for p in sorted(open_ports, key=lambda x: x["port"]):
            print(f"  Port {p['port']}/tcp - {p.get('service','unknown')}")

    if args.verbose:
        print("\nDetailed results (first 200 entries):")
        for r in results[:200]:
            status = r.get("status", "error")
            if status.startswith("open"):
                print(f"  Port {r['port']}: OPEN ({r.get('service','unknown')})")
            elif status == "closed":
                print(f"  Port {r['port']}: CLOSED")
            elif "filtered" in status:
                print(f"  Port {r['port']}: FILTERED/NO RESPONSE")
            else:
                print(f"  Port {r['port']}: ERROR - {r.get('error','Unknown')}")

if __name__ == "__main__":
    main()
