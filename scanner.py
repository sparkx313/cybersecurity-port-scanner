import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    5432: "PostgreSQL", 8080: "HTTP-Alt"
}

def scan_port(target_ip, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            banner = ""
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip().split('\n')[0]
            except Exception:
                banner = "No banner response"
            service = COMMON_PORTS.get(port, "Unknown Service")
            sock.close()
            return port, True, service, banner
        sock.close()
    except Exception:
        pass
    return port, False, None, None

def main():
    parser = argparse.ArgumentParser(description="Multi-Threaded TCP Port Scanner")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or Hostname")
    parser.add_argument("--start-port", type=int, default=1, help="Start Port")
    parser.add_argument("--end-port", type=int, default=1024, help="End Port")
    parser.add_argument("--threads", type=int, default=50, help="Thread Pool Workers")
    args = parser.parse_args()

    print("=" * 60)
    print(f"🛡️  Cybersecurity Port Scanner")
    print(f"🎯 Target: {args.target}")
    print(f"🔌 Port Range: {args.start-port} - {args.end-port}")
    print("=" * 60)

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("❌ Error: Hostname could not be resolved.")
        sys.exit(1)

    open_ports = []
    ports_to_scan = range(args.start_port, args.end_port + 1)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_port, target_ip, p) for p in ports_to_scan]
        for future in futures:
            port, is_open, service, banner = future.result()
            if is_open:
                print(f"[+] Port {port:5d}/TCP : OPEN | Service: {service:<15} | Banner: {banner}")
                open_ports.append(port)

    print("=" * 60)
    print(f"✅ Scan Complete. Total Open Ports Found: {len(open_ports)}")
    print("=" * 60)

if __name__ == "__main__":
    main()
