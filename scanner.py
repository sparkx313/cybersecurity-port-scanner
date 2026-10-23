"""Bounded, concurrent TCP connect scanner for explicitly selected hosts."""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import sys
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 27017: "MongoDB",
}


def classify_result(error_code: int) -> str:
    if error_code == 0:
        return "open"
    if error_code == errno.ECONNREFUSED:
        return "closed"
    return "filtered"


def scan_port(family: int, address: tuple, port: int, timeout: float) -> dict:
    endpoint = list(address)
    endpoint[1] = port
    started = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        error_code = sock.connect_ex(tuple(endpoint))
        state = classify_result(error_code)
    except (socket.timeout, TimeoutError):
        state = "filtered"
    except OSError as exc:
        state = classify_result(exc.errno or errno.EIO)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    service = COMMON_PORTS.get(port)
    if service is None:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "unknown"
    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "service": service,
        "latency_ms": elapsed_ms,
    }


def scan_target(target: str, start_port: int, end_port: int, workers: int, timeout: float) -> dict:
    try:
        address_info = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)[0]
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target {target!r}: {exc}") from exc

    family, _, _, _, sockaddr = address_info
    resolved_address = sockaddr[0]
    counts = {"open": 0, "closed": 0, "filtered": 0}
    open_ports = []
    total = end_port - start_port + 1
    started_at = datetime.now(timezone.utc).isoformat()
    scan_started = time.perf_counter()

    port_iterator = iter(range(start_port, end_port + 1))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()
        exhausted = False
        while pending or not exhausted:
            while not exhausted and len(pending) < workers * 4:
                try:
                    port = next(port_iterator)
                except StopIteration:
                    exhausted = True
                    break
                pending.add(executor.submit(scan_port, family, sockaddr, port, timeout))
            if not pending:
                continue
            completed, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in completed:
                result = future.result()
                counts[result["state"]] += 1
                if result["state"] == "open":
                    open_ports.append(result)

    return {
        "target": target,
        "resolved_address": resolved_address,
        "address_family": "IPv6" if family == socket.AF_INET6 else "IPv4",
        "protocol": "TCP connect",
        "started_at": started_at,
        "duration_seconds": round(time.perf_counter() - scan_started, 3),
        "ports_scanned": total,
        "counts": counts,
        "open_ports": sorted(open_ports, key=lambda item: item["port"]),
        "interpretation": (
            "A refused connection is reported closed. Other connection errors and timeouts are grouped as filtered; "
            "that does not prove a firewall is present."
        ),
    }


def write_json(path: Path, report: dict) -> None:
    destination = path.expanduser().resolve()
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", prefix=f".{destination.name}.",
            suffix=".tmp", dir=destination.parent, delete=False,
        ) as output:
            temporary = Path(output.name)
            json.dump(report, output, indent=2, ensure_ascii=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise ValueError(f"Could not write JSON report: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a TCP port range on one host you are authorized to assess.")
    parser.add_argument("--target", default="127.0.0.1", help="hostname or IP address (default: 127.0.0.1)")
    parser.add_argument("--start-port", type=int, default=1)
    parser.add_argument("--end-port", type=int, default=1024)
    parser.add_argument("--threads", type=int, default=64, help="concurrent connection attempts (1-256)")
    parser.add_argument("--timeout", type=float, default=0.5, help="per-port connection timeout in seconds")
    parser.add_argument("--json-output", type=Path, help="optional JSON report path")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not 1 <= args.start_port <= 65535 or not 1 <= args.end_port <= 65535:
        parser.error("ports must be between 1 and 65535")
    if args.start_port > args.end_port:
        parser.error("--start-port must be less than or equal to --end-port")
    if not 1 <= args.threads <= 256:
        parser.error("--threads must be between 1 and 256")
    if not 0 < args.timeout <= 10:
        parser.error("--timeout must be greater than 0 and at most 10 seconds")

    try:
        report = scan_target(args.target, args.start_port, args.end_port, args.threads, args.timeout)
        if args.json_output:
            write_json(args.json_output, report)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(f"Target: {report['target']} ({report['resolved_address']}, {report['address_family']})")
    print(f"Scanned {report['ports_scanned']} TCP ports in {report['duration_seconds']} seconds")
    print("Counts: " + ", ".join(f"{name}={count}" for name, count in report["counts"].items()))
    if report["open_ports"]:
        print("\nOpen ports:")
        for item in report["open_ports"]:
            print(f"  {item['port']:5d}/tcp  {item['service']:<12} {item['latency_ms']:>8.2f} ms")
    else:
        print("No open TCP ports found in the selected range.")
    if args.json_output:
        print(f"JSON report: {args.json_output.expanduser().resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
