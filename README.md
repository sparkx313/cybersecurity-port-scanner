# TCP Port Scanner

A bounded, concurrent TCP connect scanner for one explicitly selected host. It reports open ports, connection refusals, other connection errors, service names when available, and per-port latency. It supports IPv4 and IPv6 and writes an optional JSON report.

## Run

Requires Python 3.10 or newer; no third-party packages are needed.

~~~sh
python scanner.py --target 127.0.0.1 --start-port 1 --end-port 1024
python scanner.py --target 192.0.2.10 --start-port 1 --end-port 65535 --json-output scan.json
~~~

The default target is loopback. The scanner only performs TCP connection attempts; it does not scan UDP, exploit services, or send HTTP probes for banners. A refused connection is reported closed. Timeouts and other connection errors are grouped as filtered, which is not proof of a firewall. The port-to-service label is a hint based on the local service table, not service identification.

Use it only on systems and networks you own or are explicitly authorized to assess. The default range is ports 1 through 1024. Worker count is capped at 256, and timeout at 10 seconds.