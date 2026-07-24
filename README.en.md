# tcp-port

[中文](./README.md)

**tcp-port** is a Linux TCP protocol traffic analyzer built on [gopacket](https://github.com/google/gopacket). It captures TCP traffic on network interfaces, reassembles TCP streams, and decodes the following 6 common backend protocols:

| Protocol | Supported Versions |
|----------|-------------------|
| Dubbo | 2.x (Hessian2), 3.x (Triple / gRPC) |
| Redis | RESP2 |
| RocketMQ | Remoting Protocol |
| MySQL | 8.x (client-server protocol) |
| MongoDB | 4.x+ (OP_MSG, etc.) |
| HTTP | 1.x |

Features: **auto protocol detection**, **millisecond-precision timestamps**, **request latency tracking**, **per-protocol file output**, and **rich protocol-specific filtering**.

---

## Installation

### Prerequisites

**Build dependency** (source build only):

```bash
# Ubuntu / Debian
sudo apt-get install libpcap-dev

# CentOS / RHEL
sudo yum install libpcap-devel

# macOS
brew install libpcap
```

**Runtime dependency** (pre-built binary; most Linux distros include it — install if you see `libpcap.so.0.8: cannot open`):

```bash
# Ubuntu / Debian
sudo apt-get install libpcap0.8

# CentOS / RHEL
sudo yum install libpcap
```

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/carlvine500/tcp-port/releases):

| Platform | Binary |
|----------|--------|
| Linux amd64 | `tcp-port-linux-amd64` |
| Linux arm64 | `tcp-port-linux-arm64` |
| macOS arm64 | `tcp-port-darwin-arm64` |

> **macOS amd64 (Intel)** / **Windows**: Build from source. Instructions below.

```bash
# Example: install on Linux amd64
curl -L https://github.com/carlvine500/tcp-port/releases/latest/download/tcp-port-linux-amd64 -o tcp-port
chmod +x tcp-port
sudo mv tcp-port /usr/local/bin/
```

### Build from Source

```bash
git clone https://github.com/carlvine500/tcp-port.git
cd tcp-port
go build -o tcp-port .
sudo cp tcp-port /usr/local/bin/
```

Or with `go install`:

```bash
go install github.com/carlvine500/tcp-port@latest
```

> **Note**: Packet capture requires root privileges or `CAP_NET_RAW` capability on Linux.

---

## Quick Start

### 1. Monitor all local TCP traffic (auto-detect protocols)

```bash
sudo tcp-port
```

Sample output:

```
2026-01-02 09:22:11.651
10.0.0.5:45123 -----> 10.0.0.6:6379
  SET  user:1001  {"name":"Alice","age":30}
2026-01-02 09:22:11.654
10.0.0.6:6379 <----- 10.0.0.5:45123
  [SimpleString] OK
  [3.12ms]

2026-01-02 09:22:12.108
10.0.0.5:45124 -----> 10.0.0.7:3306
  Query  SELECT * FROM users WHERE id = 1
2026-01-02 09:22:12.113
10.0.0.7:3306 <----- 10.0.0.5:45124
  Resultset  columns=3 rows=1
  [4.87ms]
```

Every request-response pair includes a **millisecond timestamp** and **latency** measurement.

### 2. Filter by port

```bash
sudo tcp-port -port 6379
```

### 3. Filter by IP

```bash
sudo tcp-port -ip 172.17.0.3
```

This is ideal for monitoring **Docker containers** — no need to exec into the container; capture all protocol traffic from the host.

### 4. Specify a protocol

```bash
sudo tcp-port -protocol redis
sudo tcp-port -protocol dubbo
sudo tcp-port -protocol mysql
sudo tcp-port -protocol mongo
sudo tcp-port -protocol http
```

---

## Detailed Examples

### Dubbo

**Monitor all Dubbo calls:**

```bash
sudo tcp-port -protocol dubbo
```

Output:

```
2026-01-02 09:30:00.123
10.0.0.5:52001 -----> 10.0.0.6:20880
  Dubbo 2.7.0  com.example.UserService  findById(long)  id=1001
2026-01-02 09:30:00.145
10.0.0.6:20880 <----- 10.0.0.5:52001
  Dubbo 2.7.0  com.example.UserService  findById  ok  {"id":1001,"name":"Alice"}
  [22.45ms]
```

**Filter by service and method:**

```bash
# Only UserService
sudo tcp-port -protocol dubbo -dubbo-service 'com.example.UserService'

# Methods starting with "find" (wildcard)
sudo tcp-port -protocol dubbo -dubbo-method 'find*'

# Combined
sudo tcp-port -protocol dubbo \
  -dubbo-service 'com.example.*' \
  -dubbo-method 'find*'
```

**URL summary only (minimal output):**

```bash
sudo tcp-port -protocol dubbo -level url
```

Output:

```
10.0.0.5:52001 -----> 10.0.0.6:20880  com.example.UserService  findById(long)
```

### Redis

**Monitor all Redis commands:**

```bash
sudo tcp-port -protocol redis
```

**Filter by command:**

```bash
# Only SET commands
sudo tcp-port -protocol redis -redis-command 'SET'

# GET and HGET (wildcard)
sudo tcp-port -protocol redis -redis-command 'GET*'
```

**Filter by key regex:**

```bash
# Keys starting with "user:"
sudo tcp-port -protocol redis -redis-key '^user:'

# Session keys matching a digit pattern
sudo tcp-port -protocol redis -redis-key '^session:\d+'

# Hash keys under a specific prefix
sudo tcp-port -protocol redis -redis-key '^cache:product:'
```

The regex syntax is standard Go `regexp` (RE2).

### MySQL

**Monitor all MySQL queries:**

```bash
sudo tcp-port -protocol mysql
```

Sample output:

```
2026-01-02 09:35:10.201
10.0.0.5:33060 -----> 10.0.0.7:3306
  Query  SELECT * FROM orders WHERE user_id = 1001
2026-01-02 09:35:10.218
10.0.0.7:3306 <----- 10.0.0.5:33060
  Resultset  columns=5 rows=42
  [17.11ms]
```

**Filter by query content:**

```bash
# Queries containing "orders"
sudo tcp-port -protocol mysql -mysql-query 'orders'

# Queries containing "JOIN"
sudo tcp-port -protocol mysql -mysql-query 'JOIN'
```

**Filter by command type:**

```bash
# Only Query commands
sudo tcp-port -protocol mysql -mysql-command 'Query'

# Wildcard for prepared statements
sudo tcp-port -protocol mysql -mysql-command 'Stmt*'
```

### MongoDB

**Monitor all MongoDB operations:**

```bash
sudo tcp-port -protocol mongo
```

**Filter by opcode:**

```bash
# OP_MSG (typically CRUD operations)
sudo tcp-port -protocol mongo -mongo-opcode 2013

# OP_QUERY
sudo tcp-port -protocol mongo -mongo-opcode 2004
```

### RocketMQ

```bash
sudo tcp-port -protocol rocketmq
```

**Filter by request code:**

```bash
# SEND_MESSAGE (code 10)
sudo tcp-port -protocol rocketmq -rmq-code 10

# PULL_MESSAGE (code 11)
sudo tcp-port -protocol rocketmq -rmq-code 11
```

### HTTP

```bash
sudo tcp-port -protocol http
```

Output:

```
2026-01-02 09:40:05.500
10.0.0.5:54321 -----> 10.0.0.8:8080
  GET /api/users HTTP/1.1
2026-01-02 09:40:05.523
10.0.0.8:8080 <----- 10.0.0.5:54321
  200 OK  Content-Length: 1024
  [23.18ms]
```

---

## Docker Container Monitoring (Core Use Case)

Monitor all multi-protocol traffic from a Java process inside a container:

```bash
# Get the container IP
docker inspect -f '{{.NetworkSettings.IPAddress}}' my-app

# Capture all traffic with auto-detection
sudo tcp-port -ip 172.17.0.3 -protocol auto
```

Output spans Redis, MySQL, Dubbo, HTTP, etc.:

```
2026-01-02 10:00:01.100
172.17.0.3:45123 -----> 172.17.0.5:6379
  GET  user:1001
2026-01-02 10:00:01.103
172.17.0.5:6379 <----- 172.17.0.3:45123
  [BulkString] {"id":1001,"name":"Alice"}
  [2.87ms]

2026-01-02 10:00:01.200
172.17.0.3:45124 -----> 172.17.0.6:3306
  Query  INSERT INTO logs (msg) VALUES ('order created')
2026-01-02 10:00:01.205
172.17.0.6:3306 <----- 172.17.0.3:45124
  OK  affected_rows=1
  [5.12ms]

2026-01-02 10:00:01.300
172.17.0.3:45125 -----> 172.17.0.7:20880
  Dubbo 3.0  com.example.OrderService  createOrder(...)
  ...
```

---

## Output Levels

`-level` controls verbosity:

| Level | Description |
|-------|-------------|
| `url` | Request/response address and method only (most compact) |
| `header` | Request header + response header (default) |
| `all` | Full content including body / payload |

```bash
# Most compact — just the call chain
sudo tcp-port -level url

# Full content
sudo tcp-port -level all
```

---

## Per-Protocol File Output

Use `-output-dir` to write each protocol's traffic to separate files:

```bash
sudo tcp-port -output-dir /tmp/tcpdump/
```

This creates (existing files are overwritten):

```
/tmp/tcpdump/
├── dubbo.log
├── redis.log
├── rocketmq.log
├── mysql.log
├── mongo.log
└── http.log
```

Terminal output continues as normal. To suppress it and only write files:

```bash
sudo tcp-port -output-dir /tmp/tcpdump/ > /dev/null
```

---

## Offline PCAP Analysis

```bash
# Read from a pcap file
sudo tcp-port -file capture.pcap

# Read pcap, filter to dubbo only
sudo tcp-port -file capture.pcap -protocol dubbo

# Read pcap, export to files
sudo tcp-port -file capture.pcap -output-dir ./output/
```

---

## Complete CLI Reference

```
tcp-port [flags]

GENERAL:
  -protocol string    Protocol: auto, dubbo, redis, rocketmq, mysql, mongo, http (default: auto)
  -level string       Output level: url | header | all (default: header)
  -ip string          Filter by IP address
  -port uint          Filter by port (default: any)
  -device string      Capture interface (default: any)
  -file string        Read from pcap file
  -output string      Write to a single file
  -output-dir string  Write per-protocol files to directory (e.g., redis.log, mysql.log)

DUBBO:
  -dubbo-service string  Filter by service name (wildcard)
  -dubbo-method string   Filter by method name (wildcard)

REDIS:
  -redis-command string  Filter by command (SET, GET, etc.; wildcard)
  -redis-key string      Filter by key (Go regexp)

ROCKETMQ:
  -rmq-code int          Filter by request code

MYSQL:
  -mysql-command string  Filter by command type (Query, Ping, etc.)
  -mysql-query string    Filter by query substring

MONGODB:
  -mongo-opcode int      Filter by opcode
```

---

## Timestamps & Latency

All output includes millisecond-precision timestamps (`2006-01-02 15:04:05.000`), and responses show elapsed time:

```
2026-01-02 09:22:11.651          ← request timestamp
10.0.0.5:45123 -----> ...
  SET  user:1001  ...
2026-01-02 09:22:11.654          ← response timestamp
10.0.0.5:45123 <----- ...
  [SimpleString] OK
  [3.12ms]                        ← total latency (request → response)
```

> Latency is measured from the first byte of the request to the last byte of the response.

---

## How It Works

```
┌─────────────────────────────────────────────┐
│                   pcap (libpcap)             │
│                Packet capture                │
└─────────────────┬───────────────────────────┘
                  │ TCP packets
┌─────────────────▼───────────────────────────┐
│              TCP Assembler                   │
│      Bidirectional TCP stream reassembly     │
└─────────────────┬───────────────────────────┘
                  │ Ordered byte streams
┌─────────────────▼───────────────────────────┐
│          Protocol Detector (auto)            │
│  Tries dubbo→triple→redis→rocketmq          │
│        →mysql→mongo→http in order           │
└─────────────────┬───────────────────────────┘
                  │ Detected protocol
┌─────────────────▼───────────────────────────┐
│          Protocol Handler                    │
│   Parse → Format → MultiPrinter             │
└─────────────────┬───────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
  stdout      dubbo.log     redis.log  ...
```

---

## Requirements

- **OS**: Linux (requires `AF_PACKET`), macOS, or Windows (Npcap)
- **Privileges**: root or `CAP_NET_RAW` on Linux
- **Dependencies**: `libpcap` (see prerequisites above)
- **Go**: 1.22+ (build from source only)

---

## License

MIT
