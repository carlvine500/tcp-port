# tcp-port

[English](./README.en.md)

**tcp-port** 是一个 Linux TCP 协议流量分析工具，基于 [gopacket](https://github.com/google/gopacket) 构建。它可以截获网卡上的 TCP 流量，自动重组 TCP 流，并解析以下 6 种常见后端协议：

| 协议 | 支持版本 |
|------|---------|
| Dubbo | 2.x (Hessian2), 3.x (Triple / gRPC) |
| Redis | RESP2 |
| RocketMQ | Remoting Protocol |
| MySQL | 8.x (客户端-服务端协议) |
| MongoDB | 4.x+ (OP_MSG 等) |
| HTTP | 1.x |

支持**自动协议检测**、**毫秒级时间戳**、**请求耗时统计**、**按协议分类导出**以及丰富的**协议内过滤**。

---

## 安装

### 前置依赖

**编译依赖**（仅源码编译时需要）：

```bash
# Ubuntu / Debian
sudo apt-get install libpcap-dev

# CentOS / RHEL
sudo yum install libpcap-devel
```

**运行时依赖**（使用预编译二进制时需要。大多数 Linux 已自带，报错 `libpcap.so.0.8: cannot open` 则安装）：

```bash
# Ubuntu / Debian
sudo apt-get install libpcap0.8

# CentOS / RHEL
sudo yum install libpcap
```

### 源码编译

```bash
git clone https://github.com/carlvine500/tcp-port.git
cd tcp-port
go build -o tcp-port .
sudo cp tcp-port /usr/local/bin/
```

### go install

```bash
go install github.com/carlvine500/tcp-port@latest
```

> **注意**：抓包需要 root 权限或 `CAP_NET_RAW` capability。

---

## 快速开始

### 1. 监控本机所有 TCP 流量（自动检测协议）

```bash
sudo tcp-port
```

输出示例：

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

每条请求-响应都有**毫秒时间戳**和**耗时统计**。

### 2. 只看某个端口

```bash
sudo tcp-port -port 6379
```

### 3. 只看某个 IP

```bash
sudo tcp-port -ip 172.17.0.3
```

这非常适合监控 **Docker 容器内的 Java 进程**——无需进入容器，在宿主机上即可看到所有协议的通信。

### 4. 指定协议

```bash
sudo tcp-port -protocol redis
sudo tcp-port -protocol dubbo
sudo tcp-port -protocol mysql
sudo tcp-port -protocol mongo
sudo tcp-port -protocol http
```

---

## 详细示例

### Dubbo

**监控所有 Dubbo 调用：**

```bash
sudo tcp-port -protocol dubbo
```

输出：

```
2026-01-02 09:30:00.123
10.0.0.5:52001 -----> 10.0.0.6:20880
  Dubbo 2.7.0  com.example.UserService  findById(long)  id=1001
2026-01-02 09:30:00.145
10.0.0.6:20880 <----- 10.0.0.5:52001
  Dubbo 2.7.0  com.example.UserService  findById  ok  {"id":1001,"name":"Alice"}
  [22.45ms]
```

**过滤服务名和接口名：**

```bash
# 只看 UserService
sudo tcp-port -protocol dubbo -dubbo-service 'com.example.UserService'

# 只看 find* 方法（通配符）
sudo tcp-port -protocol dubbo -dubbo-method 'find*'

# 组合过滤
sudo tcp-port -protocol dubbo \
  -dubbo-service 'com.example.*' \
  -dubbo-method 'find*'
```

**只输出 URL 摘要（最小输出）：**

```bash
sudo tcp-port -protocol dubbo -level url
```

输出：

```
10.0.0.5:52001 -----> 10.0.0.6:20880  com.example.UserService  findById(long)
```

### Redis

**监控所有 Redis 命令：**

```bash
sudo tcp-port -protocol redis
```

**按命令过滤：**

```bash
# 只看 SET 命令
sudo tcp-port -protocol redis -redis-command 'SET'

# 只看 GET 和 HGET（通配符 *）
sudo tcp-port -protocol redis -redis-command 'GET*'
```

**按 key 正则过滤：**

```bash
# 只看 user: 开头的 key
sudo tcp-port -protocol redis -redis-key '^user:'

# 只看 session 相关的 key
sudo tcp-port -protocol redis -redis-key '^session:\d+'

# 只看某个前缀的 hash
sudo tcp-port -protocol redis -redis-key '^cache:product:'
```

正则语法为标准 Go regexp (`regexp.Compile`)。

### MySQL

**监控所有 MySQL 查询：**

```bash
sudo tcp-port -protocol mysql
```

输出示例：

```
2026-01-02 09:35:10.201
10.0.0.5:33060 -----> 10.0.0.7:3306
  Query  SELECT * FROM orders WHERE user_id = 1001
2026-01-02 09:35:10.218
10.0.0.7:3306 <----- 10.0.0.5:33060
  Resultset  columns=5 rows=42
  [17.11ms]
```

**按查询内容过滤：**

```bash
# 只看包含 orders 的查询
sudo tcp-port -protocol mysql -mysql-query 'orders'

# 只看包含慢查询关键字的
sudo tcp-port -protocol mysql -mysql-query 'JOIN'
```

**按命令类型过滤：**

```bash
# 只看 Query 类命令
sudo tcp-port -protocol mysql -mysql-command 'Query'

# 通配符
sudo tcp-port -protocol mysql -mysql-command 'Stmt*'
```

### MongoDB

**监控所有 MongoDB 操作：**

```bash
sudo tcp-port -protocol mongo
```

**按 opcode 过滤：**

```bash
# OP_MSG 通常是 CRUD 操作
sudo tcp-port -protocol mongo -mongo-opcode 2013

# OP_QUERY
sudo tcp-port -protocol mongo -mongo-opcode 2004
```

### RocketMQ

```bash
sudo tcp-port -protocol rocketmq
```

**按 Request Code 过滤：**

```bash
# 只看 SEND_MESSAGE (code 10)
sudo tcp-port -protocol rocketmq -rmq-code 10

# 只看 PULL_MESSAGE (code 11)
sudo tcp-port -protocol rocketmq -rmq-code 11
```

### HTTP

```bash
sudo tcp-port -protocol http
```

输出：

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

## Docker 容器监控（核心场景）

监控某个容器中 Java 进程的全部多协议流量：

```bash
# 先找到容器 IP
docker inspect -f '{{.NetworkSettings.IPAddress}}' my-app

# 监控该容器的所有流量，自动检测协议
sudo tcp-port -ip 172.17.0.3 -protocol auto
```

输出同时包含 Redis、MySQL、Dubbo、HTTP 等：

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

## 输出级别

`-level` 控制输出详细程度：

| 级别 | 说明 |
|------|------|
| `url` | 只输出请求-响应的地址和方法（最精简） |
| `header` | 输出请求头 + 响应头（默认） |
| `all` | 输出完整内容，包括 body / payload |

```bash
# 最精简模式——只看调用链
sudo tcp-port -level url

# 完整内容
sudo tcp-port -level all
```

---

## 分类导出到文件

使用 `-output-dir` 将不同协议的流量写入独立文件：

```bash
sudo tcp-port -output-dir /tmp/tcpdump/
```

运行后生成（已存在的同名文件会被覆盖）：

```
/tmp/tcpdump/
├── dubbo.log
├── redis.log
├── rocketmq.log
├── mysql.log
├── mongo.log
└── http.log
```

每个文件内 `time.Now()` → `time.Now()` 耗时会持续更新并追加新请求。

- 终端输出照常显示
- 可以只导出不打印（`> /dev/null`），减少终端干扰：

```bash
sudo tcp-port -output-dir /tmp/tcpdump/ > /dev/null
```

---

## 离线分析 pcap 文件

```bash
# 从 pcap 文件读取
sudo tcp-port -file capture.pcap

# 从 pcap 读取，只看 dubbo 协议
sudo tcp-port -file capture.pcap -protocol dubbo

# 从 pcap 读取，导出到文件
sudo tcp-port -file capture.pcap -output-dir ./output/
```

---

## 完整命令行参数

```
tcp-port [flags]

GENERAL:
  -protocol string    协议: auto, dubbo, redis, rocketmq, mysql, mongo, http (default: auto)
  -level string       输出级别: url | header | all (default: header)
  -ip string          按 IP 过滤
  -port uint          按端口过滤 (default: 任意)
  -device string      抓包网卡 (default: any)
  -file string        从 pcap 文件读取
  -output string      写入单个文件
  -output-dir string  写入按协议分类的目录 (e.g. redis.log, mysql.log)

DUBBO:
  -dubbo-service string  过滤服务名（通配符支持）
  -dubbo-method string   过滤方法名（通配符支持）

REDIS:
  -redis-command string  过滤命令（SET, GET 等，通配符支持）
  -redis-key string      按 key 正则过滤（Go regexp）

ROCKETMQ:
  -rmq-code int          按请求码过滤

MYSQL:
  -mysql-command string  按命令类型过滤（Query, Ping 等）
  -mysql-query string    按查询内容过滤（子串匹配）

MONGODB:
  -mongo-opcode int      按 opcode 过滤
```

---

## 时间戳与耗时

所有输出都带有毫秒精度的时间戳（`2006-01-02 15:04:05.000`），响应末尾显示耗时：

```
2026-01-02 09:22:11.651          ← 请求时间戳
10.0.0.5:45123 -----> ...
  SET  user:1001  ...
2026-01-02 09:22:11.654          ← 响应时间戳
10.0.0.5:45123 <----- ...
  [SimpleString] OK
  [3.12ms]                        ← 总耗时（请求→响应）
```

> 耗时从收到请求第一个字节开始计时，到收到完整响应为止。

---

## 工作原理

```
┌─────────────────────────────────────────────┐
│                   pcap (libpcap)             │
│                  网络数据包捕获               │
└─────────────────┬───────────────────────────┘
                  │ TCP packets
┌─────────────────▼───────────────────────────┐
│              TCP Assembler                   │
│           TCP 流重组（双向）                  │
└─────────────────┬───────────────────────────┘
                  │ Ordered byte streams
┌─────────────────▼───────────────────────────┐
│          Protocol Detector (auto)            │
│    依次尝试 dubbo→triple→redis→rocketmq      │
│         →mysql→mongo→http                   │
└─────────────────┬───────────────────────────┘
                  │ Detected protocol
┌─────────────────▼───────────────────────────┐
│          Protocol Handler                    │
│    解析协议消息 → 格式化 → MultiPrinter       │
└─────────────────┬───────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
  stdout      dubbo.log     redis.log  ...
```

---

## 要求

- **操作系统**：Linux（需要 `AF_PACKET` 支持）或 macOS
- **权限**：root 或 `CAP_NET_RAW`
- **依赖**：`libpcap`（安装见上方）
- **Go**：1.22+（编译时）

---

## License

MIT
