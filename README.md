# tcpshow

> TCP 流量分析工具 — 支持 Dubbo、Redis、MySQL、MongoDB、RocketMQ、HTTP

`tcpshow` 是服务器端的 TCP 流量抓包分析工具，无需客户端配置即可实时捕获和解析应用层协议流量。

## 功能

- 🎯 **自动协议检测** — 无需指定协议，自动识别 6 种常见协议
- 📦 **子命令模式** — `tcpshow redis`、`tcpshow mysql` 等，独立参数
- ⏱️ **毫秒级耗时** — 每次请求-响应显示精确耗时
- 🔍 **协议专用过滤** — 正则匹配 key、wildcard 匹配 service/method、SQL 子串
- 💰 **耗时过滤** — `-C 100+` 只看慢请求（100ms 以上）
- 📁 **按协议分类输出** — `-o /tmp/logs/` 生成 `redis.log`、`mysql.log` 等
- 🐳 **容器友好** — 可监控容器内 Java 进程的所有端口
- 🏗️ **全平台** — Linux amd64/arm64、macOS arm64、CentOS 7 专用版

## 安装

从 [Releases](https://github.com/carlvine500/tcpshow/releases) 下载对应平台的二进制，或从源码编译：

```bash
git clone https://github.com/carlvine500/tcpshow.git
cd tcpshow
go build -o tcpshow .
```

**CentOS 7 用户**：请下载 `tcpshow-linux-amd64-centos7` 专用版本（glibc 2.17 兼容）。

**macOS 用户**：需要安装 libpcap：
```bash
brew install libpcap
```

## 快速开始

```bash
# 监听所有协议（自动检测）
sudo tcpshow

# 只监听 Redis
sudo tcpshow redis

# 监听指定网卡
sudo tcpshow -i eth0

# 读取 pcap 文件
tcpshow -r capture.pcap
```

## 子命令

| 子命令 | 别名 | 描述 |
|--------|------|------|
| `dubbo` | `d` | Dubbo/Triple RPC |
| `redis` | `r` | Redis RESP |
| `mysql` | `m` | MySQL |
| `mongo` | — | MongoDB |
| `rocketmq` | `rmq` | RocketMQ Remoting |
| `http` | — | HTTP/1.x |
| `websocket` | `ws` | WebSocket |
| `zookeeper` | `zk` | ZooKeeper |
| `nacos` | — | Nacos HTTP API |
| *(无)* | — | 自动检测所有协议 |

## 全局参数

| 参数 | 短写 | 默认值 | 说明 |
|------|------|--------|------|
| `-i <iface>` | `-i` | `any` | 网络接口 |
| `-r <file>` | `-r` | — | 读取 pcap 文件 |
| `--ip <ip>` | — | — | 按 IP 过滤 |
| `--port <port>` | — | — | 按端口过滤 |
| `-o <dir>` | `-o` | — | 按协议输出文件到目录 |
| `-l <level>` | `-l` | `all` | 输出级别：`url` / `all` |

## 协议专用参数

### Dubbo

| 参数 | 短写 | 说明 |
|------|------|------|
| `--service <wildcard>` | `-s` | 按服务名过滤 |
| `--method <wildcard>` | `-m` | 按方法名过滤 |
| `--cost <filter>` | `-C` | 耗时过滤 |

### Redis

| 参数 | 短写 | 说明 |
|------|------|------|
| `--key <regex>` | `-k` | 按 key 正则过滤 |
| `--cmd <wildcard>` | `-c` | 按命令过滤 (GET/SET/...) |
| `--cost <filter>` | `-C` | 耗时过滤 |

### MySQL

| 参数 | 短写 | 说明 |
|------|------|------|
| `--cmd <wildcard>` | `-c` | 按命令类型过滤 |
| `--query <substring>` | `-q` | 按 SQL 子串过滤 |
| `--cost <filter>` | `-C` | 耗时过滤 |

### MongoDB

| 参数 | 短写 | 说明 |
|------|------|------|
| `--opcode <code>` | — | 按 opcode 过滤 |
| `--cost <filter>` | `-C` | 耗时过滤 |

### RocketMQ

| 参数 | 短写 | 说明 |
|------|------|------|
| `--code <code>` | — | 按请求码过滤 |
| `--cost <filter>` | `-C` | 耗时过滤 |

### HTTP

| 参数 | 短写 | 说明 |
|------|------|------|
| `--cost <filter>` | `-C` | 耗时过滤 |

### WebSocket

| 参数 | 短写 | 说明 |
|------|------|------|
| `--cost <filter>` | `-C` | 耗时过滤 |

### ZooKeeper

| 参数 | 短写 | 说明 |
|------|------|------|
| `--cost <filter>` | `-C` | 耗时过滤 |

### Nacos

| 参数 | 短写 | 说明 |
|------|------|------|
| `--cost <filter>` | `-C` | 耗时过滤 |

## 耗时过滤 `-C` / `--cost`

| 表达式 | 含义 |
|--------|------|
| `100+` 或 `+100` | 耗时 ≥ 100ms |
| `100-` 或 `-100` | 耗时 ≤ 100ms |
| `50-200` | 耗时在 50ms ~ 200ms 之间 |
| `100` | 耗时恰好 100ms |

## 示例

```bash
# 只看耗时大于 100ms 的 MySQL 查询
sudo tcpshow mysql -q tableName -C 100+

# 只看特定 service 的 Dubbo 调用
sudo tcpshow dubbo -s com.example.UserService

# 只看 Redis GET 命令，key 匹配 session:*
sudo tcpshow redis -k 'session:*' -c GET

# 监听容器内 Java 进程的多端口混合流量
sudo tcpshow -i eth0 --ip 172.17.0.2

# 按协议分类输出到文件
sudo tcpshow -o /tmp/tcp-logs/

# 从 pcap 文件分析
tcpshow -r dump.pcap mysql -q 'SELECT.*FROM orders'

# 只看 50-200ms 的 Redis 操作
sudo tcpshow redis -C 50-200
```

## 帮助

```bash
tcpshow -h              # 全局帮助 + 子命令列表
tcpshow redis -h        # Redis 专属帮助
tcpshow dubbo -h        # Dubbo 专属帮助
```

## 输出格式

```
2026-07-25 07:09:35.328 [172.38.100.213:58004 -----> 172.38.100.66:27017]
  OP_MSG find (body=676 bytes)
  BSON: {"find":"orders","filter":{"status":"pending"},"$db":"mydb"}
  Command: find
  RequestID: 16441  ResponseTo: 0

2026-07-25 07:09:35.335 [172.38.100.213:58004 <----- 172.38.100.66:27017] (7ms)
  OP_MSG cursor (body=1286 bytes)
  BSON: {"cursor":{"firstBatch":[...],"id":0,"ns":"mydb.orders"},"ok":1}
  Command: cursor
  RequestID: 172384538  ResponseTo: 16441
```

- **时间戳** + **连接方向** 同行
- **耗时** 紧跟响应行括号内（如 `(7ms)`）
- **BSON** 行显示 MongoDB 查询/响应 JSON

## 权限

抓包需要 root 权限或 `CAP_NET_RAW` capability：

```bash
sudo tcpshow redis
# 或
sudo setcap cap_net_raw+ep tcpshow
./tcpshow redis
```

## 与 tshark 对比

tshark (Wireshark 的命令行版) 是强大的万能网络分析器，但 tcpshow 在以下场景做它做不到的事：

### tshark 能做 ✅（tcpshow 也支持）

```bash
tshark -i eth0 -Y redis          # 过滤 Redis
tshark -i eth0 -Y mysql.query    # 过滤 MySQL 查询
tshark -r file.pcap -Y http      # 读 pcap 文件
```

### tshark 做不到 ❌（tcpshow 核心差异）

**1. Dubbo / Triple / RocketMQ 协议解析**

这三种是 Java 生态特有的二进制协议，tshark 没有内置解析器。tcpshow 自实现了完整协议栈：
- Dubbo 2.x（Hessian2/compactjava 序列化）
- Triple（Dubbo 3.x，基于 HTTP/2 + Protobuf）
- RocketMQ Remoting（自定义二进制协议）

```bash
tcpshow dubbo -s com.example.* -m getUser
tcpshow rocketmq --code 10
```

**2. 请求-响应配对 + 耗时计算**

tshark 把每个包独立展示，不关联请求和响应。tcpshow 将 TCP 流中的请求-响应配对，计算精确耗时：

```
# tshark — 两个独立包，不关联
Frame 1: 192.168.1.1:12345 → 192.168.1.2:3306  [Query: SELECT...]
Frame 2: 192.168.1.2:3306 → 192.168.1.1:12345  [Response...]

# tcpshow — 成对展示，带耗时
2026-07-25 07:09:35.328 [192.168.1.1:12345 -----> 192.168.1.2:3306]
  Query: SELECT * FROM orders WHERE status='pending'
2026-07-25 07:09:35.987 [192.168.1.2:3306 <----- 192.168.1.1:12345] (659ms)
  OK, 42 rows affected
```

**3. 基于耗时的过滤**

`-C 100+` 只看慢于 100ms 的请求——tshark 没有"先算耗时再过滤"的能力，因为 tshark 不配对请求响应。

```bash
tcpshow mysql -q tableName -C 100+    # 只看慢查询
tcpshow redis -C 50-200               # 50~200ms
tcpshow dubbo -C -50                  # ≤50ms 的快请求
```

**4. BSON 正文解析为 JSON**

tshark 解析 MongoDB 协议时只显示 opcode，不解析 BSON 内容：

```bash
# tshark
OP_MSG find (body=676 bytes)

# tcpshow
OP_MSG find (body=676 bytes)
  BSON: {"find":"orders","filter":{"status":"pending"},"limit":50,"$db":"mydb"}
```

**5. 简洁的专项过滤语法**

```bash
# tshark — 需要记复杂的 display filter
tshark -Y 'mysql.query contains "tableName"' 

# tcpshow
tcpshow mysql -q tableName
```

### 能力矩阵

| 能力 | tshark | tcpshow |
|------|:------:|:-------:|
| 抓包 / 读 pcap | ✅ | ✅ |
| TCP 流重组 | ✅ | ✅ |
| HTTP / Redis / MySQL / MongoDB 解析 | ✅ | ✅ |
| WebSocket / ZooKeeper 解析 | ✅ | ✅ |
| Nacos 协议解析 | ❌ | ✅ |
| Dubbo / Triple / RocketMQ 解析 | ❌ | ✅ |
| 请求-响应配对 + 耗时 | ❌ | ✅ |
| 耗时过滤 (`-C 100+`) | ❌ | ✅ |
| BSON → JSON 展示 | ❌ | ✅ |
| 子命令简写 + 协议专属帮助 | — | ✅ |

> **选型建议：** 如果你只抓 HTTP/MySQL 包并用 Wireshark 图形界面分析细节，tshark + Wireshark 是更全面的选择。如果你需要在服务器终端快速排查 Dubbo 调用链、定位慢 Redis/MySQL/MongoDB 查询、或监控 RocketMQ 消息流量，tcpshow 更直接。

## License

MIT
