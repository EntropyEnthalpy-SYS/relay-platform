# 本机并发吞吐与延迟报告

## 0.39.0 SOCKS5 UDP（2026-10-27）

固定条件：macOS 27.0.1 arm64、Apple M1 Pro、10 逻辑 CPU、32 GiB；Release 二进制 `relay 0.39.0`，SHA-256 `828d025867ea52affd81884e02193baea2a3874d7ef2a37dce9498dc49686694`；Python 3.14 UDP 回显、本机 loopback、无 TLS/WAN。场景为 SOCKS5 TCP 控制连接 + UDP ASSOCIATE，1000 个 1200 字节载荷、32 窗口，逐个校验 SOCKS5 头与回显载荷。完整数据见 [performance-socks5-udp-0.39.0.json](performance-socks5-udp-0.39.0.json)。

| 指标 | 结果 |
| --- | ---: |
| 数据报 | 1000 |
| 载荷 | 1200 B |
| 收到/丢失 | 1000 / 0 |
| 批次 RTT p50 | 0.034 ms |
| 批次 RTT p95 | 0.045 ms |
| Goodput | 265.2 Mbit/s |

### 解释与边界

- 这是 SOCKS5 UDP 的 loopback 冒烟数据，验证 0.36.0 的关联级 socket 复用和 0.37.0 的计量路径不会破坏转发；数字只对该二进制、硬件和 Python 回显有效。
- 不是 WAN、真实 SOCKS5 客户端、UDP 分片、多目标并发、TLS、CPU/RSS 采样、72 小时稳定性或生产 SLA；没有做与直连/iPerf3/竞品的对照。
- 脚本是 `scripts/bench_socks5_udp.py`，报告由同一 Release 二进制生成。

## 0.33.0（2026-10-27）

固定条件：macOS 27.0.1 arm64、Apple M1 Pro、10 逻辑 CPU、32 GiB；Rust/Cargo 1.99.1；Release 二进制 `relay 0.33.0`，SHA-256 `1496361474ae752afe06e65f17949acbeb6587bceef81c22b260fba70e902802`。Python 回显目标、本机 loopback、无 TLS、无 WAN、无其他并发负载；每连接 8 MiB、3 轮、直连与经 Relay 交替运行。完整数据见 [performance-0.33.0.json](performance-0.33.0.json)。

| 连接数 | 直连中位吞吐 | Relay 中位吞吐 | Relay/直连 | 直连 p95 连接耗时 | Relay p95 连接耗时 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 10,270 Mbit/s | 5,180 Mbit/s | 0.504 | 6.46 ms | 12.89 ms |
| 8 | 11,259 Mbit/s | 10,239 Mbit/s | 0.909 | 47.4 ms | 52.1 ms |
| 32 | 9,653 Mbit/s | 9,123 Mbit/s | 0.945 | 221.9 ms | 235.0 ms |

UDP 200 个 1,200 字节数据报：直连 RTT 中位 41.5 µs、p95 74.9 µs；Relay RTT 中位 81.8 µs、p95 165.4 µs，零失败。计量账本记录 2,066,174,720 字节，与预期逐字节一致；没有重复计量。

### 解释与边界

- 单连接吞吐约为直连的一半，符合单连接逐块转发与 Python 回显的额外拷贝；8/32 连接时中位吞吐达到直连的 91%/95%。32 连接 p95 约 235 ms，说明高并发下尾部延迟明显增加，不能据此声称生产 SLA。
- 这是 loopback 冒烟基准，不是两台真实 Linux 节点、跨 WAN、TLS、真实客户端、iperf3 或竞品对照；没有 CPU/RSS 采样、72 小时稳定性、故障注入或最大吞吐声明。
- 结果只对上述二进制、硬件、内核和负载条件有效；改变缓冲、Python 回显或并发数会改变数字。
