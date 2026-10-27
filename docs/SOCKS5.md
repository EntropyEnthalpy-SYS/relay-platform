# SOCKS5 入口

0.25.0 增加 SOCKS5（RFC 1928/1929）TCP CONNECT 入口；0.35.0 增加 UDP ASSOCIATE。它和 Shadowsocks 入口一样，由客户端在连接时指定目的地；规则本身没有固定目标，仍共享连接数、来源 ACL、额度、速率、跨节点用户份额、PROXY 前置和 TLS/WS 包装。

## 配置

```json
{
  "inbound_socks5": {
    "username": "user",
    "password": "secret",
    "allow_private_destinations": false
  }
}
```

- `username` 与 `password` 必须同时填写（各 1..255 字节，不含控制字符），或同时省略。启用认证时使用 RFC 1929 用户名/密码子协商；未启用时只接受无认证方法。
- `allow_private_destinations=false` 默认拒绝回环、私网、链路本地、组播等非公网目标，和 Shadowsocks 的默认策略一致。设为 `true` 仅用于本机/内网测试。
- 规则必须 `targets=[]`。TCP CONNECT/BIND 可使用 `protocol=tcp`；UDP ASSOCIATE 需要 `protocol=both` 且单监听端口。SOCKS5 与 Shadowsocks、HTTP CONNECT 入口不能同时配置。
- BIND 在控制连接上返回临时监听地址，等待入站 TCP 连接后返回第二份绑定地址并双向转发；请求的具体地址/端口必须匹配，通配地址/端口分别放宽；入站对端还须通过来源 ACL、目的地 ACL 和私网策略。等待受 `connect_timeout_ms` 和规则取消约束；不匹配对端被丢弃后继续等待，超时返回失败。域名 BIND 请求当前拒绝。
- UDP ASSOCIATE 的控制连接保持打开；每个关联获得独立的临时 UDP 中继端点，客户端向该端点发送带 SOCKS5 UDP 头的报文。服务器只接受关联首个 UDP 源端点，按目标解析/ACL 转发并包装来源地址回复；其他源端点和其他回复源被丢弃。控制连接关闭会取消并等待中继任务退出。
- 可以与入口 TLS、WebSocket/WSS、PROXY protocol 组合；处理顺序是 PROXY（位置按配置）→ TLS → WS → SOCKS5。
- 客户端来源 ACL、来源哈希、连接数、配额和限速沿用规则引擎。

## 分享链接

面板生成 `socks5://[user:password@]host:port#name`。链接包含认证信息，持有者即可使用入口；停用方法是删除规则或修改凭据。订阅模块目前只渲染 Shadowsocks，未把 SOCKS5 混入现有格式。

## 验证与限制

- 协议单元测试覆盖无认证域名 CONNECT、成功回复编码、用户名密码认证、错误密码和 UDP ASSOCIATE 拒绝。
- 真实 Engine 测试启动 SOCKS5 入口与 TCP 回显目标，完成握手、CONNECT、字节双向转发并关闭。
- 规则校验测试覆盖必须有 TCP、不能有固定目标、认证成对和两种代理入口互斥。
- UDP ASSOCIATE 测试使用真实 TCP 控制连接、UDP 回显目标和 SOCKS5 头，验证关联、目标转发、16 个连续数据报和回复；每个关联复用 IPv4/IPv6 出口 UDP socket 与响应任务，减少每包建 socket 的开销。UDP 载荷计入规则计量与限速。
- 未测试真实浏览器/系统 SOCKS5 客户端矩阵、UDP 分片、多目标高并发吞吐、SOCKS5 over TLS 的客户端组合、认证暴力破解限速和正式性能报告；出口 socket 按地址族复用，但未按目标分别复用或做背压。
- 模块 10 仍是部分实现：SOCKS5 是新增的一种入站协议，不代表 VLESS/REALITY/Hysteria2/TUIC 等其余协议已完成。
