# SOCKS5 入口

0.25.0 增加 SOCKS5（RFC 1928/1929）TCP CONNECT 入口。它和 Shadowsocks 入口一样，由客户端在连接时指定目的地；规则本身没有固定目标，仍共享连接数、来源 ACL、额度、速率、跨节点用户份额、PROXY 前置和 TLS/WS 包装。

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
- 规则必须 `protocol=tcp`，且 `targets=[]`。SOCKS5 与 Shadowsocks 入口不能同时配置。
- 目前只实现 CONNECT；BIND 和 UDP ASSOCIATE 返回 SOCKS5 状态 7（命令不支持）。因此 `udp_max_sessions` 对 SOCKS5 无意义。
- 可以与入口 TLS、WebSocket/WSS、PROXY protocol 组合；处理顺序是 PROXY（位置按配置）→ TLS → WS → SOCKS5。
- 客户端来源 ACL、来源哈希、连接数、配额和限速沿用规则引擎。

## 分享链接

面板生成 `socks5://[user:password@]host:port#name`。链接包含认证信息，持有者即可使用入口；停用方法是删除规则或修改凭据。订阅模块目前只渲染 Shadowsocks，未把 SOCKS5 混入现有格式。

## 验证与限制

- 协议单元测试覆盖无认证域名 CONNECT、成功回复编码、用户名密码认证、错误密码和 UDP ASSOCIATE 拒绝。
- 真实 Engine 测试启动 SOCKS5 入口与 TCP 回显目标，完成握手、CONNECT、字节双向转发并关闭。
- 规则校验测试覆盖必须有 TCP、不能有固定目标、认证成对和两种代理入口互斥。
- 未测试真实浏览器/系统 SOCKS5 客户端矩阵、UDP ASSOCIATE、SOCKS5 over TLS 的客户端组合、认证暴力破解限速和完整性能。
- 模块 10 仍是部分实现：SOCKS5 是新增的一种入站协议，不代表 VLESS/REALITY/Hysteria2/TUIC 等其余协议已完成。
