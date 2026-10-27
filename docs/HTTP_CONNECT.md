# HTTP CONNECT 入口

0.32.0 增加 HTTP/1.x CONNECT 代理入口，作为多协议模块的又一种 TCP 入站。它和 Shadowsocks/SOCKS5 一样由客户端指定目的地，规则没有固定目标。

## 配置

```json
{
  "inbound_http_connect": {
    "username": "user",
    "password": "secret",
    "allow_private_destinations": false
  }
}
```

- 只接受请求行 `CONNECT authority HTTP/1.0|1.1`；其他方法返回 405。
- `authority` 支持 IPv4、IPv6（`[::1]:443`）和域名加端口；端口不能为 0。
- 未配置用户名/密码时无认证；配置时必须成对。认证使用 `Proxy-Authorization: Basic base64(user:password)`，缺失/错误返回 407，并带 `Proxy-Authenticate: Basic`。
- 默认拒绝回环/私网/链路本地等非公网目的地；测试可显式允许。
- 规则必须 `protocol=tcp`、`targets=[]`，且不能同时配置 Shadowsocks 或 SOCKS5 入口。
- 可与入口 TLS、WebSocket/WSS、PROXY protocol 组合；处理顺序为 PROXY（按位置）→ TLS → WS → HTTP CONNECT。
- 连接目标成功后才返回 `200 Connection Established`；失败返回 502。连接后按原始字节双向转发，复用统一 ACL、配额、限速、用户份额和路由。

## 分享

面板生成 `http://[user:password@]host:port#name`。这是 HTTP 代理地址，不是可浏览网页；链接含凭据，停用需删除规则或轮换凭据。订阅模块目前仍只渲染 Shadowsocks。

## 验证与限制

- 协议单元测试覆盖域名 CONNECT、成功响应、Basic 认证、缺失认证 407、私网标志和成功路径。
- 真实 Engine 测试启动入口与 TCP 回显目标，完成 CONNECT、200 响应、双向字节转发和关闭。
- 规则校验覆盖 TCP-only、无固定目标、认证成对、与 SOCKS5 互斥。
- 未测试真实浏览器/系统代理矩阵、HTTP/2 CONNECT、absolute-form HTTP 代理、Digest/NTLM、认证暴力破解限速、TLS/WS 客户端组合和性能。模块 10 仍为部分实现。
