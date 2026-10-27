# 0.46.0 稳定化：关闭 0.45 审查 P1

基线：`e7cb41a`（0.45.0）。0.46.0 不新增业务功能，先关闭独立审查 R1–R5，并把审查探针转为永久安全断言。

## 修复

| 编号 | 0.45 缺陷 | 0.46 修复 | 永久回归 |
| --- | --- | --- | --- |
| R1 | UDP 关联只按客户端 IP 注册，第二个客户端覆盖第一个，回复串流 | 每个控制连接绑定独立的临时 UDP 中继 socket，返回不同端点；每个关联只接受首个客户端 UDP 源端点，后续不同源端点丢弃 | `socks5_udp_associations_are_isolated_behind_one_ip` |
| R2 | DNS 任一地址命中允许列表即放行全部解析地址 | `DestinationPolicy::filter` 逐地址过滤；域名允许授权未拒绝的解析地址，IP/CIDR 只授权匹配地址；`resolve_destination` 只返回存活地址 | `ip_allowlist_filters_mixed_answers` + 审查 DNS 探针 |
| R3 | BIND 丢弃请求对端，任意入站连接成功 | `Request::Bind(Destination)` 保留请求地址/端口；匹配请求端点、来源 ACL、目的地 ACL 和私网策略，错误对端持续拒绝直到超时 | `socks5_bind_rejects_a_peer_outside_the_requested_policy` |
| R4 | UDP 回复任务只随规则取消，控制连接关闭后仍转发 | 关联任务绑定控制连接取消令牌；控制 EOF 取消并等待关联退出；回复任务检查取消；限速/计量等待也可取消 | `socks5_udp_replies_stop_with_the_control_connection` |
| R5 | 配置激活失败时无限续租旧用户限速，新限制不生效 | `Engine::reconcile_user_shares` 以新份额覆盖同一 owner，同时保留未出现在失败修订中的旧 owner；失败激活不再只续租旧值 | `lower_limit_applies_during_a_rejected_revision` |

## UDP 加固

- 每个关联使用独立 UDP socket，不再共享 IP 键注册表。
- 只接受关联首个 UDP 源端点；源端口变化被拒绝，避免同 NAT 串流。
- 出口回复只接受该关联实际发送过的目标地址；其他源端口的非预期回复丢弃。
- 关联级 IPv4/IPv6 出口 socket 和回复任务随控制连接/规则取消退出。
- 上传/下载计量与限速仍生效；取消可打断限速等待。
- 目标 ACL 在解析后逐地址过滤，UDP 与 TCP/代理路径共用。

## BIND 策略

- 请求端点：具体 IP/端口必须匹配；`0.0.0.0`/`::` 和端口 0 分别表示通配。
- 入站对端还必须通过规则来源 ACL、目的地 ACL 和 `allow_private_destinations`。
- 不匹配的对端被丢弃并继续等待；超时返回 SOCKS5 失败状态。
- 域名形式的 BIND 请求当前拒绝（返回失败），避免未定义的 DNS 对端语义。

## 验证

- 0.45 审查的五个探针在修复后均不再复现（探针本身以“缺陷复现”为 PASS，因此修复后返回非零并输出 `defect_reproduced=false`）。
- 原有 SOCKS5 CONNECT/UDP、HTTP CONNECT、Shadowsocks、ACL、模板、MPTCP 观测、NAT-PMP/PCP/UPnP 回归保持通过。
- 未声称完成 0.45 审查范围外的 Linux、真实客户端、浏览器点击、真实路由器、商业或 72 小时验收。
