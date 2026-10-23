# Relay 独立转发平台

这是从独立源码开始开发的控制服务、Agent 和 TCP/UDP 转发核心。原有压缩包及三个参考产品没有作为代码基础；网络、数据库、密码哈希和 TLS 客户端采用公开的成熟依赖。运行不需要商业产品激活。

**当前是开发中的 0.1.0 基础版本，完整目标尚未完成。** 已经打通真实数据转发、管理 API、节点同步、持久化计量和管理界面源码。完整范围保留在 [22 个模块验收清单](docs/REQUIREMENTS.md)，逐项状态见 [STATUS.md](docs/STATUS.md)。多路径聚合、组网、运营交易等仍需继续开发。

## 已打通的业务链路

1. 启动控制服务，生成私有管理员密码文件，登录管理界面或调用 API。
2. 创建节点，通过一次性注册令牌绑定独立节点凭据；注册响应丢失后可幂等重试。
3. 发布带修订号的规则，Agent 先准备全部新增监听，再提交配置。端口冲突保留旧版本。
4. 执行 TCP、UDP 或双协议转发，支持 IPv4/IPv6、域名目标、加权轮询、来源 IP 哈希和最少连接。
5. 按规则执行上下行合并配额、共享速率、到期和来源 CIDR 限制。
6. 先持久化接纳字节再转发；控制服务幂等接收累计账本。控制器断联时继续使用最后有效配置，恢复后补报。

系统管理员、租户管理员和只读用户的权限由服务端检查。配置历史、发布冲突检查、回滚发布、会话撤销、操作审计、SQLite 一致性备份均已实现基础路径。

## 构建和验证

本次构建环境为 macOS arm64、Rust/Cargo 1.99.1。包声明最低 Rust 1.89；其他工具链和 Linux 实机尚待验证。Node 只用于检查浏览器脚本，Web 资源无需 npm 构建。

```sh
cargo build --locked --release
rustup component add rustfmt clippy
sh scripts/verify.sh
```

可执行程序为 `target/release/relay`，管理界面直接编入二进制。`Cargo.lock` 固定依赖版本，第三方清单位于 [THIRD_PARTY.md](docs/THIRD_PARTY.md)。自有代码的对外发布许可尚未指定。

## 本机控制台

```sh
./target/release/relay server --listen 127.0.0.1:8080 --state ./state/controller
```

打开本机 `http://127.0.0.1:8080`，用户名 `admin`，首次密码位于 `state/controller/admin-password.secret`。密码不会打印到运行日志。数据库和初始密码文件采用私有权限；不要将运行状态目录放入源码包或公开站点。

在“节点总览”注册节点，将一次性令牌保存为权限 0600 的文件，然后启动 Agent：

```sh
./target/release/relay agent \
  --controller http://127.0.0.1:8080 \
  --node-id 注册后得到的节点ID \
  --enrollment-token-file ./state/enrollment.secret \
  --state ./state/agent
```

成功注册后，长期凭据保存在 Agent 私有数据库中。后续启动无需再次传入注册令牌；首次注册响应丢失时，本地已持久化的待注册身份可以继续重试。

跨机器控制连接要求有效 HTTPS，可通过反向代理接入。私有 CA 使用 `--ca-certificate`；没有跳过证书验证的选项。不要把管理界面的 127.0.0.1 地址作为另一台机器的控制地址。

## 离线转发与实际探测

准备两个终端，分别启动本地回显目标与转发程序：

```sh
python3 scripts/echo_fixture.py --port 19000
```

```sh
./target/release/relay validate --config examples/standalone.json
./target/release/relay standalone --config examples/standalone.json \
  --database ./state/standalone/agent.sqlite --watch
```

第三个终端执行：

```sh
python3 scripts/probe.py --host 127.0.0.1 --port 19001
./target/release/relay usage --database ./state/standalone/agent.sqlite
```

探测分别验证 TCP 和 UDP 的回显内容，任一失败会返回非零退出码。回显目标只监听本机。修改配置时递增 `revision`；同一版本不同内容和未知字段都会被拒绝。`--watch` 每两秒检查一次配置；停止程序使用 Ctrl-C 或 SIGTERM。

## 计量、限速与故障行为

- 配额单位为字节，计量口径是**已接纳的应用负载**，上下行合计；目标写入失败时也可能已计入额度。真正写出的字节另在节点运行统计中显示。
- `quota_bytes: null` 为不限量，`0` 为禁止接纳；`rate_bytes_per_sec` 是每秒字节，非 Mbps，且由规则内所有会话共享。
- 速率桶允许 `max(64 KiB, 一秒额度)` 的突发。当前没有跨规则、跨节点用户总预算，不能将多个本地额度当成一个全局额度。
- 计量周期由 `meter_epoch` 显式标识。改名称、重启、重复发布不会清零计量；重新分配周期需保留旧账。
- 未改变的规则保持连接；仅目标/均衡调整时，已有 TCP 使用原目标，新连接采用新目标。禁用、删除、协议、额度、到期、限速、空闲时间或 ACL 变化会终止关联会话。UDP 会话在空闲回收前继续使用原目标。
- 更换 UDP 监听地址会取消旧监听上的会话，限速等待不能长期占用旧端口。降低连接或会话上限时，已有会话自然排空，新会话按新上限准入。
- 无法持久化计量时拒绝负载。网络断联、控制端 5xx、429 或无效 JSON 不覆盖最后有效配置；身份、账本冲突等明确拒绝会停止 Agent，要求修复状态。
- `stats` 是本次进程的实际运行计数，重启后从零开始；累计账本持久保存。控制在线和实际业务健康分别判断。

更详细的模型见 [架构决定](docs/architecture.md) 与 [API 说明](docs/API.md)。

## 备份与部署范围

```sh
./target/release/relay backup --database ./state/controller/controller.sqlite \
  --output ./backups/controller.sqlite
```

备份使用 SQLite 在线备份接口，不覆盖已有文件。控制数据库含用户、节点凭据哈希、配置历史和上报账本；Agent 数据库含节点长期凭据、最后配置及本地计量，必须分别保护。恢复到旧时间点的 Agent 账本仍需和控制器对账，自动灾难恢复流程尚未完成；不要仅复制旧凭据到空数据库以替代迁机。

`deploy/` 提供 systemd 和 Caddy 配置模板，**尚未在 Linux 实机验收**，没有在你的机器安装服务或修改网络配置。控制服务模板使用 DynamicUser；Agent 模板需要先创建独立的 `relay-agent` 系统用户与组，将注册文件设为该用户可读的 0600 文件。默认使用 1024 以上业务端口，不赋予节点任意 shell 执行或 root 网络管理能力。

SQLite 版本限定单控制实例。PostgreSQL、控制面高可用、OpenRC、离线安装、签名升级与完整恢复演练仍属于待交付范围。

## 性能数据

```sh
python3 scripts/bench_loopback.py --mib 32 --rounds 5 \
  --output ./artifacts/benchmark.json
```

基准交替测量直连和转发，逐字节检查 TCP/UDP 回显，结束时核对持久化账本。当前结果见 [benchmark-local.json](docs/benchmark-local.json)，边界和验收记录见 [VALIDATION.md](docs/VALIDATION.md)。这是无 TLS 的本机回环烟测，不能推导实际线路吞吐，也没有证明优于 Realm 或另外两个参考产品。

管理页面的 HTML、JS 和 API 已实现；本次浏览器地址访问未获授权，视觉及点击验收未完成。
