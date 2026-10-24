# Relay 独立转发平台

这是从独立源码开始开发的控制服务、Agent 和 TCP/UDP 转发核心。原有压缩包及三个参考产品没有作为代码基础；网络、数据库、密码哈希和 TLS 实现采用公开的成熟依赖。运行不需要商业产品激活。

**当前是开发中的 0.6.0 开发版本，完整目标尚未完成。** 已经打通真实数据转发、管理 API、节点同步、持久化计量和管理界面源码。完整范围保留在 [22 个模块验收清单](docs/REQUIREMENTS.md)，逐项状态见 [STATUS.md](docs/STATUS.md)。多路径聚合、组网、运营交易等仍需继续开发。

## 已打通的业务链路

1. 启动控制服务，生成私有管理员密码文件，登录管理界面或调用 API。
2. 创建节点，通过一次性注册令牌绑定独立节点凭据；注册响应丢失后可幂等重试。
3. 发布带修订号的规则，Agent 先准备全部新增监听，再提交配置。端口冲突保留旧版本。
4. 执行 TCP、UDP 或双协议转发，支持 IPv4/IPv6、域名目标、加权轮询、来源 IP 哈希和最少连接。
5. 按规则执行上下行合并配额、共享速率、到期和来源 CIDR 限制。
6. 先持久化接纳字节再转发；控制服务幂等接收累计账本。普通断网重启使用最后有效配置，从备份恢复先对账再开放监听。
7. 为 TCP 入口、出口选择 TLS，支持私有 CA、服务名验证和可选双向证书认证；私钥只留在节点本地。
8. 为用户、租户和节点创建总额度，通过持久化预留在多个 Agent 上共同执行。正常空闲或停止归还剩余额度；异常重启保守保留旧预留。
9. 控制器默认记录独立恢复日志。使用数据库备份、完整日志和最新进度清单，可恢复备份之后的节点身份、配置、权限及额度记录。

0.6.0 增加端口段与固定/偏移映射、业务出口 IP/网卡绑定、按真实响应 TTL 缓存目标 DNS，以及节点内监听环路检查。端口段共用规则额度、速率与会话上限。字段、升级注意事项和支持边界见 [ROUTING.md](docs/ROUTING.md)。

系统管理员、租户管理员和只读用户的权限由服务端检查。配置历史、发布冲突检查、回滚发布、会话撤销、操作审计、SQLite 一致性备份均已实现基础路径。

## 构建和验证

本次构建环境为 macOS arm64、Rust/Cargo 1.99.1。包声明最低 Rust 1.89；其他工具链和 Linux 实机尚待验证。构建需要 C 编译器和 libclang，用于 SQLite Session 扩展的构建期绑定生成；运行程序不需要 libclang。Node 只用于检查浏览器脚本，Web 资源无需 npm 构建。测试还需要 Python 3，以及 PATH 中的 OpenSSL 或 LibreSSL（只在临时目录生成测试证书）。

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

0.5.0 默认合并短时间内到达的节点同步请求，最多等 2 ms、每批最多 16 个请求，共享一次持久化提交。队列最多保留 64 个待处理请求，满时返回 429，Agent 稍后重试。参数 `--sync-batch-size 1` 可关闭合并以做同条件对比，允许范围 1..16。每个请求单独校验、单独回滚；全部日志确认完成后才响应，额度粒度与持久化屏障保持不变。“恢复保护”页面包含本次运行的同步统计。

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

## 业务 TLS

TLS 安全层独立于目标地址。入口和出口可以分别启用；启用后仅允许 TCP。一条规则不能混合明文与 TLS 出口，证书验证失败不会回退到明文。

节点本地证书目录示例：

```text
state/agent/tls/
  entrance-v1/cert.pem     # 叶证书及中间证书链
  entrance-v1/key.pem      # 匹配的 PEM 私钥，权限 0600
  trust-v1/ca.pem          # 自定义信任根
  client-v1/cert.pem       # 可选：出口客户端证书
  client-v1/key.pem        # 可选：出口客户端私钥，权限 0600
```

`relay agent` 默认读取 `STATE/tls`；可用 `--tls-directory` 明确指定。`standalone` 的自定义证书必须用此参数指定目录。证书编号只接受字母、数字、下划线和连字符；目录与证书文件必须是真实目录/文件，编号不能指定任意磁盘路径。证书目录不可由组或其他用户写入。

入口配置例如 `"inbound_tls":{"identity":"entrance-v1","client_ca":"trust-v1"}`。`client_ca:null` 不要求客户端证书；指定 CA 后只接纳该信任根下的有效客户端证书。每个目标可添加 `"tls":{"server_name":"relay.example.com","ca":"trust-v1","identity":"client-v1"}`；`ca:null` 使用随依赖固定的公共根，`identity:null` 不提交客户端证书。面板提供相应字段，不收集私钥。

TLS 1.2/1.3 使用 rustls；没有跳过证书验证或启用早期数据的配置。握手受连接超时和并发上限约束。错误证书、服务名和私钥匹配都不会静默通过。计量仍按解密后的应用负载，TLS 开销不计入当前规则额度。

更新文件后发布新修订才会加载新证书；建议使用新的证书编号。材料或 TLS 安全参数变化会终止旧会话。文件缺失、私钥权限不合规或证书与私钥不匹配时保留旧配置。自动签发、续期、吊销列表与 WebSocket/WSS 尚未实现。

## 计量、限速与故障行为

- 配额单位为字节，计量口径是**已接纳的应用负载**，上下行合计；目标写入失败时也可能已计入额度。向传输流成功写入并刷出的应用字节另在节点运行统计中显示；这不等于远端应用已经收到。
- `quota_bytes: null` 为不限量，`0` 为禁止接纳；`rate_bytes_per_sec` 是每秒字节，非 Mbps，且由规则内所有会话共享。
- 速率桶允许 `max(64 KiB, 一秒额度)` 的突发。跨节点用户总**流量额度**已接入；跨节点总**速率**、公平分配和节点硬速率上限仍待实现。
- 计量周期由 `meter_epoch` 显式标识。改名称、重启、重复发布不会清零计量；重新分配周期需保留旧账。
- 未改变的规则保持连接；仅目标/均衡调整时，已有 TCP 使用原目标，新连接采用新目标。禁用、删除、协议、TLS 安全策略/材料、额度、到期、限速、空闲时间或 ACL 变化会终止关联会话。UDP 会话在空闲回收前继续使用原目标。
- 更换 UDP 监听地址会取消旧监听上的会话，限速等待不能长期占用旧端口。降低连接或会话上限时，已有会话自然排空，新会话按新上限准入。
- 无法持久化计量时拒绝负载。网络断联、控制端 5xx、429 或无效 JSON 不覆盖最后有效配置；身份、账本冲突等明确拒绝会停止 Agent，要求修复状态。
- `stats` 是本次进程的实际运行计数，重启后从零开始；累计账本持久保存。控制在线和实际业务健康分别判断。

更详细的模型见 [架构决定](docs/architecture.md) 与 [API 说明](docs/API.md)。

## 跨节点共享额度

在“共享额度”中为用户、租户或节点设置字节总额与单次预留大小。引入新额度前，要先停用相关规则，并等所有相关节点确认配置；创建后重新启用规则时，控制器会自动绑定适用额度。回滚配置或编辑规则不会移除这种绑定。一个数据包要同时满足规则及所有适用层级的额度。

控制器保证“已消费 + 尚未归还的预留 ≤ 总额度”。Agent 持有独立预留，在本地事务中扣量后才转发；预留用完前申请补充。TCP 在补额期间保留尚未转发的缓冲内容，UDP 必须整包获准。单个 UDP 包大于预留批次时可请求至少容纳该包的额度，仍受剩余总额约束。

进程持续运行但控制器断联时，只能使用已经拿到的预留。进程重新启动后不再消费或归还上次运行中尚未封存的预留，需要在线领取新额度。这样会保守占用部分额度；周期重置、异常预留回收和完整恢复流程仍待实现。正常情况下，节点所有业务会话空闲或有序停止时会封存并归还未用部分。详情及边界见 [BUDGETS.md](docs/BUDGETS.md)。

## 备份与部署范围

```sh
./target/release/relay backup --database ./state/controller/controller.sqlite \
  --output ./backups/controller.sqlite
```

备份使用 SQLite 在线备份接口，不覆盖已有文件。控制数据库含用户、节点凭据哈希、配置历史和上报账本；Agent 数据库含节点长期凭据、最后配置及本地计量，必须分别保护。备份工具会在导出的受管 Agent 数据库中设置恢复标记，不改变正在运行的数据库。恢复文件后首次启动先逐页对账，将已确认累计值作为下限；断网、分页中断或新配置应用失败时均不开启旧监听。普通在线状态库重启仍可断网运行。控制器进程身份变化会让在线 Agent 重新核对确认位置，补报被旧控制器快照遗忘的数据。

恢复 Agent 时先停止旧实例，将工具产生的节点备份放进新的私有状态目录，使用原节点 ID 和控制器地址启动；证书、CA、私钥目录须另行保管和恢复，SQLite 备份不包含它们。同一路径有实例锁，但跨机器复制出的同一身份不能靠本地锁互斥。不要同时运行原 Agent 与恢复副本。

0.4.0 的控制器默认在 `STATE/recovery.log` 记录数据库变更，并维护 `recovery.log.head.json`。可以用 `server --recovery-log` 将日志写在已创建的另一个私有目录；自动异地复制与日志轮换尚未实现。只有旧数据库备份会缺少之后已发放的额度，因此导出文件仍带分配隔离标记，不能直接清除。

停止原控制器后，使用启用日志之后生成的备份及最新完整日志恢复：

```sh
./target/release/relay restore --backup ./backups/controller.sqlite \
  --recovery-log ./state/controller/recovery.log --output ./state/restored-controller
./target/release/relay server --state ./state/restored-controller --listen 127.0.0.1:8080
```

输出目录必须尚不存在；日志相邻的最新 `.head.json` 必须一起保留。命令校验连续性并重放变更，成功后恢复原控制器的额度分配状态，原备份和日志不变。管理页面“恢复保护”显示日志状态；发生日志写入故障会停止后续写入，健康检查返回 503。完整步骤及失败处理见 [RECOVERY.md](docs/RECOVERY.md)。

恢复只能使用仍然保存的数据；尚未上报且已从节点磁盘丢失的数据无法凭空重建。哈希链不能证明同时回退的日志及进度清单是最新版本。完整节点身份租约、异常预留恢复、双端数据同时丢失、密钥迁机和异地存储仍待完善，不能称为完整灾难恢复。

`deploy/` 提供 systemd 和 Caddy 配置模板，**尚未在 Linux 实机验收**，没有在你的机器安装服务或修改网络配置。控制服务模板使用 DynamicUser；Agent 模板需要先创建独立的 `relay-agent` 系统用户与组，将注册文件设为该用户可读的 0600 文件。默认使用 1024 以上业务端口，不赋予节点任意 shell 执行或 root 网络管理能力。

0.4.0 会把状态库迁移到 schema v4，增加恢复检查点和已取消预留请求记录；v1/v2/v3 数据可迁移。受管 v1 节点第一次升级仍需要控制器在线。控制器和 Agent 需要协调升级：0.4.0 扩展了严格校验的额度同步字段，与 0.3.0 混用会被拒绝。迁移前保留旧备份；旧二进制拒绝 v4 数据库，不能直接降级。升级前的控制器备份没有连续恢复日志，不能使用新日志恢复；升级后应生成新的基线备份。

SQLite 版本限定单控制实例。PostgreSQL、控制面高可用、OpenRC、离线安装、签名升级与完整恢复演练仍属于待交付范围。

0.5.0 继续使用 schema v4 和 0.4.0 的节点同步字段、日志格式，现有 v4 日志可以继续使用。合并提交改变的是一次数据库事务包含的节点请求数量，不改变日志的确认顺序。

## 性能数据

```sh
python3 scripts/bench_loopback.py --mib 32 --rounds 5 \
  --output ./artifacts/benchmark.json
```

基准交替测量直连和转发，逐字节检查 TCP/UDP 回显，结束时核对持久化账本。当前结果见 [benchmark-local.json](docs/benchmark-local.json)，边界和验收记录见 [VALIDATION.md](docs/VALIDATION.md)。这是无 TLS 的本机回环烟测，不能推导实际线路吞吐，也没有证明优于 Realm 或另外两个参考产品。

另外可运行 `python3 scripts/bench_budget.py --output artifacts/benchmark-budget.json`，在两个实际 Agent 进程间比较启用共享额度前后的吞吐，并核对控制端、Agent、总额度三份计量以及有序停止后的预留归还。它仍是本机回环测试。

0.4.0 新增严格控制器恢复日志后，小批次补额出现显著吞吐回退。本机 4 MiB 预留、8 总连接约 0.32 Gbps，32 MiB 预留约 2.97 Gbps；完整条件见 `VALIDATION.md`。后续优先优化合并提交和补额调度，此开发版尚未达到最终性能目标。

0.5.0 已加入合并提交：同一二进制、4 MiB 预留、8 总连接，关闭合并约 0.322 Gbps，默认合并约 1.277 Gbps；32 MiB 预留约 4.412 Gbps。32 个模拟节点的控制 API 中位处理率为 342.1 请求/秒，关闭合并为 52.8。控制 API 与实际转发是两套基准，均不代表 Linux/WAN 结果。可用 `python3 scripts/bench_sync.py --output artifacts/benchmark-control-sync.json` 重跑控制面交替对比。

管理页面的 HTML、JS 和 API 已实现；本次浏览器地址访问未获授权，视觉及点击验收未完成。
