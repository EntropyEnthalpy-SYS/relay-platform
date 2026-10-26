# 签名离线包与 Linux 部署工具

0.18.0 提供 `scripts/relay_deploy.py`：生成签名离线包、独立验签、系统预检、安装、停止状态下的升级/回滚、安装中断恢复、保留状态的卸载及重装。工具使用 Python 标准库和 OpenSSL/兼容 LibreSSL 命令，不下载二进制、依赖或远程脚本。

0.19.0 在 Debian 13（systemd 257，x86_64）实机完成 systemd 验收：签名包验签与预检、创建专用账户、安装并启用控制器与 Agent、注册节点、TCP/UDP 实际转发、进程被强制结束后的自动重启、升级、回滚和保留状态的卸载，结果见 [VALIDATION.md](VALIDATION.md)。这次验收发现并修复了两个问题：Agent 的服务文件不允许 netlink，无法列出本机地址，导致**所有配置都被拒绝**；升级时不会更新服务文件，修复无法到达已安装的主机。OpenRC 与 logrotate 仍只有生成文件和语法检查，未在实机运行。

## 包格式与信任

离线包是严格限制成员的 gzip/USTAR 文件，只有 `relay`、`THIRD_PARTY.md`、`manifest.json`、`manifest.sig`。清单绑定目标系统/架构、程序版本、状态兼容代号、源代码提交声明、每个载荷的长度和 SHA256，以及签名公钥的 DER SHA256 指纹。签名采用 RSA PKCS#1 v1.5 + SHA256；生成密钥为 3072 位，验证接受 3072～8192 位 RSA 公钥。

`verify` 必须使用从独立可信渠道取得的公钥，不信任包内自带公钥。验证不执行载荷；不匹配的签名、哈希、目标头部、重复成员、路径越界、符号链接、硬链接、PAX 扩展和超出限制的成员都会被拒绝。一个二进制的上限为 256 MiB，清单上限为 64 KiB。安装在签名验证之后才执行目标程序的 `build-info`，并与签名声明逐字段比较。

`relay build-info` 输出产品、版本、编译目标、部署格式、controller/agent 状态兼容代号及数据库 schema。Linux 包必须具有对应 x86_64 或 aarch64 的 64 位小端 ELF 头；macOS 开发包只能在同目标机器的隔离目录使用。打包工具执行本机程序读取元信息，因此应在对应目标构建机打包；不假装已验证无法运行的交叉编译产物。

状态兼容代号是开发者维护的合同，**不是根据 schema 自动推断的结论**。任何会使旧程序误读持久状态的改变都必须先更新相应代号。安装、回滚和重装只允许同一角色的代号相等；跨代号迁移需要另外验证。0.17.0 及更早程序没有此元信息，不会被新工具当作可直接回滚版本。签名确认发布者及内容一致性，不证明程序无缺陷、源代码声明真实或构建可重现；这些仍需发布流程验收。

## 构建者：生成离线包

需要 Python 3.9+、可执行的本机 `relay` 和 OpenSSL/兼容 LibreSSL CLI。编译 Rust 程序仍需要现有 README 中的构建工具。密钥只保留在发布者的私有目录，不放入源码仓库、离线包或运行节点。

```sh
python3 scripts/relay_deploy.py keygen --directory /私有目录/relay-signing

python3 scripts/relay_deploy.py pack \
  --binary target/release/relay \
  --signing-key /私有目录/relay-signing/signing-private.pem \
  --source-revision 完整的40位Git提交ID \
  --output relay-linux-offline.tar.gz
```

生成的 `signing-public.pem` 可通过独立渠道分发。`--source-revision` 是发布者提供的提交声明，工具不会把当前工作目录自动当成干净构建来源。`THIRD_PARTY.md` 默认取本仓库清单，签名保护该文件内容；它不能替代完整机器可读 SBOM 或依赖安全审查。正式密钥托管、轮换/撤销、签名源码归档与 Linux 发布流水线仍待完成；本次验收仅使用临时测试密钥。

## 运行节点：验证与预检

将离线包、可信公钥，以及源码交付中的 `scripts/relay_deploy.py` 和 `scripts/deployment/` 一起复制到节点。无需 pip 安装。非 root 用户也能读取主机信息和执行验签；系统安装和服务操作需要 Linux root。工具识别当前运行的 systemd 或 OpenRC，不把仅安装了命令视为服务管理器可用。

```sh
python3 scripts/relay_deploy.py verify \
  --bundle relay-linux-offline.tar.gz --trusted-key /可信目录/signing-public.pem

python3 scripts/relay_deploy.py preflight \
  --role controller --config controller.json \
  --bundle relay-linux-offline.tar.gz --trusted-key /可信目录/signing-public.pem
```

预检返回系统、架构、内核、发行版、当前 UID、Python、服务管理器、可用磁盘、创建一代安装文件所需空间，以及配置/控制器监听地址能否在检查时绑定。缺少权限或依赖返回 `ready:false` 和非零退出码，不修改系统配置。未提供配置时不测试控制器监听。端口和可用磁盘的瞬时检查不能保证之后无人占用，也不证明节点业务端口、证书、外部网络或防火墙已就绪。

OpenRC 需要 `supervise-daemon`、`rc-service`、`rc-update` 和 `logrotate`。systemd 使用固定的非 root 服务账户和权限设置。工具不修改防火墙、路由、sysctl 或低端口能力；控制器监听限定为 1024～65535。Agent 的低端口、出口网卡权限与真实路由仍需单独验收。

## 首次安装

每台主机当前支持一个 controller 角色和一个 agent 角色，可同时安装；多 Agent 实例模板尚未实现。新工具使用独立命名，不自动接管旧版手工模板、原状态目录或其他软件的同名文件。

`controller.json`：

```json
{"listen":"127.0.0.1:8080","behind_tls_proxy":false}
```

```sh
sudo python3 scripts/relay_deploy.py install \
  --role controller --config controller.json \
  --bundle relay-linux-offline.tar.gz --trusted-key /可信目录/signing-public.pem
sudo python3 scripts/relay_deploy.py start --role controller
sudo python3 scripts/relay_deploy.py enable --role controller
```

控制器首次管理员密码仍在私有状态目录的 `admin-password.secret`。远程管理应按现有 Caddy 示例配置 HTTPS；非回环监听须明确设置 `behind_tls_proxy:true`。安装器不自动配置域名、证书或反向代理。

创建节点后，把一次性注册令牌保存为私有普通文件。`agent.json`：

```json
{"controller":"https://relay.example.com","node_id":"实际节点ID","poll_seconds":5}
```

```sh
sudo python3 scripts/relay_deploy.py install \
  --role agent --config agent.json \
  --enrollment-token-file /私有目录/enrollment.secret \
  --bundle relay-linux-offline.tar.gz --trusted-key /可信目录/signing-public.pem
sudo python3 scripts/relay_deploy.py start --role agent
sudo python3 scripts/relay_deploy.py enable --role agent
```

私有控制器 CA 可通过 `--ca-certificate` 指定；工具只接受包含证书的文件，不接受私钥。CA 作为该安装代次的一部分保留；升级时省略 `--ca-certificate` 会沿用当前代次的 CA（提供新文件则替换），不会因此失去与控制器的连接。数据面 TLS 私钥继续放在 Agent 私有状态的 `tls/` 中，安装器不会从其他主机自动迁移。

首次安装生成专用 `relayp-controller` / `relayp-agent` 账户；已有账户必须符合专用账户约束。注册令牌按 0600 复制给 Agent，运行状态目录为 0700。签名程序、启动脚本和服务文件由安装者拥有，Agent 不能修改安装选择。安装不会自动启动或启用服务；`start` 只确认服务管理器报告 active，不代表注册、租约、配置应用和业务健康全部完成。

## 安装目录

| 路径 | 内容 |
| --- | --- |
| `/opt/relay-platform/OWNER.json` | 安装器归属标记 |
| `/opt/relay-platform/roles/ROLE/generations/ID/` | 不可变二进制、签名、清单、公开 CA、配置及启动脚本 |
| `/opt/relay-platform/roles/ROLE/current` | 原子切换的安装代次链接 |
| `/opt/relay-platform/roles/ROLE/installation.json` | 当前/上一代、角色、兼容代号、账户及文件归属记录 |
| `/etc/relay-platform/ROLE/` | 注册令牌等保留的角色配置 |
| `/var/lib/relay-platform/ROLE/` | 运行数据库、恢复日志、凭据和 TLS 文件；不进入程序代次 |
| `/var/log/relay-platform/ROLE/` | OpenRC 标准输出日志 |

systemd 服务为 `relay-platform-controller.service` / `relay-platform-agent.service`；OpenRC 使用对应名称的 init 脚本。拒绝父目录中的符号链接、可被其他账户写入的管理路径、被外部硬链接的管理文件，以及未经本工具登记的文件覆盖。

## 升级、回滚和中断恢复

先升级控制器，再升级 Agent。安装前应按现有备份文档保留状态和恢复日志；升级操作本身不将备份当作可安全回退的实时账本。

```sh
sudo python3 scripts/relay_deploy.py stop --role controller
sudo python3 scripts/relay_deploy.py install \
  --role controller --config controller.json \
  --bundle 新版离线包.tar.gz --trusted-key /可信目录/signing-public.pem
sudo python3 scripts/relay_deploy.py start --role controller
```

Agent 使用相同流程，升级时不再传注册令牌。已有 Agent 的控制器地址和节点 ID 不允许通过安装器改绑；身份遗失/撤销按 [NODE_IDENTITY.md](NODE_IDENTITY.md) 处理。已运行的服务必须先停止，安装器不会在运行期间替换文件或声称无中断滚动升级。

安装器先验证签名并写入新代次，再执行 `build-info` 验证本机加载能力，之后持久化切换意图、原子替换 `current`、写入安装回执并清除意图。原有代次保留。相同包和配置重复安装不新增代次；外部改动过的服务文件会被保留并报告冲突。

新版安装器生成的服务文件（systemd 单元、OpenRC 脚本、logrotate）与已安装的不同时，升级会一并替换；用相同的包重新安装也会只替换服务文件。新内容写入持久化的切换意图，中断后 `recover` 接受旧版或新版文件并完成替换；被外部改动过的文件仍拒绝覆盖。回滚不恢复旧服务文件。

systemd 服务在异常退出 1 秒后重启，持续失败时间隔逐步增加到 30 秒（systemd 254 及以上；更早版本固定 1 秒），不会因为短时间内多次失败而永久停止；OpenRC 每 2 秒重启且不设次数上限。

```sh
sudo python3 scripts/relay_deploy.py status --role controller
sudo python3 scripts/relay_deploy.py recover --role controller
sudo python3 scripts/relay_deploy.py rollback --role controller
```

`recover` 完成已持久化的切换或卸载意图，不改成另一次操作。切换中断时原子链接只会指向旧代或新代，恢复校验目标和文件归属后完成原事务。首次创建账户/服务文件期间中断，应重复**同一安装请求**；已有内容必须与原意图匹配。待恢复期间禁止其他版本切换或服务启动。

`rollback` 也要求服务已停止；只切换到兼容的上一程序/配置代次，**不复制旧数据库、不回退恢复日志、不清零账本**。它不保证新版开始运行后所有数据语义仍与旧版兼容，兼容代号必须由开发者正确维护。此次真实进程验收使用同一 Release 二进制的不同配置代次，并验证监听地址切换和回滚后新增数据仍在；跨程序版本迁移仍待专门验收。

## 卸载和保留状态重装

```sh
sudo python3 scripts/relay_deploy.py stop --role agent
sudo python3 scripts/relay_deploy.py remove --role agent
```

卸载禁用本角色启动项，删除已登记且内容匹配的服务文件、当前选择及程序代次。发现未知文件或改动会停止，不递归清理猜测出的路径。卸载意图持久化，中断后可用 `recover` 继续。

运行状态、角色配置、日志、专用账户和归属回执保留；另一角色不受影响。重新执行同兼容代号的 `install` 可依据保留回执重装，复用当前状态。Agent 仍沿用原节点身份，不再传注册令牌。未知旧目录、丢失归属回执、账户 UID 改变或跨兼容代号恢复不自动接管；完全清除运行数据不属于此工具的默认卸载行为。

## 服务监督与日志

systemd 配置非 root 账户、私有临时目录、只读系统目录、仅状态目录可写、文件句柄上限、故障重启和重启频率限制。OpenRC 通过 `supervise-daemon` 监督，配置 5 秒间隔和 60 秒窗口内 5 次重启限制。它们的隔离能力不同，不能把 OpenRC 配置当作具有同等 systemd 文件系统隔离。

OpenRC 生成大小阈值 10 MiB、保留 5 份的 logrotate 配置；实际执行依赖主机已有的 logrotate 定时任务，安装器不擅自启用 cron。采用 copytruncate 可能在复制/截断之间丢少量标准输出日志，这些不是权威账本。**控制器 `recovery.log` 不在轮转配置中**，不得用普通日志轮转截断它。systemd 使用主机 journal 的保留策略，本工具不修改全局 journal 设置。

服务参数依据 [systemd 执行环境](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)、[systemd 服务合同](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)及 [OpenRC 服务脚本指南](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md)实现；签名调用遵循 [OpenSSL dgst](https://docs.openssl.org/3.0/man1/openssl-dgst/) 和 [genpkey](https://docs.openssl.org/3.0/man1/openssl-genpkey/)。实际发行版支持以实机验收为准。

## 本地隔离验证

任意安装命令加 `--root /绝对私有目录` 可生成隔离目录。隔离模式不创建系统账户，也拒绝 start/stop/enable/disable 宿主服务；启动脚本可由测试进程显式运行。目录路径目前限制为不含空白或 shell 特殊字符的绝对路径。

```sh
python3 scripts/check_deployment.py --binary target/release/relay --output docs/deployment-smoke.json
```

测试用临时密钥签名，验证包、启动真实控制器与 Agent，在切换后 SIGKILL 安装器并恢复，再验证回滚、卸载和保留状态重装后的 TCP/UDP 与账本。测试不会在当前主机安装系统服务。具体结果见 [VALIDATION.md](VALIDATION.md)。Linux 原生服务、干净主机重建、正式发布密钥、跨版本状态迁移、长时间服务恢复和完整 SBOM 仍保留为未完成项。

## 严格租约下的控制器离线与崩溃重启

以下是严格租约节点的实机结果（见 [NODE_LEASES.md](NODE_LEASES.md)）。因此 0.19.0 起新建节点默认改为离线（可用优先）模式，严格租约需在创建时选择：

- 控制器重启（20 秒以内）不影响转发。
- **控制器停止超过约 25 秒后，严格节点停止全部转发**；控制器恢复后还要等一个完整租约期（30 秒）。实测控制器停止 45 秒，转发在第 25 秒中断、第 76 秒恢复。
- Agent 被强制结束（SIGKILL）后，新进程要等旧租约过期（最多 30 秒）才开始转发；正常停止或重启会先归还租约，不需要等待。

离线模式（缺省，或创建节点时 `lease_policy: null`）的节点在控制器不可用时继续按最后配置转发，崩溃后立即恢复，但不能阻止复制的节点身份同时运行，控制器离线期间也不能严格限制额度。已有节点的模式创建后固定。

## 线路排查：服务商丢弃部分端口的回包

个别服务商会丢弃发往某段本地端口的入站 TCP 包。表现为：到某个目标的新连接偶发卡住，抓包可见对端回复了 SYN-ACK 而本机收不到，卡住的连接本地端口都落在同一段。实测一台 VPS 丢弃 30000–32000 段（见 VALIDATION.md）。确认后可让系统自动选端口时跳过这一段（不影响明确绑定这些端口的程序）：

```sh
echo 'net.ipv4.ip_local_reserved_ports = 30000-32000' | sudo tee /etc/sysctl.d/90-reserved-ports.conf
sudo sysctl --system
```

安装器不修改 sysctl。程序的建链竞速只能把这类卡顿缩短到对冲延迟（约 250 ms），不能消除。

## 连接容量

出站 TCP 端口在连接时按目标分配，节点到不同目标的连接可以复用同一端口号；到**同一个**目标地址和端口的并发连接数上限是本机临时端口范围（`net.ipv4.ip_local_port_range`，Debian 缺省 32768–60999，约 2.8 万）。每个 UDP 会话占用一个本地端口，节点并发 UDP 会话总数也受这个范围限制。单个出口要承载更多到同一后端的连接时，可扩大端口范围（例如 `10000 65000`，注意避开本机服务监听的端口并按上节保留被服务商屏蔽的端口段），或为后端提供多个地址/端口。每条空闲 TCP 中转连接约占 12 KiB 内存，另需两个文件描述符。服务文件把文件描述符上限设为 1048576（systemd `LimitNOFILE`、OpenRC `rc_ulimit`；以前为 65536，约 3.2 万条连接即耗尽），升级时随服务文件一起更新。
