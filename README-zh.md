# burrow

把一台**只能主动出站**的机器，通过 WebSocket 反向隧道变成你的代理出口。

> **实测场景**：Muse 沙箱 VM。VM 的所有出站 TCP 被透明改写到 `198.19.0.1:3128`
>（无认证 HTTP CONNECT 代理，HTTPS 会被 MITM），UDP 全禁。`burrow-agent`
> 跑在 VM 里，经沙箱代理拨出 WebSocket 连回 `burrow-server`，浏览器流量就从
> VM 出口走了。其他受限环境（公司内网、NAT 后的机器）原理相同，但暂未实测。

```
浏览器
  ↓  按需开启：127.0.0.1:18080 (HTTP) / :1080 (SOCKS5) / :8443 (VLESS)
burrow-server (你 Mac / 公网机器)
  ↓  WebSocket (wss, 可经 Cloudflare Tunnel)
burrow-agent (VM)
  ↓  HTTP CONNECT → 上游代理 (如 198.19.0.1:3128)
目标网站
```

纯 Go，核心零第三方依赖。单文件交叉编译，开箱即用。

## 快速开始

### 1. 编译

```bash
go build -o burrow-server ./cmd/burrow-server
go build -o burrow-agent ./cmd/burrow-agent
```

### 2. 启动 server（Mac）

```bash
# 自动拉起 cloudflared quick tunnel（推荐，URL 会打印在日志里）
./burrow-server --tunnel --bind vless://127.0.0.1:8443

# 固定域名：复用已经运行并配置好路由的 cloudflared
./burrow-server --tunnel --domain burrow.lyra.run --bind vless://127.0.0.1:8443

# 局域网 HTTP 控制面
./burrow-server --bind vless://127.0.0.1:8443 --listen 0.0.0.0:9000
```

HTTP、SOCKS5、VLESS、Trojan 代理入站默认都关闭，只有显式指定对应地址才监听。
上面的命令只开启 VLESS；需要 HTTP 代理时加 `--bind http://127.0.0.1:18080`，
需要 SOCKS5 时加 `--bind socks5://127.0.0.1:1080`。控制面默认监听 `127.0.0.1:9000`。

`--bind` 可重复，支持同一协议监听多个地址。例如同时开启三个代理入站：

```bash
./burrow-server --tunnel --domain burrow.lyra.run \
  --bind vless://127.0.0.1:8443 \
  --bind http://127.0.0.1:18080 \
  --bind socks5://127.0.0.1:1080
```

支持 `http://`、`socks5://`、`vless://`、`trojan://`，均须指定主机和端口。
IPv6 地址加方括号，并在 shell 中引用，例如 `--bind 'vless://[::1]:8443'`。
同一地址不能重复绑定；端口 `0` 表示自动分配，实际地址会打印到日志。
VLESS 身份和 Trojan 密码分别用 `--vless-uuid`、`--trojan-password` 设置，
同协议的所有入站共用。原来的四个代理地址参数已统一为 `--bind`。

固定域名模式要求 Cloudflare Tunnel 的发布应用规则为
`burrow.lyra.run → http://127.0.0.1:9000`。Cloudflare 提供公网 TLS，
burrow 提供本机 HTTP。这个组合不会创建隧道、修改 DNS 或启动第二个
cloudflared；已有连接器由系统服务或你自己的命令管理。agent 使用
`wss://burrow.lyra.run/ws`。随机域名模式仍会自动启动 cloudflared。

**直连公网并申请 TLS 证书：**

```bash
./burrow-server --acme --domain example.com \
  --listen 0.0.0.0:443 --acme-listen 0.0.0.0:80

# 已有证书（也适用于外部证书管理工具）
./burrow-server --listen 0.0.0.0:443 \
  --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem
```

直连 ACME 要求域名解析到这台服务器，公网 80 端口能到达
`--acme-listen`。程序先启动独立的 HTTP-01 验证服务，签发完成后关闭它，
再启动 TLS 服务。`--acme-staging` 可用于测试；它签发的证书不受浏览器信任。
证书保存在 `./certs/`；当前只在启动时签发，没有运行中自动续期。
长期部署可由 Caddy/Nginx/证书管理工具负责续期，burrow 在其后提供本机 HTTP。
TLS 证书同时应用于控制面、VLESS 和 Trojan 入站，HTTP/SOCKS 代理仍为本机明文服务。

`--domain` 不再隐式申请证书。单独使用时会提示补充 `--acme`、证书文件或
`--tunnel`；隧道模式与本机 ACME/证书文件不能混用。

| 参数 | 默认 | 说明 |
|---|---|---|
| `--listen` | `127.0.0.1:9000` | 控制面监听地址（/ws, /fetch, /debug） |
| `--bind` | 无 | 代理入站 `协议://主机:端口`，可重复；支持 http、socks5、vless、trojan |
| `--tunnel` | `false` | 无域名时启动随机隧道；有域名时使用已有固定隧道 |
| `--domain` | `""` | 固定入口或 ACME 证书的域名 |
| `--acme` | `false` | 为直连 TLS 显式申请 Let's Encrypt 证书 |
| `--acme-listen` | `:80` | 签发期间的 HTTP-01 监听地址 |
| `--tls-cert` / `--tls-key` | `""` | 成对提供已有 PEM 证书和私钥 |
| `--system-proxy` | `false` | agent 接入后将桌面代理设为第一条 HTTP 绑定，退出时恢复 |
| `--proxy-service` | `""` | macOS 网络服务名，默认所有已启用的服务 |
| `--restore-system-proxy` | `false` | 从上次异常退出留下的快照恢复代理，然后退出 |
| `--cloudflared` | `cloudflared` | cloudflared 二进制路径 |
| `--token` | `""` | agent 认证口令，空为不认证 |
| `--install-ca` | `false` | 安装内嵌 Hatch 出口 CA 后退出 |
| `--debug` | `false` | 暴露 /debug 和 /fetch（或 `TUNNEL_DEBUG=1`） |

### 3. 启动 agent（VM）

```bash
./burrow-agent \
  --server wss://<tunnel-url>/ws \
  --upstream http://198.19.0.1:3128
```

| 参数 | 说明 |
|---|---|
| `--server` | server 的 WebSocket 地址（`ws(s)://host/ws`） |
| `--upstream` | VM 出站用的 HTTP CONNECT 代理；空为直连 |
| `--token` | 与 server 一致的口令 |

agent 断线自动重连（指数退避，最大 30s）。

### 4. 开始用

若启动时指定了 `--bind http://127.0.0.1:18080`，浏览器 HTTP 代理填相同地址，访问 https://api.ipify.org，
看到的 IP 是 VM 的出口 IP，不是你本地的。或把打印的 VLESS URL 导入
tunnet / Shadowrocket / Streisand。

### 可选：自动设置桌面系统代理

```bash
./burrow-server --tunnel --domain burrow.lyra.run --bind http://127.0.0.1:18080 --system-proxy

# macOS 可只操作指定网络服务
./burrow-server --tunnel --domain burrow.lyra.run --bind http://127.0.0.1:18080 --system-proxy --proxy-service Wi-Fi

# 被强制结束或断电后恢复
./burrow-server --restore-system-proxy
```

`--system-proxy` 使用第一条 `--bind http://...`，支持本机回环、内网和公网监听地址。
通配监听地址 `0.0.0.0` / `[::]` 会转换成同一监听端口的本机回环地址，供桌面应用连接。
缺少 HTTP 绑定时，启动会明确报错。
程序等到第一个 agent 完成连接认证
后才切换，避免尚无出口时切断桌面网络。Ctrl-C、SIGTERM 和启动失败会尝试恢复；
强制终止/断电后使用恢复命令。快照保存在用户配置目录的
`burrow/system-proxy.json`，写入失败会回滚；若其他应用改过设置，恢复时保留其改动并报告冲突。

| 平台 | 设置范围 |
|---|---|
| Windows | 当前用户的 WinINet/LAN HTTP 和 HTTPS 代理，保存并恢复 PAC/自动检测标志 |
| macOS | `networksetup` 管理的网络服务；修改可能要求管理员权限。已有认证代理时拒绝覆盖，避免丢失凭据 |
| Linux GNOME | 当前桌面会话的 GSettings，保留并恢复原模式和配置 |
| Linux KDE 5/6 | 当前用户 `kioslaverc` 的 HTTP/HTTPS 代理，并通过 D-Bus 通知刷新 |
| 无桌面 Linux | 明确返回不支持；命令行应用可单独设置 `http_proxy`、`https_proxy` |

这些设置只影响遵循桌面代理配置的应用。Windows 服务的 WinHTTP、终端环境变量和
TUN 路由需要各自配置。Windows/Linux 已完成交叉编译及配置逻辑测试，
原生桌面读写仍需在对应系统上验证。

### 部署在 VPS

VPS 可以使用 `--bind vless://0.0.0.0:8443` 等地址接收远程代理客户端。
代理客户端填写 **VPS 的 IP 或域名及对应端口**；`0.0.0.0` 是监听地址。
`--system-proxy` 只修改运行 burrow-server 的那台机器，不会修改远程客户端。
无桌面 VPS 通常省略该参数，在你自己的电脑或手机上配置代理客户端。
Cloudflare Tunnel 的 HTTP 回源规则仍指向控制面；VLESS/Trojan 的 TCP 入站
由对应 `--bind` 单独监听。

## 给 Muse 用户

- [docs/muse.md](docs/muse.md) — 保姆级教程（中文）：你在 Mac 上，agent 在 VM 里，一步步来。
- [docs/muse-en.md](docs/muse-en.md) — 英文版。

## Agent skills

- `skills/burrow-server/SKILL.md` — 给你 Mac 上的 agent（编译、起隧道、装 CA、验证）。
- `skills/burrow-agent/SKILL.md` — 给 VM 里的 Muse agent（编译、连接、上报出口 IP）。

## 协议

`internal/proto` 定义了 WebSocket 上的消息：

- **Text 帧**：JSON 控制消息 —
  `fetch` / `fetch_result`、`connect` / `connect_result`、
  `close`、`hello` / `hello_ack`
- **Binary 帧**：流数据，格式 `[idLen(1)][streamID][payload]`

`internal/ws` 是零依赖的 WebSocket 实现（server 端 hijack / client 端握手），
`internal/cloudflared` 负责拉起 quick tunnel 并解析 URL。

## 测试

```bash
go test ./...
go vet ./...
```

## 安全注意

这是 PoC 级别的隧道，生产使用前请补齐：

- `--token` 口令认证（已支持，默认关闭）
- server 只监听本机（默认 `127.0.0.1`，不要轻易改 `0.0.0.0`）
- `/fetch` 是无认证的 SSRF 接口，公网部署时请关闭或加鉴权
- 建议再加：连接数/流量限制、TLS 证书固定、审计日志

## 协议范围与验证

- 已有真实本地 agent/WebSocket/TCP 的回归测试：VLESS TCP、MUX TCP、Trojan TCP、HTTP CONNECT、SOCKS5，以及 VLESS/Trojan TLS 握手。
- VLESS UDP 从 server 本机直接出站，**不经过 VM agent**；MUX UDP/XUDP、Vision、REALITY 和非空 flow/addons 未实现。
- Trojan UDP 与未认证请求的伪装回落未实现。无证书的 Trojan 仅用于本机测试。
- 隧道尚无 TCP 半关闭语义，HTTP fetch 是最多 4 MiB 的缓冲请求，不是完整的流式 HTTP 代理。
- 尚未完成 Xray/sing-box/Shadowrocket 的客户端兼容矩阵，也未验证其他受限 VM 环境。
- 详细发现、已修复问题和剩余限制见 [审计记录](docs/audit-2026-09-29.md)。
