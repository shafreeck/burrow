# burrow

把一台**只能主动出站**的机器，通过 WebSocket 反向隧道变成你的代理出口。

> **实测场景**：Muse 沙箱 VM。VM 的所有出站 TCP 被透明改写到 `198.19.0.1:3128`
>（无认证 HTTP CONNECT 代理，HTTPS 会被 MITM），UDP 全禁。`burrow-agent`
> 跑在 VM 里，经沙箱代理拨出 WebSocket 连回 `burrow-server`，浏览器流量就从
> VM 出口走了。其他受限环境（公司内网、NAT 后的机器）原理相同，但暂未实测。

```
浏览器
  ↓  127.0.0.1:8080 (本地 HTTP 代理) / :1080 (SOCKS5) / :8443 (VLESS)
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
./burrow-server --tunnel --vless 127.0.0.1:8443

# 已有公网 IP / 域名：不需要 tunnel
./burrow-server --vless 127.0.0.1:8443 --listen 0.0.0.0:9000
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--listen` | `127.0.0.1:9000` | 控制面监听地址（/ws, /fetch, /debug） |
| `--proxy` | `127.0.0.1:8080` | 本地 HTTP 代理监听地址，空字符串禁用 |
| `--socks5` | `127.0.0.1:1080` | SOCKS5 监听地址，空字符串禁用 |
| `--vless` | `""` | VLESS 监听地址，空字符串禁用 |
| `--trojan` | `""` | Trojan 监听地址，空字符串禁用 |
| `--tunnel` | `false` | 自动启动 `cloudflared tunnel --url` |
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

浏览器 HTTP 代理填 `127.0.0.1:8080`，访问 https://api.ipify.org，
看到的 IP 是 VM 的出口 IP，不是你本地的。或把打印的 VLESS URL 导入
tunnet / Shadowrocket / Streisand。

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

## 没验证过的

- VLESS over TLS 入站（代码有，没实测）
- Trojan 入站（代码有，没实测）
- 非 Muse VM 的受限环境（原理通用，没实测）
