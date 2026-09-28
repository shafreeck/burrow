# burrow

把一台**只能主动出站、没有公网入口**的机器，通过 WebSocket 反向隧道变成你的代理出口。

> **实测场景**：Muse 沙箱 VM。VM 的所有出站 TCP 被强制改写到 `198.19.0.1:3128`
>（HTTP CONNECT 代理，HTTPS 还会被 MITM），UDP 全禁。`burrow-agent` 跑在 VM 里，
>经沙箱代理拨出 WebSocket 连回 `burrow-server`，浏览器流量就从 VM 出口走了。
>其他受限环境（公司内网、NAT 后的机器）原理相同，但暂未实测。

```
浏览器
  ↓  127.0.0.1:8080 (本地 HTTP 代理) / :1080 (SOCKS5) / :8443 (VLESS)
burrow-server (你 Mac / 公网机器)
  ↓  WebSocket (wss, 可经 Cloudflare Tunnel)
burrow-agent (VM)
  ↓  HTTP CONNECT → 上游代理 (如 198.19.0.1:3128)
目标网站
```

纯 Go 标准库，无第三方依赖。单文件交叉编译，开箱即用。

## 快速开始

### 1. 编译

```bash
go build -o burrow-server ./cmd/burrow-server
go build -o burrow-agent ./cmd/burrow-agent
```

### 2. 启动 server（Mac）

```bash
# 自动拉起 cloudflared quick tunnel（推荐，URL 会打印在日志里）
./burrow-server --tunnel --proxy 127.0.0.1:8080

# 已有公网 IP / 域名：不需要 tunnel
./burrow-server --proxy 127.0.0.1:8080 --listen 0.0.0.0:9000
```

常用参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--listen` | `127.0.0.1:9000` | 控制面监听地址（/ws, /fetch, /debug） |
| `--proxy` | `127.0.0.1:8080` | 本地 HTTP 代理监听地址，空字符串禁用 |
| `--tunnel` | `false` | 自动启动 `cloudflared tunnel --url` |
| `--cloudflared` | `cloudflared` | cloudflared 二进制路径 |
| `--verbose` | `false` | 显示完整的 cloudflared 日志（默认只显示错误） |
| `--token` | `""` | agent 认证口令，空为不认证 |
| `--domain` | `""` | 公网域名（用于 TLS/ACME，预留） |
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

### 4. 浏览器设置代理

HTTP/HTTPS 代理填 `127.0.0.1:8080`，然后访问 https://api.ipify.org，
看到的不再是你本地 IP，而是 VM 的出口 IP。

## 协议

`internal/proto` 定义了 WebSocket 上的消息：

- **Text 帧**：JSON 控制消息
  - `fetch` / `fetch_result`：单次 HTTP 请求（供 `/fetch` 调试接口和普通 HTTP 代理）
  - `connect` / `connect_result`：打开一条 TCP 流（供 HTTPS `CONNECT`）
  - `close`：关闭流；`hello` / `hello_ack`：握手认证
- **Binary 帧**：流数据，格式 `[idLen(1)][streamID][payload]`

`internal/ws` 是零依赖的 WebSocket 帧实现（server 端 hijack / client 端握手），
`internal/cloudflared` 负责拉起并解析 quick tunnel URL。

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
