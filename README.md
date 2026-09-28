# burrow

Turn a machine that **can only dial out** into your proxy egress, via a reverse
WebSocket tunnel.

> **Tested scenario**: Muse sandbox VM. All outbound TCP in the VM is
> transparently rewritten to `198.19.0.1:3128` (a no-auth HTTP CONNECT proxy,
> MITMs HTTPS), UDP fully disabled. `burrow-agent` runs in the VM, dials out
> through the sandbox proxy over WebSocket back to `burrow-server`, and your
> browser traffic exits from the VM. Other restricted environments (corporate
> NAT, etc.) work on the same principle but are untested.

```
browser
  ↓  127.0.0.1:8080 (local HTTP proxy) / :1080 (SOCKS5) / :8443 (VLESS)
burrow-server (your Mac / public box)
  ↓  WebSocket (wss, via Cloudflare Tunnel)
burrow-agent (VM)
  ↓  HTTP CONNECT → upstream proxy (e.g. 198.19.0.1:3128)
target website
```

Pure Go, zero third-party dependencies for the core. Single-binary cross-compile.

## Quick start

### 1. Build

```bash
go build -o burrow-server ./cmd/burrow-server
go build -o burrow-agent ./cmd/burrow-agent
```

### 2. Start the server (Mac)

```bash
# Auto-starts a cloudflared quick tunnel (recommended; URL printed in logs)
./burrow-server --tunnel --vless 127.0.0.1:8443

# Already have a public IP / domain: no tunnel needed
./burrow-server --vless 127.0.0.1:8443 --listen 0.0.0.0:9000
```

| Flag | Default | Description |
|---|---|---|
| `--listen` | `127.0.0.1:9000` | Control-plane listen addr (`/ws`, `/fetch`, `/debug`) |
| `--proxy` | `127.0.0.1:8080` | Local HTTP proxy listen addr; empty disables |
| `--socks5` | `127.0.0.1:1080` | SOCKS5 listen addr; empty disables |
| `--vless` | `""` | VLESS listen addr; empty disables |
| `--trojan` | `""` | Trojan listen addr; empty disables |
| `--tunnel` | `false` | Auto-start `cloudflared tunnel --url` |
| `--cloudflared` | `cloudflared` | Path to cloudflared binary |
| `--token` | `""` | Agent auth token; empty = no auth |
| `--install-ca` | `false` | Install embedded Hatch egress CA and exit |
| `--debug` | `false` | Expose `/debug` and `/fetch` (or `TUNNEL_DEBUG=1`) |

### 3. Start the agent (VM)

```bash
./burrow-agent \
  --server wss://<tunnel-url>/ws \
  --upstream http://198.19.0.1:3128
```

| Flag | Description |
|---|---|
| `--server` | Server WebSocket URL (`ws(s)://host/ws`) |
| `--upstream` | HTTP CONNECT proxy for VM egress; empty = direct |
| `--token` | Must match server's `--token` |

Auto-reconnects on drop (exponential backoff, max 30s).

### 4. Use it

Set your browser's HTTP proxy to `127.0.0.1:8080`, visit https://api.ipify.org —
the IP shown is the VM's egress, not yours. Or import the printed VLESS URL
into tunnet / Shadowrocket / Streisand.

## For Muse users

- [docs/muse.md](docs/muse.md) — nanny-level tutorial (Chinese): you on the Mac,
  your agent in the VM, step by step.
- [docs/muse-en.md](docs/muse-en.md) — same in English.

## Agent skills

- `skills/burrow-server/SKILL.md` — for an agent on your Mac (build, tunnel,
  CA install, verify).
- `skills/burrow-agent/SKILL.md` — for your Muse agent in the VM
  (build, connect, report egress IP).

## Protocol

`internal/proto` defines the WebSocket messages:

- **Text frames**: JSON control messages —
  `fetch` / `fetch_result`, `connect` / `connect_result`,
  `close`, `hello` / `hello_ack`
- **Binary frames**: stream data as `[idLen(1)][streamID][payload]`

`internal/ws` is a zero-dependency WebSocket implementation
(server-side hijack / client-side handshake);
`internal/cloudflared` spawns quick tunnel and parses its URL.

## Testing

```bash
go test ./...
go vet ./...
```

## Security notes

This is PoC-grade. Before production use:

- `--token` auth (supported, off by default)
- Server binds loopback by default — don't change to `0.0.0.0` lightly
- `/fetch` is an unauthenticated SSRF endpoint — keep it off public networks
- Consider: connection/rate limits, cert pinning, audit logging

## Untested

- VLESS over TLS inbound (coded, not E2E-tested)
- Trojan inbound (coded, not E2E-tested)
- Non-Muse-VM restricted environments (same principle, not verified)
