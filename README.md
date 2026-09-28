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
  ↓  Explicitly enabled: 127.0.0.1:18080 (HTTP) / :1080 (SOCKS5) / :8443 (VLESS)
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
./burrow-server --tunnel --bind vless://127.0.0.1:8443

# Fixed hostname: reuse an already configured/running cloudflared connector
./burrow-server --tunnel --domain burrow.example.com --bind vless://127.0.0.1:8443

# Plain HTTP control plane on a LAN
./burrow-server --bind vless://127.0.0.1:8443 --listen 0.0.0.0:9000
```

HTTP, SOCKS5, VLESS, and Trojan inbounds are disabled by default. Each requires
an explicit listen address. The commands above enable only VLESS; add
`--bind http://127.0.0.1:18080` for HTTP or `--bind socks5://127.0.0.1:1080` for SOCKS5.
The control plane still defaults to `127.0.0.1:9000`.

Repeat `--bind` to enable multiple listeners, including multiple addresses for
the same protocol:

```bash
./burrow-server --tunnel --domain burrow.example.com \
  --bind vless://127.0.0.1:8443 \
  --bind http://127.0.0.1:18080 \
  --bind socks5://127.0.0.1:1080
```

Supported schemes are `http`, `socks5`, `vless`, and `trojan`; host and port
are required. Quote IPv6 URLs, e.g. `--bind 'vless://[::1]:8443'`. Duplicate
addresses are rejected; port `0` allocates a free port and logs the actual address.
`--vless-uuid` and `--trojan-password` apply to all inbounds of their protocol.
The four previous proxy address flags have been replaced by `--bind`.

For a fixed hostname, configure the Cloudflare Tunnel published application as
`burrow.example.com → http://127.0.0.1:9000`. Cloudflare terminates public TLS;
burrow serves local HTTP. This mode does not create a tunnel, change DNS, or
start another cloudflared process. The agent connects to
`wss://burrow.example.com/ws`.

For direct public TLS:

```bash
# DNS must point to this server; public port 80 must reach --acme-listen.
./burrow-server --acme --domain example.com \
  --listen 0.0.0.0:443 --acme-listen 0.0.0.0:80

# Or load a certificate maintained by an external certificate manager.
./burrow-server --listen 0.0.0.0:443 \
  --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem
```

ACME starts a dedicated HTTP-01 listener before requesting the certificate,
then closes it before starting TLS. Use `--acme-staging` for testing.
Certificates are saved under `./certs/`; issuance runs at startup, with no
automatic renewal while running. Caddy/Nginx or another certificate manager
can manage renewal and proxy to burrow over local HTTP.
The certificate enables TLS on the control plane, VLESS, and Trojan; local
HTTP/SOCKS proxy listeners remain plain TCP.

`--domain` no longer implicitly requests a certificate: add `--acme`, provide
certificate files, or use `--tunnel`. Tunnel mode rejects local ACME/cert flags.

| Flag | Default | Description |
|---|---|---|
| `--listen` | `127.0.0.1:9000` | Control-plane listen addr (`/ws`, `/fetch`, `/debug`) |
| `--bind` | None | Repeatable proxy URL: protocol://host:port; supports http, socks5, vless, trojan |
| `--tunnel` | `false` | Start Quick Tunnel without a domain; reuse a fixed tunnel with a domain |
| `--domain` | `""` | Public hostname for fixed Tunnel or ACME |
| `--acme` | `false` | Explicitly request a Let's Encrypt certificate for direct TLS |
| `--acme-listen` | `:80` | HTTP-01 listener during issuance |
| `--tls-cert` / `--tls-key` | `""` | Existing PEM certificate and key, supplied together |
| `--system-proxy` | `false` | Use the first HTTP binding for desktop proxy after an agent connects; restore on exit |
| `--proxy-service` | `""` | macOS service name; empty selects all enabled services |
| `--restore-system-proxy` | `false` | Restore the saved proxy settings after an unclean exit |
| `--cloudflared` | `cloudflared` | Path to cloudflared binary |
| `--token` | `""` | Agent auth token; empty = no auth |
| `--install-ca` | `false` | Install an egress root CA and exit; use `--ca-cert` to select the file |
| `--ca-cert` | `""` | Root CA PEM exported from the current VM, used with `--install-ca`; empty uses the bundled CA snapshot |
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

Reconnects with backoff of 1, 2, 4, 8, 16, then 30 seconds. Updated peers negotiate
application heartbeats: the agent sends a ping every 10 seconds and closes the
session if its matching pong is missing for 20 seconds. The server removes an
agent after 45 seconds without a heartbeat. With older servers, the agent falls
back to WebSocket ping, which only checks transport liveness; upgrade both ends
for application checks. Heartbeats detect dead sessions; reconnecting still
requires working network routes.

### 4. Use it

If started with `--bind http://127.0.0.1:18080`, set your browser's HTTP proxy to that
address and visit https://api.ipify.org —
the IP shown is the VM's egress, not yours. Or import the printed VLESS URL
into tunnet / Shadowrocket / Streisand.

### VM egress CA

The sandbox egress re-signs HTTPS certificates. `ERR_CERT_AUTHORITY_INVALID`
means the current certificate chain is untrusted; it does not establish expiry.
Different VMs or egress instances may have identically named CAs with different
keys. A single installation is not guaranteed to work forever, and we have not
established that the CA changes on every connection.

Ask the agent inside the current VM to export its egress root CA from the VM's
trust store and report the SHA-256 fingerprint. Compare the transferred file
with that fingerprint, then install it:

```bash
openssl x509 -in current-egress-ca.crt -noout -subject -dates -fingerprint -sha256
sudo ./burrow-server --install-ca --ca-cert ./current-egress-ca.crt
```

This trusts certificates issued by that CA. The installer accepts one currently
valid, self-signed root and prints its fingerprint before installation. A matching
name is insufficient; do not trust a root solely because an untrusted TLS peer
sent it. Without `--ca-cert`, the installer uses the bundled CA snapshot and
asks you to verify its fingerprint against the current VM. The bundled root was
updated on 2026-09-29; its SHA-256 fingerprint is
`A9:D6:3E:7B:EC:DC:BD:21:0D:EC:22:A3:73:7E:17:CF:E4:E7:7F:CA:E2:99:00:96:02:3E:F2:E1:50:1E:1D:77`.
macOS uses the System keychain; Linux uses
`update-ca-certificates`; other platforms export the file for manual installation.

### TUN mode and reconnect failures

If enabling TUN disconnects the agent and disabling it restores service, exclude
`cloudflared` and `burrow-server` from the TUN client or route those processes
directly. DNS used by cloudflared must also work independently of burrow.
Cloudflare Tunnel uses TCP/UDP 7844; see its
[published destinations](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/).

The server attempts direct egress for `argotunnel.com`, `cftunnel.com`,
`trycloudflare.com` and their subdomains, plus the specific Global/US IPv4/IPv6
tunnel addresses on port 7844. HTTP CONNECT, SOCKS5, VLESS TCP/MUX and Trojan TCP
check this before depending on an agent. MUX can carry bootstrap traffic while
offline and selects the current agent for each new stream after reconnect.
macOS/Linux attempt physical interface binding; Windows relies on OS routes.
The address list can change. DNS, other regions, and TUN implementations that
ignore interface binding still need client rules.

For a fixed tunnel, use origin `http://127.0.0.1:9000` to match the default IPv4
listener. `localhost` may resolve to `::1`, causing Cloudflare 502 responses.
`reconnecting` means an attempt is pending; `websocket connected and authenticated`
confirms a successful connection.

### Optional desktop proxy configuration

Add `--bind http://127.0.0.1:18080 --system-proxy` to configure desktop HTTP/HTTPS
traffic. `--system-proxy` uses the first `http://` binding and accepts loopback,
private, and public listener addresses. Wildcards (`0.0.0.0` / `[::]`) become
local loopback addresses on the same port for desktop applications to connect.
A missing HTTP binding is rejected before listeners start.
Settings change after the first authenticated agent connects. A private
snapshot in the user config directory, `burrow/system-proxy.json`, supports
rollback, restoration on Ctrl-C/SIGTERM, and `--restore-system-proxy` after a
forced exit. Settings changed by another app are preserved and reported as a
conflict during restoration.

Supported backends: Windows user WinINet/LAN settings, macOS `networksetup`,
Linux GNOME GSettings, and KDE 5/6 `kioslaverc`. macOS may require administrator
permissions; `--proxy-service Wi-Fi` selects one service. Existing authenticated
macOS proxies are not overwritten because their credentials cannot be restored
through networksetup. Headless Linux reports an explicit unsupported error.
Desktop proxy settings do not configure WinHTTP services, shell environment
variables, or TUN routes. Windows/Linux builds and configuration logic are
tested; native desktop writes still need validation on those platforms.

### VPS deployment

Use bindings such as `--bind vless://0.0.0.0:8443` to accept remote proxy clients.
Configure clients with the VPS IP or hostname and the corresponding port;
`0.0.0.0` is a listen address. `--system-proxy` only changes the machine running
burrow-server, not remote clients. Omit it on a headless VPS and configure your
desktop or phone's proxy client separately. The Cloudflare HTTP tunnel routes
to the control plane; VLESS/Trojan TCP clients use their separate `--bind` ports.

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
  `close`, `hello` / `hello_ack`, `ping` / `pong` (negotiated application heartbeats)
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

## Validation and limits

- Local end-to-end tests cover real agent TCP forwarding through HTTP CONNECT,
  SOCKS5, VLESS, Trojan, TLS inbounds, and VLESS MUX session reuse.
- VLESS UDP exits from the server itself; agent UDP, MUX UDP/XUDP, Vision,
  REALITY, and Trojan UDP/fallback are not implemented.
- Windows and Linux builds and simulated desktop proxy restoration are checked;
  native Windows/Linux desktop settings and third-party client interoperability
  still need validation. Restricted environments beyond the Muse VM are untested.
- See the [audit record](docs/audit-2026-09-29.md) for fixes, evidence, and remaining limits.
