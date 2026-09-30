---
name: "burrow-server"
description: "Run burrow-server on this machine (Mac or any box with outbound internet): build it, start it with Cloudflare Quick Tunnel, report the public URL and VLESS link to the user, and help configure their browser or VLESS client. Trigger when the user asks to set up burrow server, expose a tunnel, or use their VM as a proxy egress."
---

# burrow-server

## Purpose

You are running on the user's own machine (Mac / VPS / any box with internet).
`burrow-server` is the public side of the tunnel: it listens for the VM agent's
WebSocket dial-in, and exposes local proxy endpoints (HTTP / SOCKS5 / VLESS /
Trojan) that forward through the tunnel. The VM side is handled by the user's
Muse agent via the `burrow-agent` skill — your only handoff to them is the
public tunnel URL.

## Workflow

### 1. Build

```bash
cd ~/burrow  # or wherever the repo is; clone if missing:
# git clone https://github.com/shafreeck/burrow.git ~/burrow
go build -o burrow-server ./cmd/burrow-server
```

Needs Go 1.21+ and `cloudflared` on PATH (`brew install cloudflared` on Mac).

### 2. Start with Quick Tunnel

```bash
./burrow-server --tunnel --bind vless://127.0.0.1:8443
```

This enables only VLESS. All proxy inbounds are disabled by default; enable
only those the user needs. For a browser HTTP proxy, also pass
`--bind http://127.0.0.1:18080`. `--system-proxy` requires this explicit HTTP address.

Read the generated **AI handoff**. Forward the complete Agent WebSocket URL,
build revision, authentication requirement, role and verification instructions.
The copyable command omits upstream for direct egress; the remote operator discovers
their verified HTTP CONNECT proxy and uses `BURROW_UPSTREAM` if required.
Never send placeholder shell syntax, tokens or a supposedly universal proxy address.
Public URL is the control plane; --bind listeners are separate local proxy entrypoints.
A fixed-domain connector is externally managed; burrow neither starts nor supervises it.

Keep the server running. A Quick Tunnel gets a new URL on restart; a configured
fixed tunnel keeps its hostname. Only forward a replacement URL when it changed.

### 3. Install the current VM's CA

The VM's egress does TLS MITM, so the user's browser needs to trust the
egress CA. Ask the VM agent to export the root from its trust store and report
its SHA-256 fingerprint. Compare the transferred file with that fingerprint.
The CA name alone is insufficient: different roots can share the name
`Hatch Sandbox Egress CA`. Do not assume a fixed lifetime or per-session rotation.

```bash
openssl x509 -in current-egress-ca.crt -noout -subject -dates -fingerprint -sha256
sudo ./burrow-server --install-ca --ca-cert ./current-egress-ca.crt
```

Warn the user: this trusts a CA that can issue certs for any site.
Only on their own machine. Verify:

```bash
security find-certificate -c "Hatch Sandbox Egress CA" /Library/Keychains/System.keychain
```

(Linux: the flag writes to `/usr/local/share/ca-certificates/`.)
The command without `--ca-cert` uses the bundled CA snapshot; its fingerprint
is documented in README. Verify that it matches the current VM.
Do not automatically trust a root captured from a
failing TLS connection. Finding a certificate by name does not verify its key.

### 4. Help the user verify

- If started with `--bind http://127.0.0.1:18080`, set the browser HTTP proxy to
  `127.0.0.1:18080` and visit https://api.ipify.org.
  This request must traverse the configured server proxy, and should match verified remote egress,
  not their local IP.
- Or import the VLESS URL into tunnet / Shadowrocket / Streisand.

### 5. TUN mode

If TUN disconnects the agent, configure the TUN client to exclude `cloudflared`
and `burrow-server` or route those processes directly. DNS for cloudflared must
also work without the burrow agent. Do not promise that TUN needs no configuration.

The server attempts direct egress for Cloudflare Tunnel domains and the published
Global/US tunnel IPs on port 7844, including VLESS MUX while no agent is connected.
macOS/Linux attempt physical interface binding; Windows relies on OS routes.
Other destinations or TUN implementations may require explicit exclusions.
Heartbeats detect stale sessions and trigger reconnects, but do not repair routes.

For fixed tunnels, match the origin to the listener: `http://127.0.0.1:9000`
for the default IPv4 binding. `localhost` can resolve to `::1` and yield 502.

## Operating Rules

1. **The Public URL is the handoff.** Nothing works until the user's VM agent
   has it. If the tunnel seems dead, first check whether the URL changed
   (server restart) and whether the new one was forwarded.
2. **Never ask the user for passwords, tokens, or proxy credentials.**
   Quick Tunnel needs none. If `--token` is set, it must match on both sides —
   default is empty (no auth), fine for personal use behind 127.0.0.1.
3. **Keep listeners on loopback** (`127.0.0.1`) unless the user explicitly
   asks for LAN/public exposure. `/fetch` is an unauthenticated SSRF endpoint —
   never expose it to the network.
4. Do not invent flags. Check `./burrow-server --help` for the real list.
5. If `cloudflared` fails to start, show the user the error and suggest
   `brew reinstall cloudflared` — don't work around it with other tunnel tools.
