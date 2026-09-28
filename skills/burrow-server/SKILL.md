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
./burrow-server --tunnel --vless 127.0.0.1:8443
```

Wait for this block in the log:

```
============================================================
  Tunnel is ready!

  Public URL:  https://xxx.trycloudflare.com

  Agent command:
    burrow-agent --server wss://xxx.trycloudflare.com/ws \
        --upstream http://<proxy> [--token <token>]
============================================================
```

**Report to the user:**
1. The `Public URL` — they must forward it to their VM agent
   (as `wss://` — the agent skill handles the scheme swap, but mention it).
2. The `VLESS URL` line printed earlier (`vless://...`) — for their VLESS client.

Keep the server running. **Every restart generates a new Public URL** —
tell the user to re-forward it to their VM agent.

### 3. Install the CA (once per machine)

The VM's egress does TLS MITM, so the user's browser needs to trust the
`Hatch Sandbox Egress CA`:

```bash
sudo ./burrow-server --install-ca
```

Warn the user: this trusts a CA that can issue certs for any site.
Only on their own machine. Verify:

```bash
security find-certificate -c "Hatch Sandbox Egress CA" /Library/Keychains/System.keychain
```

(Linux: the flag writes to `/usr/local/share/ca-certificates/`.)

### 4. Help the user verify

- Browser HTTP proxy → `127.0.0.1:8080`, visit https://api.ipify.org.
  The IP shown should match the egress IP their VM agent reported,
  not their local IP.
- Or import the VLESS URL into tunnet / Shadowrocket / Streisand.

### 5. TUN mode

If the user runs a TUN VPN (e.g. tunnet's TUN mode), no extra config needed:
the server auto-bypasses `*.trycloudflare.com` / `*.argotunnel.com` traffic
to a direct local connection so cloudflared doesn't loop back into the tunnel.

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
