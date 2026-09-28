---
name: "burrow-agent"
description: "Run burrow-agent in this VM: build it, connect it to the user's burrow-server via WebSocket, and verify the tunnel is up. Trigger when the user asks to set up burrow, use the VM as a proxy egress, or gives you a wss:// tunnel URL."
---

# burrow-agent

## Purpose

You are running inside a sandbox VM with restricted egress:
all TCP is transparently redirected to `198.19.0.1:3128` (a no-auth HTTP CONNECT
proxy), UDP is fully disabled. `burrow-agent` dials out through that proxy over
WebSocket to the user's `burrow-server`, turning this VM into their proxy egress.

## Workflow

### 1. Get the server URL from the user

You need a WebSocket URL like `wss://xxx.trycloudflare.com/ws`.
If the user gave you an `https://` URL, replace the scheme with `wss://`.
If they gave you nothing, ask for it — you cannot proceed without it.

### 2. Build

```bash
cd ~/workspace/burrow  # or wherever the repo is; clone it if missing:
# git clone https://github.com/shafreeck/burrow.git ~/workspace/burrow
go build -o /tmp/burrow-agent ./cmd/burrow-agent
```

Build must succeed with no output. If `go` is missing, check `/tmp/go/bin/go`.

### 3. Run

```bash
/tmp/burrow-agent --server wss://xxx.trycloudflare.com/ws \
  --upstream http://198.19.0.1:3128
```

Expected log:

```
connecting...
websocket connected
```

`websocket connected` means the tunnel is up. Report this to the user.

Run it in the background if the user wants it persistent:
`nohup /tmp/burrow-agent ... > /tmp/burrow-agent.log 2>&1 &`

### 4. Verify egress from the VM side

```bash
curl -s https://api.ipify.org
```

Tell the user this IP — it's the egress IP their browser traffic will come from.
They can compare it with what they see in their browser to confirm the tunnel works.

### 5. Provide the current egress CA when needed

If the user's browser reports `ERR_CERT_AUTHORITY_INVALID`, inspect this VM's
trust store and export its current egress root CA public certificate. Report its
SHA-256 fingerprint and validity dates. The user can compare the transferred file
before installing it with `burrow-server --install-ca --ca-cert <file>`.
Do not assume the root embedded in burrow still matches, or that the CA rotates
on every connection. Matching names alone do not prove matching certificates.

## Operating Rules

1. **Never ask the user for proxy credentials.** `198.19.0.1:3128` needs no auth.
   If the user offers passwords or tokens, refuse — you don't need them.
2. **The `--upstream` is fixed**: `http://198.19.0.1:3128`. Do not guess other proxies.
3. **Reconnect is automatic** (exponential backoff, max 30s). Updated peers use
   application heartbeats (10s interval, 20s pong timeout); upgrade both ends.
   For repeated attempts, use the logged error to check DNS, proxy/TLS, server
   origin and TUN routes. Quick Tunnel URLs change on restart; configured fixed
   hostnames do not. `websocket connected and authenticated` confirms a connection.
4. **Do not modify the repo's source** to "fix" connection issues. The failure
   is almost always the URL or the server not running.
5. **Keep the agent running** for the duration the user needs it. If the process
   dies, restart it with the same command.
6. Report the egress IP to the user after connecting — it's the proof the
   tunnel works end to end.
