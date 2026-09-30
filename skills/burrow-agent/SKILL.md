---
name: burrow-agent
description: Build and run the remote egress agent using the environment's verified networking configuration, then distinguish connection from end-to-end forwarding.
---

# Remote agent workflow

The agent runs on the remote egress machine. The server runs on the user's Mac/VPS.
This is a reverse proxy egress tunnel, not a local website publishing tool.

1. Obtain the complete `wss://HOST/ws` URL from the server handoff. For an HTTPS
   control-plane URL, use WSS and append `/ws` once.
2. Check out the same commit as the server; build `go build -o /tmp/burrow-agent
   ./cmd/burrow-agent`. Compare `/tmp/burrow-agent --version` with the handoff.
3. Read this execution environment's documented outbound networking settings.
   If direct access is permitted, omit upstream. If an HTTP CONNECT proxy is
   required, set `BURROW_UPSTREAM` to the verified URL. No proxy address is universal.
   Upstream carries both WSS dial-out and target egress, not a local published service.
   Do not bypass policy rejections or repeatedly probe rejected destinations.
4. If token auth is enabled, supply the matching secret via `BURROW_TOKEN` using
   an approved secret channel. Never include credentials in reports or handoffs.
5. Run one process: `/tmp/burrow-agent --server 'wss://HOST/ws'` (replace HOST).
   Preserve the process only as authorized and supported by the execution environment.
6. `session_authenticated` / `websocket connected and authenticated` proves WSS
   and hello acknowledgement, not target forwarding. Compare UTC session events,
   peer build, heartbeat and close status when troubleshooting.
7. Verify an explicitly allowed target THROUGH an enabled server-side local proxy.
   A standalone VM curl proves only VM egress. Coordinate with the local server
   operator for HTTP CONNECT/SOCKS/VLESS/Trojan verification; record target, path
   and outcome. Do not claim end-to-end success without that evidence.

Native reconnect uses exponential backoff capped at 30 seconds with jitter.
Updated peers negotiate application heartbeats (10-second interval, 20-second
pong timeout, server 45-second timeout). Older peers fall back to transport ping.
Heartbeats cannot fix DNS/routes or revive a terminated cloud execution session.
Quick Tunnel hostnames change on restart; external named tunnel hostnames persist.
Do not restart services, change routes/TUN, or edit code merely to resolve a connection
failure without authorization. For TLS trust failures, verify the current environment's
CA public certificate and fingerprint; never assume a bundled CA matches.
