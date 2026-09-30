# Connection diagnostics validation

Run `./scripts/build.sh` to stamp both peers with one source revision, then
`python3 scripts/smoke.py` for isolated binary acceptance. The smoke test uses
random loopback ports, a temporary working directory and a local target only;
it terminates its own test children. It verifies origin health before connection,
agent authentication, HTTP CONNECT forwarding through the agent, and peer version
in diagnostics. It does not start cloudflared or touch production proxy settings.

The implementation was validated on macOS arm64 with:

- `go test ./...` and `go test -race ./...` (including existing real forwarding,
  stalled-session reconnect, current/legacy heartbeat and MUX tests).
- `go vet ./...`, macOS builds of both binaries.
- Linux amd64 and Windows amd64 cross-builds of both binaries.
- `python3 scripts/smoke.py` with the freshly built binaries.
- Shell argument round-trip including apostrophes, command substitution text and
  URL query metacharacters; close payload retention; safe event output; health
  layer semantics; version/session propagation; simulated Quick Tunnel exit.

The simulated Quick Tunnel exit test uses a five-second startup budget to accommodate
race instrumentation; URL matching remains unchanged.
Race validation exposed test logger callbacks outliving their testing.T; those
asynchronous callbacks now use the concurrency-safe standard logger.

Limits: no live Cloudflare edge, production WSS, cloud policy enforcement, TUN
switching, real external CONNECT proxy or Linux/Windows native runtime was exercised.
A cloud execution session terminated by its platform cannot be revived by agent
reconnect logic. An origin health response does not prove connector or egress health.
