# Nanny-level guide: using burrow on Muse

**You need zero networking knowledge.** Follow the steps; in the end your
browser traffic will exit from your Muse sandbox VM.

## How you and your agent split the work

- **You**: 4 things on the Mac (download, start server, install cert, set up browser)
- **Your agent**: 1 thing in the VM (start burrow-agent) — you just say one
  sentence in the Muse app and it handles the rest

You **cannot** (and don't need to) open a terminal in the VM. The VM is your
agent's territory.

---

## Prep: check your Mac

Open Terminal.app and run these two lines:

```bash
go version
cloudflared --version
```

- `go version` shows `go1.21` or higher: OK, skip
- `command not found`: download the macOS build from https://go.dev/dl,
  install it, **open a new terminal**, and confirm with `go version`
- `cloudflared` not found: run `brew install cloudflared`
  (install brew first from https://brew.sh if needed)

Got both? Continue.

---

## Step 1: Download burrow (Mac)

```bash
cd ~
git clone https://github.com/shafreeck/burrow.git
cd burrow
```

You'll see `Cloning into 'burrow'...` plus some `remote:` lines. Run `ls` —
you should see `cmd`, `internal`, `docs`, `skills`.

## Step 2: Build the server (Mac)

```bash
go build -o burrow-server ./cmd/burrow-server
```

**No output = success.** Run `ls -lh burrow-server` to confirm a binary
of a few MB exists.

`go: command not found` → Go isn't installed right; go back to Prep.

## Step 3: Start the server (Mac)

```bash
./burrow-server --tunnel --bind vless://127.0.0.1:8443
```

This enables only VLESS. For the HTTP browser proxy in Step 6, also pass
`--bind http://127.0.0.1:18080` when starting the server. All proxy inbounds require
an explicit address; only the control plane listens by default.

Wait 10–20 seconds. You'll see:

```
============================================================
  Agent connection

  Public URL:  https://xxx-xxx-xxx.trycloudflare.com

  Agent command:
    burrow-agent --server wss://xxx-xxx-xxx.trycloudflare.com/ws \
        --upstream http://<proxy> [--token <token>]
============================================================
```

**Do two things:**

1. **Copy the `Public URL`** (starts with `https://`, ends with
   `trycloudflare.com`) — you'll send it to your agent next
2. **Leave this terminal open** — the server must keep running

Scroll up a little for these two lines, **copy them too** (needed in Step 6):

```
  VLESS UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  VLESS URL:  vless://xxxx@127.0.0.1:8443?encryption=none&security=none&type=tcp#burrow
```

> ⚠️ The `Public URL` changes on every server restart. When it changes,
> forward the new one to your agent (Step 4).

## Step 4: Have your agent start up (in the Muse app)

Open Muse and tell your agent (replace `xxx` with your URL from Step 3):

> Clone https://github.com/shafreeck/burrow into the VM,
> build burrow-agent, then run:
> `./burrow-agent --server wss://xxx-xxx-xxx.trycloudflare.com/ws --upstream http://198.19.0.1:3128`
> Note the scheme is `wss://`, not `https://`. Send me the log to confirm it's connected.

The agent will report back something like:

```
connecting...
websocket connected
```

`websocket connected` = tunnel is up.

If it can't connect: check the URL for typos and that the server terminal
from Step 3 is still open. An expired URL (server was restarted) is the most
common cause — copy the fresh one and send it again.

## Step 5: Install the current VM's egress CA (Mac)

The VM's egress MITMs HTTPS, so your browser will show certificate errors.
Ask the agent in the current VM to export `Hatch Sandbox Egress CA` from that
VM's trust store and report its SHA-256 fingerprint. Save the certificate as
`current-egress-ca.crt`. CAs may differ between egress instances despite sharing
the same name; the rotation schedule is not established. Compare fingerprints
before installing. **Open a new terminal tab** and run:

```bash
cd ~/burrow
openssl x509 -in current-egress-ca.crt -noout -subject -dates -fingerprint -sha256
sudo ./burrow-server --install-ca --ca-cert ./current-egress-ca.crt
```

Enter your Mac login password (nothing shows while typing, press Enter after).

**What this does, in plain terms**: it adds `Hatch Sandbox Egress CA` to your
system trust store. This CA can issue certificates for **any website**.
After installing, browsers stop complaining — but the lock icon now means
"issued by Hatch CA", not the site's original certificate chain.

Only do this on your own Mac, never on a work machine.

Verify:

```bash
security find-certificate -c "Hatch Sandbox Egress CA" /Library/Keychains/System.keychain
```

Output only proves a certificate with that name exists. Its SHA-256 fingerprint
must match the current VM's CA. Omitting `--ca-cert` installs the bundled CA;
its current fingerprint is in the [README](../README.md#vm-egress-ca).
Verify that it matches the current VM. Do not trust a root solely because an
untrusted connection sent it, or disable TLS verification to hide the mismatch.

## Step 6: Set up your browser (Mac)

### Option A: browser HTTP proxy (simplest)

Chrome: Settings → search "proxy" → open proxy settings →
check "Web Proxy (HTTP)", fill `127.0.0.1`, port `18080`
(start the server with `--bind http://127.0.0.1:18080`).
Do the same for Secure Web Proxy (HTTPS).

Visit https://api.ipify.org. The IP shown should be:
- **not** your home broadband IP
- **the VM's egress IP** (ask your agent to run `curl https://api.ipify.org`
  in the VM — the two must match)

Match = done.

### Option B: VLESS client (phone/desktop)

Import the `VLESS URL` from Step 3 (the `vless://...` string) into
tunnet / Shadowrocket / Streisand. tunnet is tested working (MUX on by default;
the server supports it).

## Step 7: daily routine

1. Start the server on the Mac (Step 3's command)
2. Send the new Public URL to your agent so it restarts burrow-agent
   (Step 4's message with the new URL)
3. Browser proxy stays on — just use it

Reinstallation is unnecessary while the egress CA fingerprint stays the same.
Recheck it after changing VMs or egress instances if trust errors return.

---

## FAQ

**Agent says `websocket connected` but the browser can't load pages?**
Ask the agent whether `curl https://example.com` works inside the VM.
VM fine + browser broken → check your browser proxy settings (wrong IP/port
is the usual suspect). VM broken too → the sandbox egress proxy
`198.19.0.1:3128` may be flaky; wait a few minutes and retry.

**Browser still shows certificate errors on HTTPS?**
Compare the current VM's CA fingerprint with the installed CA. Identical names
can refer to different keys, and `ERR_CERT_AUTHORITY_INVALID` does not establish
expiry. Once the correct CA is installed, fully quit and reopen the browser.

**Enabling TUN disconnects the agent, disabling it restores service?**
Exclude `cloudflared` and `burrow-server` from TUN or route those processes
directly. DNS must work independently of burrow. Heartbeats trigger reconnects
but cannot repair a routing loop. See [TUN troubleshooting](../README.md#tun-mode-and-reconnect-failures).

**No "Agent connection" in the server terminal?**
Wait 30 seconds. Still nothing → look for `cloudflared` errors in the
terminal, or just ask your agent to take a look.

**Can I skip manually forwarding the URL every time?**
With an existing fixed Cloudflare Tunnel, use `--tunnel --domain your.domain`
and route it to `http://127.0.0.1:9000`. The agent keeps using `wss://your.domain/ws`.
Automatically created Quick Tunnel URLs change on restart.

**Can my traffic be seen?**
Path: browser → server on your Mac → Cloudflare tunnel →
agent in the VM → sandbox egress proxy → target site.
The sandbox egress proxy sees the domains you visit (not HTTPS content —
but it does MITM, which is why Step 5 exists, so in theory it *could*
decrypt). **Don't send banking passwords or similar over it.**

---

## Untested (don't rely on yet)

- VLESS over TLS inbound: coded, not E2E-tested
- Trojan inbound: coded, not E2E-tested
- Non-Muse-VM restricted environments: same principle, not verified
