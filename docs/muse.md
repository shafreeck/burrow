# 在 Muse 沙箱 VM 上用 burrow

你是 Muse 用户，就有一台沙箱 VM。这台 VM 能上网，但有三个限制：

1. **只能主动出站**：外面连不进来，没有公网 IP。
2. **所有 TCP 被劫持**：不管你连哪里的 443，都会被透明改写到 `198.19.0.1:3128`，
   一个无认证的 HTTP CONNECT 代理。你必须会说 CONNECT 才能出去。
3. **HTTPS 被中间人**：出口代理会动态签发目标网站的证书，签发者是
   `Hatch Sandbox Egress CA`。VM 系统里预装了这张 CA，所以 VM 内访问正常；
   但你的浏览器经 VM 出口时，会看到证书错误。

burrow 就是为这个场景写的：`burrow-agent` 跑在 VM 里，主动拨出 WebSocket
连回你 Mac 上的 `burrow-server`，你的浏览器流量就从 VM 的出口走了。

## 准备

- 一台 Mac（或任何有公网 IP 的机器，下文以 Mac + Cloudflare Quick Tunnel 为例）
- 能进你的 Muse VM 终端
- Go 1.21+（只编译用一次）

## 1. 编译

```bash
git clone https://github.com/shafreeck/burrow.git
cd burrow
go build -o burrow-server ./cmd/burrow-server
go build -o burrow-agent ./cmd/burrow-agent
```

`burrow-server` 放 Mac，`burrow-agent` 传到 VM。

## 2. 启动 server（Mac）

```bash
./burrow-server --tunnel --vless 127.0.0.1:8443
```

`--tunnel` 会自动拉起 `cloudflared` Quick Tunnel，公网 URL 会打印在日志里，
形如 `https://xxx.trycloudflare.com`。记下它。

server 还会生成一个 VLESS UUID 并打印导入链接，tunnet / Shadowrocket
这类客户端直接导入就能用。

## 3. 启动 agent（VM）

```bash
./burrow-agent \
  --server wss://xxx.trycloudflare.com/ws \
  --upstream http://198.19.0.1:3128
```

看到 `websocket connected` 就算通了。断线会自动重连。

## 4. 装 CA（只做一次）

不装的话，浏览器经 VM 出口访问 HTTPS 网站会报证书错误。
因为出口在做 MITM，你得信任签发者的 CA：

```bash
# Mac 上，server 二进制自带了 Hatch CA
sudo ./burrow-server --install-ca
```

这行命令把 `Hatch Sandbox Egress CA` 加进系统钥匙串。
**注意**：这是信任一个会签发任意网站证书的 CA，只在你明白含义的前提下做。
装完之后浏览器不再报错，但地址栏那把"锁"代表的是 Hatch CA 的签发，
不是网站原始证书链。

## 5. 开始用

- 浏览器 HTTP 代理填 `127.0.0.1:8080`，访问 https://api.ipify.org，
  看到的 IP 是 VM 的出口 IP，不是你本地的。
- 或用 VLESS 客户端导入 server 打印的链接（tunnet 实测可用，默认开 MUX）。

## 关于 TUN 模式

如果你用 tunnet 之类的开了 TUN（全局接管），不用做任何配置。
server 认出 `*.trycloudflare.com` / `*.argotunnel.com` 的流量会自动走本机直连，
不会把 cloudflared 自己的出站再塞回隧道里造成环路。这是自动的。

## 排错

| 现象 | 查什么 |
|---|---|
| agent 连不上 | Quick Tunnel URL 是否过期（每次重启 server 会变） |
| 浏览器证书错误 | CA 没装，见第 4 步 |
| 速度慢 | base64 文本帧有 ~33% 开销，属已知代价 |
| VLESS 握手失败 | 确认客户端 MUX 设置，server 端 MUX 已支持 |

## 没验证过的

- VLESS over TLS 入站（代码有，没实测）
- Trojan 入站（代码有，没实测）
- 非 Muse VM 的受限环境（原理通用，没实测）
