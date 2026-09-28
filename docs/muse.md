# 在 Muse 上用 burrow：把你的沙箱 VM 变成代理出口

你是 Muse 用户，你的 agent 住在一台沙箱 VM 里。这台 VM 能上网，但有三个限制：

1. **只能主动出站**：外面连不进来，没有公网 IP。
2. **所有 TCP 被劫持**：不管连哪里的 443，都会被透明改写到 `198.19.0.1:3128`，
   一个无认证的 HTTP CONNECT 代理。
3. **HTTPS 被中间人**：出口代理会动态签发目标网站的证书，签发者是
   `Hatch Sandbox Egress CA`。

burrow 让这台 VM 成为你的代理出口。你负责 Mac 这头，VM 那头交给你的 agent。

## 分工

| 你（Muse App 里） | 你的 agent（VM 里） |
|---|---|
| 编译、启动 `burrow-server` | 编译、启动 `burrow-agent` |
| 装 CA、配浏览器 | 向你汇报 agent 日志 |

你进不了 VM 终端，也不需要进。直接跟 agent 说话就行。

## 1. 你：启动 server（Mac）

```bash
git clone https://github.com/shafreeck/burrow.git
cd burrow
go build -o burrow-server ./cmd/burrow-server
./burrow-server --tunnel --vless 127.0.0.1:8443
```

`--tunnel` 会自动拉起 Cloudflare Quick Tunnel，公网 URL 打印在日志里，
形如 `https://xxx.trycloudflare.com`。**把这个 URL 发给你的 agent。**

server 还会打印 VLESS 导入链接，留着第 4 步用。

## 2. agent：启动 burrow-agent（VM）

在 Muse 里跟你的 agent 说：

> 把 burrow 仓库拉下来，编译 burrow-agent，连到 wss://xxx.trycloudflare.com/ws，
> upstream 用 http://198.19.0.1:3128，跑起来后告诉我日志。

agent 会在 VM 里执行：

```bash
go build -o /tmp/burrow-agent ./cmd/burrow-agent
/tmp/burrow-agent --server wss://xxx.trycloudflare.com/ws \
  --upstream http://198.19.0.1:3128
```

看到 `websocket connected` 就算通了。断线会自动重连，你不用管。

## 3. 你：装 CA（只做一次）

不装的话，浏览器经 VM 出口访问 HTTPS 会报证书错误——因为出口在做 MITM：

```bash
sudo ./burrow-server --install-ca
```

这把 `Hatch Sandbox Egress CA` 加进系统钥匙串。
**注意**：这是信任一个能签发任意网站证书的 CA，只在你明白含义的前提下做。
装完浏览器不再报错，但地址栏的"锁"代表的是 Hatch CA 的签发，不是网站原始证书链。

## 4. 你：开始用

- 浏览器 HTTP 代理填 `127.0.0.1:8080`，访问 https://api.ipify.org，
  看到的 IP 是 VM 的出口 IP，不是你本地的。
- 或用 VLESS 客户端导入第 1 步的链接（tunnet 实测可用，默认开 MUX）。
- 开 TUN 全局接管也不用配置：server 认出 cloudflared 自己的流量会自动直连，
  不会形成环路。

## 排错：找谁

| 现象 | 找谁 | 查什么 |
|---|---|---|
| agent 连不上 | agent | Quick Tunnel URL 是否过期（server 每次重启会变，把新的发给它） |
| 浏览器证书错误 | 你 | CA 没装，重做第 3 步 |
| 速度慢 | — | base64 文本帧有 ~33% 开销，已知代价 |
| VLESS 握手失败 | 你 | 客户端 MUX 设置，server 端 MUX 已支持 |

## 没验证过的

- VLESS over TLS 入站（代码有，没实测）
- Trojan 入站（代码有，没实测）
- 非 Muse VM 的受限环境（原理通用，没实测）
