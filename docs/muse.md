# 保姆级教程：在 Muse 上用 burrow

**读完这篇，你不需要懂任何网络知识。** 跟着一步步做，最后你的浏览器
流量会从你的 Muse 沙箱 VM 里出去。

## 你和你的 agent 如何分工

- **你**：在 Mac 上动手的 4 件事（下载、启动 server、装证书、配浏览器）
- **你的 agent**：在 VM 里动手的 1 件事（启动 burrow-agent）——你只需要在
  Muse App 里跟它说一句话，它全包

你**不需要**、也**不能**进 VM 终端。VM 是 agent 的地盘。

---

## 准备：检查你的 Mac

打开终端（Terminal.app），逐行运行下面两行，看看装没装：

```bash
go version
cloudflared --version
```

- 如果 `go version` 显示 `go1.21` 或更高：OK，跳过
- 如果提示 `command not found`：去 https://go.dev/dl 下载 macOS 版，
  一路下一步安装，装完**重开一个终端**再跑 `go version` 确认
- 如果 `cloudflared` 提示找不到：运行 `brew install cloudflared`
 （没装 brew 的先去 https://brew.sh 装）

两样都有了，继续。

---

## 第 1 步：下载 burrow（Mac）

```bash
cd ~
git clone https://github.com/shafreeck/burrow.git
cd burrow
```

看到 `Cloning into 'burrow'...` 和一堆 `remote:` 输出，最后停住，就是下好了。
运行 `ls`，你应该看到 `cmd`、`internal`、`docs` 这些目录。

## 第 2 步：编译 server（Mac）

```bash
go build -o burrow-server ./cmd/burrow-server
```

**这行跑完没有任何输出，就是成功了。** 运行 `ls -lh burrow-server`，
看到一个几 MB 的文件，就对了。

如果报错 `go: command not found`：回"准备"那节，Go 没装好。

## 第 3 步：启动 server（Mac）

```bash
./burrow-server --tunnel --bind vless://127.0.0.1:8443
```

这条命令只开启 VLESS。若第 6 步选择浏览器 HTTP 代理，请在启动时加上
`--bind http://127.0.0.1:18080`。所有代理入站都需要显式指定，默认仅监听控制面。

等 10～20 秒，终端里会出现这样一块：

```
============================================================
  Agent connection

  Public URL:  https://xxx-xxx-xxx.trycloudflare.com

  Agent command:
    burrow-agent --server 'wss://xxx-xxx-xxx.trycloudflare.com/ws'
============================================================
```

**做两件事：**

1. **复制完整 Agent WebSocket URL、Build 和 AI handoff**，下一步发给远端 agent
2. **这个终端不要关**，server 要一直跑着。关了隧道就断了

往上翻一点，你还能看到这两行，**也复制下来**，第 6 步配手机/客户端用：

```
  VLESS UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  VLESS URL:  vless://xxxx@127.0.0.1:8443?encryption=none&security=none&type=tcp#burrow
```

> ⚠️ Quick Tunnel 模式每次重启 server，`Public URL` 会变；固定域名不会。变了就重新发给 agent（第 4 步）。

## 第 4 步：把 server 输出的完整 AI handoff 交给远端 agent

复制完整 Agent WebSocket URL、Build 版本和 AI handoff。远端 agent 应检出同一
commit 并核对 `--version`，从当前云环境文档核实 HTTP CONNECT 出口代理；
允许直连时省略 upstream，需要代理时设置 `BURROW_UPSTREAM`。不要假设固定代理地址。
认证启用时通过安全渠道设置 `BURROW_TOKEN`，不要将凭据写入交接文字。
`session_authenticated` 表示 WSS 和 hello 成功，仍需通过 Mac 的代理入口访问
允许的目标来验收。查看 UTC 会话事件、心跳和关闭状态定位断线；不要绕过环境拒绝。
Quick Tunnel 重启会改变 URL；固定域名由外部 connector 管理，不随 server 重启改变。

## 第 5 步：安装当前 VM 出口的 CA（Mac）

VM 的出口会对 HTTPS 做中间人（签发假证书），你的浏览器会报证书错误。
先让 VM 里的 agent 从**当前 VM 的信任库**导出 `Hatch Sandbox Egress CA`
公钥证书，并给出 SHA-256 指纹。将文件保存为 `current-egress-ca.crt`，在 Mac
上核对指纹后安装。CA 可能随出口变化；同名不代表同一张证书，轮换周期尚未确认。

在 Mac 终端**新开一个标签页**运行：

```bash
cd ~/burrow
openssl x509 -in current-egress-ca.crt -noout -subject -dates -fingerprint -sha256
sudo ./burrow-server --install-ca --ca-cert ./current-egress-ca.crt
```

输入你的 Mac 登录密码（输的时候不显示，输完回车）。

**这行命令在干什么，你得知道**：它把一张叫 `Hatch Sandbox Egress CA`
的证书加进你系统的信任列表。这张 CA 能签发**任意网站**的证书。
装完之后，浏览器经 VM 出口访问 HTTPS 不再报错，但地址栏那把锁
代表的是这张 CA 的签发，不是网站原本的证书链。

只在你自己的 Mac 上做，别在公司电脑上做。

验证装没装上：

```bash
security find-certificate -c "Hatch Sandbox Egress CA" /Library/Keychains/System.keychain
```

有输出仅证明该名称的证书存在；必须核对 SHA-256 指纹是否与当前 VM 一致。
不带 `--ca-cert` 会安装内嵌 CA，其当前指纹见 [README](../README-zh.md#vm-出口-ca)。
仍需核对它是否匹配当前 VM。不要直接信任从报错连接
抓到的 CA，也不要用关闭 TLS 校验来替代安装正确的 CA。

## 第 6 步：配浏览器（Mac）

### 方法 A：浏览器走 HTTP 代理（最简单）

以 Chrome 为例：设置 → 搜索"代理" → 打开代理设置 →
勾选"网页代理 (HTTP)"，填 `127.0.0.1`，端口 `18080`（启动时需指定 `--bind http://127.0.0.1:18080`）。
HTTPS 代理也一样填。

通过上述代理访问当前环境允许的验收目标，例如允许访问时的 https://api.ipify.org。
这证明代理路径的出口；VM 单独 curl 只证明 VM 出站，并不能证明隧道转发。
记录请求确实通过本地代理、目标响应和 UTC 会话事件后再报告端到端成功。

### 方法 B：VLESS 客户端（手机/电脑通用）

把第 3 步复制的 `VLESS URL`（`vless://` 开头那串）导入
tunnet / Shadowrocket / Streisand 这类客户端，直接连接。
tunnet 实测可用，它默认开 MUX，server 端已经支持。

## 第 7 步：每天怎么用

1. Mac 上起 server（第 3 步那条命令）
2. 把新的 Public URL 发给 agent，让它重跑 burrow-agent（第 4 步那段话，换 URL）
3. 浏览器代理开着，直接用

出口 CA 的指纹没变就无需重装；换 VM/出口后如果再次出现信任错误，重新核对。

---

## 常见问题

**Q：agent 说 `websocket connected`，但浏览器打不开网页？**
A：先问 agent，它的 VM 里直接 `curl https://example.com` 通不通。
VM 里通、浏览器不通 → 查你浏览器的代理设置（IP/端口填错最常见）。
VM 里也不通 → 沙箱出口代理 当前环境核实的出口代理 可能抖了，等几分钟重试。

**Q：访问 HTTPS 网站，浏览器还是报证书错误？**
A：先核对当前 VM 的 CA 与 Mac 已安装 CA 的 SHA-256 指纹。即使名称相同，
密钥也可能不同；`ERR_CERT_AUTHORITY_INVALID` 不等于证书过期。
确认安装的是当前 CA 后，再完全退出并重开浏览器。

**Q：开启 TUN 后 agent 掉线，关闭就恢复？**
A：把 `cloudflared` 和 `burrow-server` 在 TUN 客户端中设为直连/排除，
确保 DNS 不依赖 burrow。升级后的心跳能触发重连，但不能修复仍然循环的路由。
具体绕行范围见 [README](../README-zh.md#tun-模式与断线排查)。

**Q：server 终端里没有出现 "Agent connection"？**
A：等 30 秒。还没有的话，看终端里有没有 `cloudflared` 的报错发给你的 agent 看，
或者直接问它。

**Q：能不能不每次手动发 URL 给 agent？**
A：已有固定 Cloudflare Tunnel 时，使用 `--tunnel --domain 你的域名`，
发布规则指向 `http://127.0.0.1:9000`。agent 继续使用同一条 `wss://域名/ws`。
只有自动创建的 Quick Tunnel 才会在重启后更换 URL。

**Q：流量会被看到吗？**
A：你的流量路径是：浏览器 → 你 Mac 上的 server → Cloudflare 隧道 →
VM 里的 agent → 沙箱出口代理 → 目标网站。
沙箱出口代理能看到你访问的域名（HTTPS 内容看不到，但它做 MITM，
理论上能解密——这就是第 5 步让你装 CA 的原因）。
**别拿它传银行密码之类的敏感信息。**

---

## 没验证过的（先别指望）

- VLESS over TLS 入站：代码写了，没实测
- Trojan 入站：代码写了，没实测
- 非 Muse VM 的受限环境：原理通用，没实测
