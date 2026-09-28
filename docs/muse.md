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
./burrow-server --tunnel --vless 127.0.0.1:8443
```

等 10～20 秒，终端里会出现这样一块：

```
============================================================
  Tunnel is ready!

  Public URL:  https://xxx-xxx-xxx.trycloudflare.com

  Agent command:
    burrow-agent --server wss://xxx-xxx-xxx.trycloudflare.com/ws \
        --upstream http://<proxy> [--token <token>]
============================================================
```

**做两件事：**

1. **复制 `Public URL` 那行**（`https://` 开头、`trycloudflare.com` 结尾的那串），
   下一步要发给 agent
2. **这个终端不要关**，server 要一直跑着。关了隧道就断了

往上翻一点，你还能看到这两行，**也复制下来**，第 6 步配手机/客户端用：

```
  VLESS UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  VLESS URL:  vless://xxxx@127.0.0.1:8443?encryption=none&security=none&type=tcp#burrow
```

> ⚠️ 每次重启 server，`Public URL` 都会变。变了就重新发给 agent（第 4 步）。

## 第 4 步：让 agent 启动（Muse App 里）

打开 Muse，跟你的 agent 说下面这段话（把 `xxx` 换成你第 3 步复制的 URL）：

> 把 https://github.com/shafreeck/burrow 这个仓库拉到 VM 里，
> 编译出 burrow-agent，然后用下面这条命令跑起来：
> `./burrow-agent --server wss://xxx-xxx-xxx.trycloudflare.com/ws --upstream http://198.19.0.1:3128`
> 注意把 `https://` 换成 `wss://`。跑起来后把日志发我，确认连上了。

**注意**：URL 是 `https://` 开头，但 agent 命令里要用 `wss://`。
上面那段话已经写对了，直接复制就行，别改。

agent 回你类似这样的日志，就是通了：

```
connecting...
websocket connected
```

如果 agent 说连不上：先检查 URL 有没有复制错、server 那头的终端是不是还开着。
URL 过期是最常见的原因（server 重启过），重新复制新的发给它。

## 第 5 步：装证书（Mac，只做一次）

VM 的出口会对 HTTPS 做中间人（签发假证书），你的浏览器会报证书错误。
解决办法是信任签发它的 CA。在 Mac 终端**新开一个标签页**运行：

```bash
cd ~/burrow
sudo ./burrow-server --install-ca
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

有输出就是装上了。

## 第 6 步：配浏览器（Mac）

### 方法 A：浏览器走 HTTP 代理（最简单）

以 Chrome 为例：设置 → 搜索"代理" → 打开代理设置 →
勾选"网页代理 (HTTP)"，填 `127.0.0.1`，端口 `8080`。
HTTPS 代理也一样填。

然后访问 https://api.ipify.org，页面上显示的 IP：
- **不是**你家宽带的 IP
- **是** VM 的出口 IP（跟 agent 在 VM 里跑 `curl https://api.ipify.org` 看到的一样）

对上了，就成了。你可以让 agent 帮你确认这个 IP。

### 方法 B：VLESS 客户端（手机/电脑通用）

把第 3 步复制的 `VLESS URL`（`vless://` 开头那串）导入
tunnet / Shadowrocket / Streisand 这类客户端，直接连接。
tunnet 实测可用，它默认开 MUX，server 端已经支持。

## 第 7 步：每天怎么用

1. Mac 上起 server（第 3 步那条命令）
2. 把新的 Public URL 发给 agent，让它重跑 burrow-agent（第 4 步那段话，换 URL）
3. 浏览器代理开着，直接用

CA 只装一次，以后不用重装。

---

## 常见问题

**Q：agent 说 `websocket connected`，但浏览器打不开网页？**
A：先问 agent，它的 VM 里直接 `curl https://example.com` 通不通。
VM 里通、浏览器不通 → 查你浏览器的代理设置（IP/端口填错最常见）。
VM 里也不通 → 沙箱出口代理 `198.19.0.1:3128` 可能抖了，等几分钟重试。

**Q：访问 HTTPS 网站，浏览器还是报证书错误？**
A：第 5 步的 CA 没装好，或者装完没重启浏览器。Chrome 要完全退出重开。

**Q：server 终端里没有出现 "Tunnel is ready!"？**
A：等 30 秒。还没有的话，看终端里有没有 `cloudflared` 的报错发给你的 agent 看，
或者直接问它。

**Q：能不能不每次手动发 URL 给 agent？**
A：目前 Quick Tunnel 的 URL 每次重启都变，这是 Cloudflare 免费版的限制。
以后可以考虑固定域名方案（需要你自己有域名，另说）。

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
