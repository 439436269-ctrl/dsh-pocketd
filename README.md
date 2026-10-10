# dsh-pocketd

把 **DSH Web** 暴露到局域网的边缘反向代理，纯 Go 标准库实现（零第三方依赖），编译产物是单个静态二进制。

> 定位：**不是** DSH 插件，也不能替代 [`dsh-pocket`](https://www.npmjs.com/package/dsh-pocket)。
> 它是一个独立进程，站在 DSH Web 前面，负责「本机之外的人怎么安全地访问它」。

## 为什么需要这一层

DSH 的 `/api` 有一道浏览器信任栅栏：只认 loopback（`127.0.0.1`）权威，或者显式白名单；
官方也明确不支持把 web 服务绑到 `0.0.0.0`——因为那等于把「能执行代码的界面」暴露给整个网络。

本代理的做法是把入站请求的 **Host / Origin / Referer / Sec-Fetch-Site** 统一改写成
loopback 权威，再转发给本机 DSH。栅栏永远看到 loopback，于是手机可以：

```
手机浏览器 → http://<电脑内网IP>:3082  →  dsh-pocketd  →  DSH Web (127.0.0.1:19387)
```

`Referer` 与 `Sec-Fetch-Site` 也必须改写：DSH 宿主的特权方法栅栏（`settings.describe`、
`credentials.*` 等）会拒绝 `sec-fetch-site: cross-site`，并校验 `Origin` 与 `Host` 是否匹配，
不改写就会在设置/凭据页面上吃 403。

## 两种部署模式

### 模式 A：链式部署（本机推荐，实测可用）

挂在已有的 `dsh-pocket` 前面，由它完成 DSH 的会话握手：

```bash
# 1. 确认 dsh-pocket 的代理在跑（默认 *:3081）
lsof -nP -iTCP -sTCP:LISTEN | grep 3081

# 2. 起本代理，用 dsh-pocket 的局域网密码做一次性上游握手
UPIN=$(cat ~/.dsh/dsh-pocket/token-lan)
./dsh-pocketd -port 3082 -upstream http://127.0.0.1:3081 -upstream-pin "$UPIN"

# 3. 手机打开横幅里打印的 http://<内网IP>:3082，输入本条命令打印的访问密码
```

链式层的价值：多一道你自己可控的入口（端口、密码、限流、日志、后续可加隧道），
而不用改 `dsh-pocket` 一行代码。

### 模式 B：直连 DSH（需要 launch token）

```bash
./dsh-pocketd -port 3082 -pin 你的8位密码 -launch-token <token>
# 或让本进程定期执行命令去取：
./dsh-pocketd -port 3082 -pin 你的8位密码 -token-cmd 'cat /path/to/token'
```

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-port` | `3082` | 监听端口（`dsh-pocket` 默认占 3081，错开） |
| `-bind` | `0.0.0.0` | 监听地址 |
| `-upstream` | `$DSH_WEB_URL` 或 `127.0.0.1:19387` | 上游地址 |
| `-pin` | 随机 8 位 | 访问密码 |
| `-pin-file` | | 从文件读密码 |
| `-no-auth` | `false` | 关闭访问密码（仅限完全可信的网络） |
| `-lan` | `true` | 关掉后只允许 loopback 访问 |
| `-inject` | `true` | 向 HTML 注入非安全上下文所需的 polyfill |
| `-launch-token` | | DSH web 会话启动 token |
| `-token-cmd` | | 取 token 的命令（结果缓存 5 秒） |
| `-upstream-pin` | | 链式部署时上游自己的访问密码 |
| `-version` | | 打印版本 |

## 已实现 / 未实现

**已实现**

- loopback 权威改写（Host / Origin / Referer / Sec-Fetch-Site）
- 访问密码：`HttpOnly` cookie（值是 `sha256(PIN:进程随机密钥)`，重启即失效）、
  URL `?token=` 直达、`POST /pocket-login` 表单登录
- 常量时间比较（防计时侧信道）+ 三层登录限速（单 IP 滑动窗口 / 全局窗口 / 成功清零）
- 来源分级与防伪造：`Host` 可伪造，用不可伪造的 TCP 源地址给它设下限，**只收紧不放松**
- 局域网总开关；loopback 与公网不受影响
- 大 JSON/text 流式 gzip；SSE 与 WebSocket 原样透传（`FlushInterval: -1`）
- HTML 注入 `crypto.randomUUID` / `AbortSignal.any` polyfill（`http://内网IP` 属于
  非安全上下文，手机浏览器缺这两个 API 会导致页面直接崩）
- 清理历史遗留的 `dsh-desktop-*` 查询参数
- 链式部署的上游引导

**未实现**（相对 `dsh-pocket` 的功能差集）

- cloudflared 公网隧道管理与二维码
- DSH 设置页里的图形化面板（那要求是 JS 插件）
- WebSocket 应用层心跳保活（防 NAT 静默断链）
- Safari 在 `http://纯IP` 下不保存 3xx cookie 的握手兜底
- brotli 压缩（只做 gzip，免第三方依赖）

## 已知约束（重要）

**独立进程拿不到 DSH 的会话启动 token。**

新版 DSH Web 要求首屏 `GET /?token=<启动token>` 换一个绑定权威的会话 cookie，
否则 `/api` 与 WebSocket 一律 401。这个 token 由 DSH 宿主进程内部生成
（cordis 服务的 `connection.authenticatedUrl`），**只存在于宿主进程内**。

实测证据（2026-10-10，DSH Desktop 0.2.0-rc.2）：

```
# 直连上游，即使带全套 loopback 权威头，仍是 401
$ curl -H 'Host: 127.0.0.1:19387' -H 'Origin: http://127.0.0.1:19387' \
       -H 'Sec-Fetch-Site: same-origin' http://127.0.0.1:19387/
status=401
body:   dsh web authentication required; reopen the URL printed by dsh web.
```

三条出路，按推荐度排序：

1. **链式部署**（模式 A）——让 `dsh-pocket` 这个插件去握手，本代理只做边缘层。
   本机已实测：经它拿到完整的 DSH 页面（45486 字节，含 `__DSH_BOOT__`）。
2. **自己提供 token**（模式 B）——`-launch-token` / `-token-cmd`。
3. 上游 DSH 若提供「为 loopback 客户端签发 token」的接口，本代理即可直连。

## 构建与测试

```bash
go build -o dsh-pocketd .
go test ./...     # 12 个用例：分级/防伪造/限速/认证/改写/注入/压缩/局域网开关
go vet ./...
gofmt -l .        # 无输出即合规
```

## 与 dsh-pocket 的关系

- 行为参考：[`dsh-pocket`](https://github.com/shaobeichen/dsh-pocket)（作者 shaobeichen，**GPL-2.0**）。
  本项目的代码由行为规格独立实现，未复制其源码；polyfill 等属规范定义的标准实现。
- 由于参考项目是 GPL-2.0，且本项目在实现过程中研读过其源码，**本仓库同样采用 GPL-2.0**（见 `LICENSE`），
  以规避许可争议。若你要换许可，请先确认与参考项目的边界。
- `dsh-pocket` 是成熟的插件方案（含公网隧道、图形面板、二维码）；本项目是它的
  **边缘补充**，不是替代品。
