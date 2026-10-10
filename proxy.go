package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ctxInjected 标记「这次请求我们补过 launch token」，用于把上游的 303
// 改写成 200 过渡页（见 modifyResponse）。
type ctxKey int

const ctxInjected ctxKey = iota

const injectMark = `data-dsh-pocketd-polyfill="1"`

// polyfill 只在浏览器缺这两个 API 时生效。手机走 http://<内网IP>:端口 属于
// 非安全上下文，crypto.randomUUID 与 AbortSignal.any 都会缺失，而 DSH 客户端
// 连接层依赖它们（缺 randomUUID 直接抛错，缺 AbortSignal.any 消息发不出去）。
const polyfill = `<script data-dsh-pocketd-polyfill="1">` +
	`!function(){try{var c=self.crypto;if(c&&!c.randomUUID){c.randomUUID=function(){var b=new Uint8Array(16);c.getRandomValues(b);b[6]=b[6]&15|64;b[8]=b[8]&63|128;var h="";for(var i=0;i<16;i++){var x=b[i].toString(16);h+=(x.length<2?"0":"")+x;if(i===3||i===5||i===7||i===9)h+="-";}return h;};}}catch(e){}}();` +
	`!function(){try{if(self.AbortSignal&&!self.AbortSignal.any){self.AbortSignal.any=function(list){var ctl=new AbortController();var arr=Array.prototype.slice.call(list||[]);var done=false;var handlers=arr.map(function(s){return function(){fire(s);};});function fire(s){if(done)return;done=true;arr.forEach(function(s,i){try{s.removeEventListener("abort",handlers[i]);}catch(e){}});try{ctl.abort(s&&s.reason);}catch(e){ctl.abort();}}arr.forEach(function(s,i){if(s.aborted){fire(s);}else{s.addEventListener("abort",handlers[i]);}});return ctl.signal;};}}catch(e){}}();` +
	`</script>`

// tokenProvider 提供 DSH web 的会话启动 token。
//
// 硬约束：这个 token 由 DSH 宿主进程内部生成（cordis 服务
// connection.authenticatedUrl），独立进程无法自己 mint，也拿不到——实测直连
// 上游、即使把 Host/Origin 全改写成 loopback 权威，仍是 401。所以这里做成
// 可插拔来源：命令行直接给，或给一条命令让本进程定期执行去取。
type tokenProvider struct {
	literal string
	cmd     string

	mu      sync.Mutex
	value   string
	fetched time.Time
}

func (p *tokenProvider) get() string {
	if p == nil {
		return ""
	}
	if p.literal != "" {
		return p.literal
	}
	if p.cmd == "" {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.fetched) < 5*time.Second { // 短缓存，避免每请求都 fork
		return p.value
	}
	out, err := exec.Command("sh", "-c", p.cmd).Output()
	p.fetched = time.Now()
	if err != nil {
		log.Printf("dsh-pocketd: 取 launch token 失败: %v", err)
		p.value = ""
		return ""
	}
	p.value = strings.TrimSpace(string(out))
	return p.value
}

type config struct {
	upstream   *url.URL
	tokens     *tokenProvider
	bootstrap  *upstreamBootstrap
	pin        string
	noAuth     bool
	lanEnabled bool
	inject     bool
}

// upstreamBootstrap 处理「上游自己也要密码」的链式部署。
//
// 典型场景：把本代理挂在 dsh-pocket 前面（上游 = 127.0.0.1:3081）。这时上游
// 会用自己的 PIN 拦我们，而我们又拿不到 DSH 的 launch token（见 README
// 「已知约束」）——于是用一个上游 PIN 做一次握手，把拿到的 cookie（上游的
// 访问 cookie + DSH 的会话 cookie）常驻复用，之后所有请求直接带上去。
type upstreamBootstrap struct {
	target *url.URL
	pin    string

	mu      sync.Mutex
	cookies []*http.Cookie
	tried   bool
}

// ensure 做一次上游握手（只做一次，失败也不反复重试）。
func (b *upstreamBootstrap) ensure() {
	if b == nil || b.pin == "" {
		return
	}
	b.mu.Lock()
	if b.tried {
		b.mu.Unlock()
		return
	}
	b.tried = true
	b.mu.Unlock()

	u := *b.target
	u.Path = "/"
	q := u.Query()
	q.Set("token", b.pin)
	u.RawQuery = q.Encode()

	client := &http.Client{
		Timeout: 8 * time.Second,
		// 不跟随 303：token 换 cookie 的响应本身就是我们要的
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(u.String())
	if err != nil {
		log.Printf("dsh-pocketd: 上游握手失败: %v", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	cookies := resp.Cookies()
	b.mu.Lock()
	b.cookies = cookies
	b.mu.Unlock()
	log.Printf("dsh-pocketd: 上游握手完成（HTTP %d，拿到 %d 个 cookie）", resp.StatusCode, len(cookies))
}

// apply 把引导 cookie 合并进出站请求头。
func (b *upstreamBootstrap) apply(h http.Header) {
	if b == nil || b.pin == "" {
		return
	}
	b.ensure()

	b.mu.Lock()
	cookies := b.cookies
	b.mu.Unlock()
	if len(cookies) == 0 {
		return
	}

	parts := make([]string, 0, len(cookies)+1)
	if existing := h.Get("Cookie"); existing != "" {
		parts = append(parts, existing)
	}
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	h.Set("Cookie", strings.Join(parts, "; "))
}

// newHandler 把「策略判定 → 认证 → 反代」串成一条链。
func newHandler(cfg config) (http.Handler, error) {
	rp, err := newReverseProxy(cfg)
	if err != nil {
		return nil, err
	}
	auth := newAuthenticator(cfg.pin)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 策略判定一律用 policyHost：Host 头可伪造，用源地址给它设下限
		host := policyHost(r.Header.Get("Host"), r.RemoteAddr)
		cls := classifyHost(host)

		// 局域网开关：只拦经局域网地址进来的请求，loopback 与公网放行
		if cls == classLAN && !cfg.lanEnabled {
			if isHTMLRequest(r) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, lanDisabledPage)
			} else {
				http.Error(w, `{"error":"lan-disabled"}`, http.StatusForbidden)
			}
			return
		}

		if !cfg.noAuth {
			// 登录提交
			if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/pocket-login") {
				handleLogin(w, r, auth)
				return
			}

			ip := clientIP(r)
			isGuess := r.URL.Query().Get("token") != ""

			if isGuess {
				if locked, retry := auth.limiter.status(ip); locked {
					if isHTMLRequest(r) {
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						w.Header().Set("Cache-Control", "no-store")
						w.WriteHeader(http.StatusOK)
						_, _ = io.WriteString(w, loginPage("locked", retry))
					} else {
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("Retry-After", strconv.Itoa(retry))
						w.WriteHeader(http.StatusTooManyRequests)
						_, _ = io.WriteString(w, `{"error":"too-many-attempts"}`)
					}
					return
				}
			}

			ok, seedFrom := auth.check(r)
			if !ok {
				if isGuess {
					auth.limiter.record(ip)
					log.Printf("dsh-pocketd: 密码错误 IP=%s", ip)
				}
				if isHTMLRequest(r) {
					locked, retry := auth.limiter.status(ip)
					msg := ""
					if locked {
						msg = "locked"
					}
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("Cache-Control", "no-store")
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, loginPage(msg, retry))
				} else {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
				}
				return
			}
			if seedFrom != "" {
				auth.limiter.clear(ip)
				auth.setCookie(w)
				// 把访问密码从 URL 上摘掉：它是发给本代理的，透传到上游会污染
				// DSH 自己的会话握手——上游会把 ?token= 当成它的启动 token，
				// 判为无效后回 303 甚至报错（实测：链式部署下整页变成 303）。
				q := r.URL.Query()
				q.Del("token")
				r.URL.RawQuery = q.Encode()
			}
		}

		rp.ServeHTTP(w, r)
	}), nil
}

func handleLogin(w http.ResponseWriter, r *http.Request, auth *authenticator) {
	ip := clientIP(r)
	if locked, retry := auth.limiter.status(ip); locked {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, loginPage("locked", retry))
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if constantTimeEqual(r.PostFormValue("token"), auth.pin) {
		auth.limiter.clear(ip)
		auth.setCookie(w)
		// 带上这个参数：让代理在下一跳强制重做一次首屏握手
		http.Redirect(w, r, "/?dsh-pocket-auth=1", http.StatusFound)
		return
	}
	auth.limiter.record(ip)
	log.Printf("dsh-pocketd: 登录失败 IP=%s", ip)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, loginPage("wrong", 0))
}

func newReverseProxy(cfg config) (*httputil.ReverseProxy, error) {
	authority := cfg.upstream.Host

	rp := &httputil.ReverseProxy{
		Transport: &http.Transport{
			// 自己决定是否压缩，别让 Transport 透明解压后再由我们判断
			DisableCompression: true,
			MaxIdleConns:       32,
			IdleConnTimeout:    90 * time.Second,
		},
		// SSE 必须立刻 flush，否则流式界面会卡住不出字
		FlushInterval: -1,

		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.upstream) // 同时把出站 Host 头改写成上游权威

			out := pr.Out
			in := pr.In

			// DSH 宿主的特权方法栅栏会拒绝 sec-fetch-site=cross-site，
			// 并校验 Origin 与 Host 是否匹配——远程访问这两个头不改写就会被 403。
			out.Header.Set("Origin", "http://"+authority)
			out.Header.Set("Sec-Fetch-Site", "same-origin")
			if ref := in.Header.Get("Referer"); ref != "" {
				if u, err := url.Parse(ref); err == nil {
					u.Scheme = "http"
					u.Host = authority
					out.Header.Set("Referer", u.String())
				} else {
					out.Header.Set("Referer", "http://"+authority+"/")
				}
			} else {
				out.Header.Del("Referer")
			}

			// 历史遗留的 dsh-desktop-* 查询参数会让上游把普通浏览器判成渲染器
			stripDesktopMarkers(out.URL)

			// 链式部署：上游自己也要密码时，带上引导得到的 cookie
			cfg.bootstrap.apply(out.Header)

			// 首屏补一次 launch token（换绑定权威的会话 cookie）。
			// 每次都补会造成 303 死循环，所以已经握过手（带 dsh-auth-* cookie）就跳过。
			if tok := cfg.tokens.get(); tok != "" && out.Method == http.MethodGet && out.URL.Path == "/" {
				force := in.URL.Query().Has("dsh-pocket-auth")
				if force || !hasDSHAuthCookie(in.Header.Get("Cookie")) {
					q := out.URL.Query()
					q.Set("token", tok)
					out.URL.RawQuery = q.Encode()
					pr.Out = out.WithContext(context.WithValue(out.Context(), ctxInjected, true))
				}
			}
		},

		ModifyResponse: func(resp *http.Response) error {
			return modifyResponse(resp, cfg)
		},

		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("dsh-pocketd: 上游不可达: %v", err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "dsh-pocketd: 连不上上游 %s —— 请确认 DSH 正在运行 | cannot reach upstream: %v\n", authority, err)
		},
	}
	return rp, nil
}

func modifyResponse(resp *http.Response, cfg config) error {
	// WebSocket 升级（101）原样透传，绝不能碰
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return nil
	}
	req := resp.Request
	contentType := resp.Header.Get("Content-Type")

	// 1) 我们补过 token、上游拿 303 回来换 cookie：改写成 200 过渡页。
	//    Safari 在 http://纯IP 源上不保存 3xx 响应下发的 cookie，直接放 303
	//    过去会让「补 token → 303 → 仍无 cookie → 再补」无限循环。
	if resp.StatusCode == http.StatusSeeOther && req.Context().Value(ctxInjected) != nil && isHTMLRequest(req) {
		_ = resp.Body.Close()
		page := handshakePage
		resp.Body = io.NopCloser(strings.NewReader(page))
		resp.ContentLength = int64(len(page))
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		resp.Header.Set("Content-Length", strconv.Itoa(len(page)))
		resp.Header.Del("Location")
		resp.Header.Set("Cache-Control", "no-store")
		resp.Header.Set("X-Dsh-Pocketd-Handshake", "transition")
		return nil
	}

	// 2) HTML 文档注入 polyfill（压缩流不能注入，会损坏页面）
	if cfg.inject && strings.Contains(contentType, "text/html") && !isCompressed(resp.Header) {
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		html := string(body)
		if !strings.Contains(html, injectMark) {
			html = injectAfterHead(html, polyfill)
		}
		resp.Body = io.NopCloser(strings.NewReader(html))
		resp.ContentLength = int64(len(html))
		resp.Header.Set("Content-Length", strconv.Itoa(len(html)))
		// 注入后的文档带本进程的动态补丁，必须禁缓存，否则中间层会把旧文档发出去
		resp.Header.Set("Cache-Control", "no-store")
		resp.Header.Del("ETag")
		resp.Header.Del("Last-Modified")
		resp.Header.Del("Expires")
		return nil
	}

	// 3) 大 JSON/text 流式压缩：长会话历史一次十几 MB，手机流量顶不住
	if shouldGzip(req, resp) {
		orig := resp.Body
		pr, pw := io.Pipe()
		zw := gzip.NewWriter(pw)
		go func() {
			_, copyErr := io.Copy(zw, orig)
			closeErr := zw.Close()
			_ = orig.Close()
			if copyErr == nil {
				copyErr = closeErr
			}
			_ = pw.CloseWithError(copyErr)
		}()
		resp.Body = pr
		resp.ContentLength = -1
		resp.Header.Set("Content-Encoding", "gzip")
		resp.Header.Del("Content-Length")
	}
	return nil
}

func shouldGzip(req *http.Request, resp *http.Response) bool {
	if !strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") {
		return false
	}
	if isCompressed(resp.Header) {
		return false
	}
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") {
		return false // SSE 原样透传，压缩会毁掉流式语义
	}
	if resp.ContentLength >= 0 && resp.ContentLength < 1024 {
		return false
	}
	return strings.Contains(contentType, "application/json") || strings.HasPrefix(contentType, "text/")
}

func isCompressed(h http.Header) bool {
	ce := strings.ToLower(h.Get("Content-Encoding"))
	return strings.Contains(ce, "gzip") || strings.Contains(ce, "br") || strings.Contains(ce, "deflate")
}

// isHTMLRequest 判断这是不是一次浏览器导航（决定给页面还是给 401 JSON）。
func isHTMLRequest(r *http.Request) bool {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		return true
	}
	// 按 pathname 判断而不是整串比较：根路径常带 query（/?token=… 同样是导航）
	p := r.URL.Path
	return p == "/" || strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".htm")
}

func hasDSHAuthCookie(cookieHeader string) bool {
	return strings.Contains(cookieHeader, "dsh-auth-")
}

// stripDesktopMarkers 就地清掉 dsh-desktop-* 查询参数。
func stripDesktopMarkers(u *url.URL) {
	if u.RawQuery == "" || !strings.Contains(u.RawQuery, "dsh-desktop-") {
		return
	}
	q := u.Query()
	changed := false
	for k := range q {
		if strings.HasPrefix(k, "dsh-desktop-") {
			q.Del(k)
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
}

// injectAfterHead 把脚本插在 <head ...> 之后；找不到 head 就放最前面。
func injectAfterHead(html, snippet string) string {
	lower := strings.ToLower(html)
	idx := strings.Index(lower, "<head")
	if idx >= 0 {
		if end := strings.Index(lower[idx:], ">"); end >= 0 {
			pos := idx + end + 1
			return html[:pos] + snippet + html[pos:]
		}
	}
	return snippet + html
}
