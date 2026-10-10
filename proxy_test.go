package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClassifyHost(t *testing.T) {
	cases := []struct {
		host string
		want hostClass
	}{
		{"127.0.0.1:3082", classLoopback},
		{"localhost:3082", classLoopback},
		{"[::1]:3082", classLoopback},
		{"", classLoopback},
		{"192.168.0.110:3082", classLAN},
		{"10.0.0.5", classLAN},
		{"172.16.0.1", classLAN},
		{"100.64.1.1", classLAN}, // CGNAT（Tailscale/ZeroTier）
		{"[fe80::1]:80", classLAN},
		{"[fd00::1]:80", classLAN},
		{"macbook.local", classLAN},
		{"macbook", classLAN},
		{"172.32.0.1", classPublic}, // 私网段之外
		{"8.8.8.8", classPublic},
		{"example.com", classPublic},
		{"abc.trycloudflare.com", classPublic},
	}
	for _, c := range cases {
		if got := classifyHost(c.host); got != c.want {
			t.Errorf("classifyHost(%q) = %v，期望 %v", c.host, got, c.want)
		}
	}
}

func TestClassifySource(t *testing.T) {
	cases := []struct {
		addr     string
		want     hostClass
		wantOkay bool
	}{
		{"127.0.0.1:5000", classLoopback, true},
		{"[::1]:5000", classLoopback, true},
		{"192.168.0.110:5000", classLAN, true},
		{"::ffff:192.168.0.110:5000", classLAN, true}, // IPv4-mapped IPv6
		{"8.8.8.8:5000", classPublic, true},
		{"", classPublic, false},
		{"garbage", classPublic, false},
	}
	for _, c := range cases {
		got, ok := classifySource(c.addr)
		if ok != c.wantOkay || got != c.want {
			t.Errorf("classifySource(%q) = (%v, %v)，期望 (%v, %v)", c.addr, got, ok, c.want, c.wantOkay)
		}
	}
}

func TestPolicyHostOnlyTightens(t *testing.T) {
	// 伪造 Host=loopback，但真实来源是局域网 → 必须按局域网判定
	if got := policyHost("127.0.0.1:3082", "192.168.0.110:5000"); got != "192.168.0.110" {
		t.Errorf("伪造 loopback Host 未被收紧，得到 %q", got)
	}
	// 公网 Host 但来源是 loopback（隧道回连）→ 保持公网，绝不放松
	if got := policyHost("abc.trycloudflare.com", "127.0.0.1:5000"); got != "abc.trycloudflare.com" {
		t.Errorf("隧道场景不应放松，得到 %q", got)
	}
	// 来源级别不高于声称级别 → 原样保留
	if got := policyHost("192.168.0.110:3082", "192.168.0.110:5000"); got != "192.168.0.110:3082" {
		t.Errorf("同级来源不该改写 Host，得到 %q", got)
	}
}

func TestRateLimiterLocksAfterFailures(t *testing.T) {
	rl := newRateLimiter()
	ip := "192.168.0.9"
	for i := 0; i < 5; i++ {
		if locked, _ := rl.status(ip); locked {
			t.Fatalf("第 %d 次之前不该被锁", i+1)
		}
		rl.record(ip)
	}
	if locked, retry := rl.status(ip); !locked || retry <= 0 {
		t.Fatalf("5 次失败后应被锁，得到 locked=%v retry=%d", locked, retry)
	}
	rl.clear(ip)
	if locked, _ := rl.status(ip); locked {
		t.Fatal("登录成功后应解锁")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abcd1234", "abcd1234") {
		t.Error("相同字符串应判等")
	}
	if constantTimeEqual("abcd1234", "abcd1235") {
		t.Error("不同字符串不应判等")
	}
	if constantTimeEqual("abcd1234", "abcd12345") {
		t.Error("长度不同不应判等")
	}
}

// newTestHandler 起一个假上游，返回处理器与「收到的权威头」快照函数。
func newTestHandler(t *testing.T, cfg config) (http.Handler, func() (host, origin, secFetch, referer string)) {
	t.Helper()
	var host, origin, secFetch, referer string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, origin, secFetch, referer = r.Host, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Referer")
		if r.URL.Path == "/big.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":"`+strings.Repeat("x", 4096)+`"}`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><head><title>t</title></head><body>hi</body></html>")
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.upstream = u
	h, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h, func() (string, string, string, string) { return host, origin, secFetch, referer }
}

func TestHandlerRequiresPIN(t *testing.T) {
	h, _ := newTestHandler(t, config{pin: "abcd1234", lanEnabled: true, inject: true, tokens: &tokenProvider{}})

	req := httptest.NewRequest(http.MethodGet, "http://192.168.0.110:3082/", nil)
	req.Host = "192.168.0.110:3082"
	req.RemoteAddr = "192.168.0.110:5000"
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("未认证的浏览器导航应拿到登录页(200)，得到 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pocket-login") {
		t.Fatalf("应是登录页，实际内容：%s", rec.Body.String()[:min(120, rec.Body.Len())])
	}

	// API 请求则应 401 JSON，而不是登录页
	apiReq := httptest.NewRequest(http.MethodGet, "http://192.168.0.110:3082/api/status", nil)
	apiReq.Host = "192.168.0.110:3082"
	apiReq.RemoteAddr = "192.168.0.110:5000"
	apiRec := httptest.NewRecorder()
	h.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusUnauthorized {
		t.Fatalf("未认证的 API 请求应 401，得到 %d", apiRec.Code)
	}
}

func TestHandlerForwardsWithLoopbackAuthorityAndInjects(t *testing.T) {
	h, snapshot := newTestHandler(t, config{pin: "abcd1234", lanEnabled: true, inject: true, tokens: &tokenProvider{}})

	// 带 ?token=<PIN> 认证 → 应被转发并被注入 polyfill
	req := httptest.NewRequest(http.MethodGet, "http://192.168.0.110:3082/?token=abcd1234", nil)
	req.Host = "192.168.0.110:3082"
	req.RemoteAddr = "192.168.0.110:5000"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "http://192.168.0.110:3082/")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("已认证请求应 200，得到 %d", rec.Code)
	}
	host, origin, secFetch, referer := snapshot()
	if !strings.HasPrefix(host, "127.0.0.1:") {
		t.Errorf("Host 应被改写成上游权威，得到 %q", host)
	}
	if !strings.HasPrefix(origin, "http://") || !strings.Contains(origin, "127.0.0.1") {
		t.Errorf("Origin 应被改写成 loopback 权威，得到 %q", origin)
	}
	if secFetch != "same-origin" {
		t.Errorf("Sec-Fetch-Site 应为 same-origin，得到 %q", secFetch)
	}
	if !strings.Contains(referer, "127.0.0.1") {
		t.Errorf("Referer 应被改写成 loopback 权威，得到 %q", referer)
	}
	if !strings.Contains(rec.Body.String(), injectMark) {
		t.Error("HTML 应被注入 polyfill 标记")
	}
	// 种 cookie，让后续子资源也走 cookie 通道
	if len(rec.Result().Cookies()) == 0 {
		t.Error("URL 带 PIN 认证后应种下 cookie")
	}
}

func TestHandlerGzipsLargeJSON(t *testing.T) {
	h, _ := newTestHandler(t, config{pin: "abcd1234", lanEnabled: true, inject: true, tokens: &tokenProvider{}})

	req := httptest.NewRequest(http.MethodGet, "http://192.168.0.110:3082/big.json?token=abcd1234", nil)
	req.Host = "192.168.0.110:3082"
	req.RemoteAddr = "192.168.0.110:5000"
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("大 JSON 应被 gzip，Content-Encoding=%q", got)
	}
	if rec.Body.Len() >= 4096 {
		t.Errorf("压缩后应明显变小，实际 %d 字节", rec.Body.Len())
	}
}

func TestHandlerBlocksLANWhenDisabled(t *testing.T) {
	h, _ := newTestHandler(t, config{pin: "abcd1234", lanEnabled: false, inject: true, tokens: &tokenProvider{}})

	req := httptest.NewRequest(http.MethodGet, "http://192.168.0.110:3082/", nil)
	req.Host = "192.168.0.110:3082"
	req.RemoteAddr = "192.168.0.110:5000"
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("局域网访问关闭时应 403，得到 %d", rec.Code)
	}
	// 本机（loopback）访问不受影响
	local := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3082/?token=abcd1234", nil)
	local.Host = "127.0.0.1:3082"
	local.RemoteAddr = "127.0.0.1:5000"
	local.Header.Set("Accept", "text/html")
	localRec := httptest.NewRecorder()
	h.ServeHTTP(localRec, local)
	if localRec.Code != http.StatusOK {
		t.Fatalf("loopback 访问应放行，得到 %d", localRec.Code)
	}
}

func TestStripDesktopMarkers(t *testing.T) {
	u, _ := url.Parse("http://x/?dsh-desktop-mode=compatibility&keep=1")
	stripDesktopMarkers(u)
	if strings.Contains(u.RawQuery, "dsh-desktop") {
		t.Errorf("dsh-desktop-* 参数应被清掉，得到 %q", u.RawQuery)
	}
	if !strings.Contains(u.RawQuery, "keep=1") {
		t.Errorf("其它参数应保留，得到 %q", u.RawQuery)
	}
}

func TestInjectAfterHead(t *testing.T) {
	out := injectAfterHead("<html><head><title>x</title></head></html>", "SNIP")
	if !strings.Contains(out, "<head>SNIP") {
		t.Errorf("应插在 <head> 之后，得到 %q", out)
	}
	// 没有 head 时放最前
	out = injectAfterHead("<body>y</body>", "SNIP")
	if !strings.HasPrefix(out, "SNIP") {
		t.Errorf("无 head 时应前置，得到 %q", out)
	}
}
