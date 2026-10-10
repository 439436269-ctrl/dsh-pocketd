package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	authCookieName = "dsh_pocketd_token"
	cookieMaxAge   = 30 * 24 * 60 * 60 // 30 天（秒）
)

// ---------- 访问密码（PIN） ----------

// authenticator 负责「手机第一次进来要输的那个密码」。
//
// cookie 值不是明文 PIN，而是 sha256(PIN:sessionKey)：sessionKey 每次进程启动
// 随机生成，于是 DSH 或本代理重启后旧 cookie 自动失效，而 PIN 本身不会出现在
// 浏览器的 cookie 存储里。
type authenticator struct {
	pin        string
	sessionKey string
	limiter    *rateLimiter
}

func newAuthenticator(pin string) *authenticator {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return &authenticator{
		pin:        pin,
		sessionKey: hex.EncodeToString(raw),
		limiter:    newRateLimiter(),
	}
}

func (a *authenticator) cookieValue() string {
	sum := sha256.Sum256([]byte(a.pin + ":" + a.sessionKey))
	return hex.EncodeToString(sum[:])
}

// constantTimeEqual 常量时间比较：普通 == 会在首个不同字节处提前返回，
// 理论上可被计时侧信道逐字节还原 PIN。
func constantTimeEqual(x, y string) bool {
	return subtle.ConstantTimeCompare([]byte(x), []byte(y)) == 1
}

// check 校验请求是否已认证。seedFrom 非空表示这次的凭据来自 URL 上的
// ?token=<明文 PIN>，调用方应顺手种一个 cookie，让后续子资源也走 cookie。
func (a *authenticator) check(r *http.Request) (ok bool, seedFrom string) {
	if c, err := r.Cookie(authCookieName); err == nil && constantTimeEqual(c.Value, a.cookieValue()) {
		return true, ""
	}
	if q := r.URL.Query().Get("token"); q != "" && constantTimeEqual(q, a.pin) {
		return true, q
	}
	return false, ""
}

func (a *authenticator) setCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    a.cookieValue(),
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ---------- 登录限速 ----------

// rateLimiter 三层防护：单 IP 滑动窗口、全局滑动窗口、成功即清零。
// 8 位密码本身可接受，真正的风险是无限制重试让穷举变得可行。
type rateLimiter struct {
	mu          sync.Mutex
	window      time.Duration
	maxFails    int
	lockFor     time.Duration
	globalMax   int
	globalLock  time.Duration
	fails       map[string]*failWindow
	locked      map[string]time.Time
	globalFails *failWindow
	globalUntil time.Time
}

type failWindow struct {
	count int
	start time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		window:      time.Minute,
		maxFails:    5,
		lockFor:     time.Minute,
		globalMax:   50,
		globalLock:  30 * time.Second,
		fails:       make(map[string]*failWindow),
		locked:      make(map[string]time.Time),
		globalFails: &failWindow{},
	}
}

// status 返回该 IP 当前是否处于锁定期，以及还需要等多少秒。
func (l *rateLimiter) status(ip string) (locked bool, retryAfter int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.globalUntil.After(now) {
		return true, int(l.globalUntil.Sub(now).Seconds()) + 1
	}
	if until, ok := l.locked[ip]; ok && until.After(now) {
		return true, int(until.Sub(now).Seconds()) + 1
	}
	return false, 0
}

// record 记一次失败，达阈值则触发单 IP 锁与全局锁。
func (l *rateLimiter) record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	rec, ok := l.fails[ip]
	if !ok || now.Sub(rec.start) > l.window {
		rec = &failWindow{start: now}
		l.fails[ip] = rec
	}
	rec.count++
	if rec.count >= l.maxFails {
		l.locked[ip] = now.Add(l.lockFor)
	}

	if now.Sub(l.globalFails.start) > l.window {
		l.globalFails = &failWindow{start: now}
	}
	l.globalFails.count++
	if l.globalFails.count >= l.globalMax {
		l.globalUntil = now.Add(l.globalLock)
	}

	// 防内存膨胀：条目过多时清掉已出窗口的记录
	if len(l.fails) > 2000 {
		for k, v := range l.fails {
			if now.Sub(v.start) > l.window {
				delete(l.fails, k)
			}
		}
	}
}

// clear 登录成功后清空该 IP 的计数与锁。
func (l *rateLimiter) clear(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
	delete(l.locked, ip)
}

// ---------- 辅助 ----------

// clientIP 取客户端身份：只信任 TCP 源地址；当来源是本机（隧道进程回连）时
// 才采信 cf-connecting-ip——那是请求头，能直连端口的人可以随手伪造。
func clientIP(r *http.Request) string {
	host := hostOnly(r.RemoteAddr)
	if cls, ok := classifySource(r.RemoteAddr); ok && cls == classLoopback {
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			return cf
		}
	}
	if host == "" {
		return "unknown"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// randomPIN 生成 8 位字母数字密码。
func randomPIN() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // 去掉易混字符
	out := make([]byte, 8)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic(err)
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out)
}
