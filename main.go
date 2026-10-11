// Command dsh-pocketd 是一个把 DSH Web 暴露到局域网（进而可放到隧道后面）的
// 边缘反向代理：监听 0.0.0.0、用自己的访问密码拦住陌生人、把请求的
// Host/Origin/Referer/Sec-Fetch-Site 统一改写成 loopback 权威后转发给本机 DSH。
//
// 为什么需要改写权威：DSH 的 /api 浏览器信任栅栏只认 loopback（127.0.0.1）
// 或显式白名单，且明确不支持把 web 绑到 0.0.0.0。代理让栅栏永远看到 loopback，
// 于是手机直接访问 http://<电脑内网IP>:3082 就能拿到和电脑一致的界面。
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const version = "0.1.1"

func main() {
	var (
		port        = flag.Int("port", 3082, "监听端口")
		bind        = flag.String("bind", "0.0.0.0", "监听地址")
		upstreamRaw = flag.String("upstream", defaultUpstream(), "上游 DSH web 地址")
		pin         = flag.String("pin", "", "访问密码（留空则随机生成 8 位）")
		pinFile     = flag.String("pin-file", "", "从文件读取访问密码")
		noAuth      = flag.Bool("no-auth", false, "关闭访问密码（仅限完全可信的网络）")
		lanEnabled  = flag.Bool("lan", true, "是否允许局域网访问")
		inject      = flag.Bool("inject", true, "向 HTML 注入非安全上下文所需的 polyfill")
		launchToken = flag.String("launch-token", "", "DSH web 会话启动 token（首屏握手用）")
		tokenCmd    = flag.String("token-cmd", "", "获取启动 token 的命令，输出应为其值")
		upstreamPin = flag.String("upstream-pin", "", "链式部署：上游自身的访问密码，用于一次性握手")
		showVersion = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVersion {
		os.Stdout.WriteString("dsh-pocketd " + version + "\n")
		return
	}

	upstream, err := url.Parse(*upstreamRaw)
	if err != nil || upstream.Host == "" {
		log.Fatalf("dsh-pocketd: -upstream 不是合法 URL: %q", *upstreamRaw)
	}

	effectivePIN := ""
	switch {
	case *noAuth:
	case *pin != "":
		effectivePIN = *pin
	case *pinFile != "":
		raw, err := os.ReadFile(*pinFile)
		if err != nil {
			log.Fatalf("dsh-pocketd: 读取 -pin-file 失败: %v", err)
		}
		effectivePIN = strings.TrimSpace(string(raw))
	default:
		effectivePIN = randomPIN()
	}

	handler, err := newHandler(config{
		upstream:   upstream,
		tokens:     &tokenProvider{literal: *launchToken, cmd: *tokenCmd},
		bootstrap:  &upstreamBootstrap{target: upstream, pin: *upstreamPin},
		pin:        effectivePIN,
		noAuth:     *noAuth,
		lanEnabled: *lanEnabled,
		inject:     *inject,
	})
	if err != nil {
		log.Fatalf("dsh-pocketd: 初始化失败: %v", err)
	}

	addr := net.JoinHostPort(*bind, itoa(*port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}

	banner(upstream, addr, effectivePIN, *noAuth, *launchToken != "" || *tokenCmd != "", *upstreamPin != "")

	// 收到 Ctrl-C / SIGTERM 时优雅退出
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Println("dsh-pocketd: 收到退出信号，正在关闭…")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("dsh-pocketd: %v", err)
	}
}

// defaultUpstream 优先用 DSH 自己注入的环境变量，其次才是常见默认端口。
func defaultUpstream() string {
	if v := strings.TrimSpace(os.Getenv("DSH_WEB_URL")); v != "" {
		return v
	}
	return "http://127.0.0.1:19387"
}

func banner(upstream *url.URL, addr, pin string, noAuth, hasToken, chainMode bool) {
	line := strings.Repeat("─", 52)
	log.Println(line)
	log.Printf("dsh-pocketd %s", version)
	log.Printf("  上游      http://%s", upstream.Host)
	log.Printf("  监听      %s", addr)
	// 多网卡时把候选都列出来：默认路由网卡不一定是手机所在的那个网段
	for _, ip := range lanIPs() {
		log.Printf("  手机访问  http://%s:%s", ip, portOf(addr))
	}
	if noAuth {
		log.Printf("  访问密码  已关闭（任何能连到此端口的人都能进）")
	} else {
		log.Printf("  访问密码  %s", pin)
	}
	switch {
	case chainMode:
		// 链式部署下会话握手由上游完成，本进程不需要 launch token
		log.Printf("  握手      链式部署：由上游 http://%s 完成会话握手", upstream.Host)
	case !hasToken:
		log.Printf("  提示      未提供 launch token：直连本版 DSH 会 401。")
		log.Printf("            用 -launch-token / -token-cmd 提供，或改用链式部署（-upstream-pin）。")
	}
	log.Println(line)
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return "3082"
}

// lanIPs 列出本机所有可用的私网 IPv4，默认路由所在的地址排最前。
//
// 多网卡机器上「第一个私网地址」经常是虚拟网桥/VPN 的，用户照着连不上；
// 而默认路由网卡也不一定是手机所在网段（比如 Wi-Fi 与有线各一个网段），
// 所以全部列出来让用户挑。
func lanIPs() []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}

	// 默认路由地址优先（UDP dial 不真的发包，只查路由表）
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() != nil && addr.IP.IsPrivate() {
			add(addr.IP.String())
		}
		_ = conn.Close()
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || !ip.IsPrivate() {
				continue
			}
			add(ip.String())
		}
	}
	return out
}
