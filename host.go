package main

import (
	"net"
	"strings"
)

// hostClass 是某个 Host / 来源地址的信任级别。
type hostClass int

const (
	classLoopback hostClass = iota // 本机（含 cloudflared 之类隧道进程的回连）
	classLAN                       // 私网 / 局域网
	classPublic                    // 其余一切陌生地址（fail closed）
)

func (c hostClass) String() string {
	switch c {
	case classLoopback:
		return "loopback"
	case classLAN:
		return "lan"
	default:
		return "public"
	}
}

// hostOnly 从 "host:port"、"[::1]:port" 或裸 IPv6 里取出主机部分。
func hostOnly(hostport string) string {
	h := strings.TrimSpace(strings.ToLower(hostport))
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end >= 0 {
			return h[1:end]
		}
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	// 裸 IPv6（::1）或没带方括号的 IPv6+端口（::ffff:192.168.0.110:5000）
	if net.ParseIP(h) == nil {
		if idx := strings.LastIndex(h, ":"); idx > 0 {
			if head := h[:idx]; net.ParseIP(head) != nil {
				return head
			}
		}
	}
	return h
}

// classifyIP 给一个 IP 定级。
func classifyIP(ip net.IP) hostClass {
	switch {
	case ip.IsLoopback():
		return classLoopback
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return classLAN
	}
	// CGNAT 100.64.0.0/10（Tailscale / ZeroTier 默认网段，公网不可路由）
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return classLAN
	}
	// IPv6 ULA fc00::/7
	if ip.To4() == nil && len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return classLAN
	}
	return classPublic
}

// classifyHost 按 Host 头定级（决定要不要访问密码）。
//
// 认不出的形态按 loopback 兜底，沿用 dsh-pocket 的历史行为：裸 IPv6、无 Host
// 这类情况多半就是本机访问，判成 public 会凭空要求密码。
func classifyHost(hostport string) hostClass {
	name := hostOnly(hostport)
	switch name {
	case "", "localhost", "0.0.0.0", "::1", "::":
		return classLoopback
	}
	if ip := net.ParseIP(name); ip != nil {
		return classifyIP(ip)
	}
	// mDNS（.local）与单标签名（NetBIOS 计算机名等）当局域网
	if strings.HasSuffix(name, ".local") || !strings.Contains(name, ".") {
		return classLAN
	}
	return classPublic
}

// classifySource 按 TCP 源地址定级。ok=false 表示拿不到源地址。
//
// 与 classifyHost 的区别在兜底方向：源地址是我们唯一无法伪造的信息，
// 认不出时必须按 public 处理，否则整条防线形同虚设。
func classifySource(remoteAddr string) (class hostClass, ok bool) {
	if strings.TrimSpace(remoteAddr) == "" {
		return classPublic, false
	}
	ip := net.ParseIP(hostOnly(remoteAddr))
	if ip == nil {
		return classPublic, false
	}
	return classifyIP(ip), true
}

// policyHost 返回用于策略判定的 Host。
//
// Host 头完全由客户端控制：能直连代理端口的人只要写 Host: 127.0.0.1:3082
// 就会被判成本机，从而绕过局域网开关与局域网密码。这里用不可伪造的 TCP
// 源地址给 Host 声明设一个下限——**只收紧、绝不放松**：经隧道进来的公网
// 请求源地址正是 127.0.0.1，若按源地址覆盖就会把公网降级成本机免密。
func policyHost(hostport, remoteAddr string) string {
	actual, ok := classifySource(remoteAddr)
	if !ok {
		return hostport
	}
	if actual <= classifyHost(hostport) {
		return hostport
	}
	return hostOnly(remoteAddr)
}
