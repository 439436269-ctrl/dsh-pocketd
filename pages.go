package main

const handshakePage = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="0; url=/">
<title>dsh-pocketd · 正在进入 | opening…</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
p{font-size:13px;color:#6b7280;margin:0}
</style></head><body><p>正在进入… | opening…</p></body></html>`

const lanDisabledPage = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dsh-pocketd · 局域网访问已关闭</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px 24px;max-width:360px;width:calc(100% - 48px);text-align:center}
h1{font-size:16px;margin:0 0 8px;color:#111827}
p{font-size:13px;color:#6b7280;margin:0;line-height:1.6}
</style></head><body><div class="card">
<h1>🔒 dsh-pocketd</h1>
<p>局域网访问已关闭。<br>请在电脑上用 --lan=false 之外的设置重新启动。<br><br>LAN access is disabled.</p>
</div></body></html>`

// loginPage 生成登录页。errMsg 为空表示首次展示，locked 表示触发了限速。
func loginPage(errMsg string, retryAfter int) string {
	hint := ""
	switch {
	case errMsg == "locked":
		hint = "尝试次数过多，请稍后再试 | Too many attempts"
		if retryAfter > 0 {
			hint = "尝试次数过多，请 " + itoa(retryAfter) + " 秒后再试 | Too many attempts"
		}
	case errMsg != "":
		hint = "密码错误，请重试 | Wrong PIN, try again"
	}
	return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dsh-pocketd · 访问验证</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:28px 24px;max-width:320px;width:calc(100% - 48px);text-align:center}
h1{font-size:16px;margin:0 0 4px;color:#111827}
p{font-size:13px;color:#6b7280;margin:0 0 16px}
input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:18px;letter-spacing:6px;text-align:center;border:1px solid #d1d5db;border-radius:8px;outline:none;margin-bottom:12px}
input:focus{border-color:#4f6ef7}
button{width:100%;padding:10px;font-size:15px;background:#4f6ef7;color:#fff;border:none;border-radius:8px;cursor:pointer}
.err{color:#dc2626;font-size:12px;margin-bottom:10px;min-height:16px}
</style></head><body><div class="card">
<h1>🔐 dsh-pocketd</h1>
<p>此地址受访问密码保护，请输入电脑上显示的密码 | Enter the PIN shown on the computer</p>
<div class="err">` + hint + `</div>
<form method="post" action="/pocket-login">
<input name="token" type="password" autocomplete="one-time-code" autofocus required>
<button type="submit">进入 | Enter</button>
</form>
</div></body></html>`
}

// itoa 避免为一个数字引入 strconv 依赖以外的东西时也保持页面函数自足。
func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
