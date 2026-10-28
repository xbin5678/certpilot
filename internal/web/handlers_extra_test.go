package web

import (
	"encoding/json"
	"net/http"
	"runtime"
	"testing"

	"certpilot/internal/store"
)

// login 完成初始化并返回会话 cookie
func login(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	w := do(t, h, "POST", "/api/setup", map[string]any{"password": "test12345", "email": "a@b.com"}, nil)
	if w.Code != 200 {
		t.Fatalf("初始化失败: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("未拿到会话 cookie")
	return nil
}

func getJSON(t *testing.T, h http.Handler, path string, cookie *http.Cookie, out any) int {
	t.Helper()
	w := do(t, h, "GET", path, nil, cookie)
	if out != nil && w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), out)
	}
	return w.Code
}

// ---------- 网页终端 ----------

func TestTerminalStatusDefaultsOff(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	var got map[string]any
	if code := getJSON(t, h, "/api/terminal", cookie, &got); code != 200 {
		t.Fatalf("状态接口应返回 200，实际 %d", code)
	}
	if got["enabled"] != false {
		t.Fatalf("终端默认应为关闭，实际 %v", got["enabled"])
	}
	if got["requirePassword"] != false {
		t.Fatalf("默认不应要求二次密码，实际 %v", got["requirePassword"])
	}
	if got["idleMinutes"] != float64(15) {
		t.Fatalf("默认空闲超时应为 15 分钟，实际 %v", got["idleMinutes"])
	}
}

// 未开启时不能签发终端票据 —— 这是最后一道闸，必须挡住
func TestTerminalTicketRejectedWhenDisabled(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	w := do(t, h, "POST", "/api/terminal/ticket", map[string]any{}, cookie)
	if w.Code != 403 {
		t.Fatalf("终端关闭时取票据应返回 403，实际 %d", w.Code)
	}
}

func TestTerminalTicketWithoutPassword(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PTY 仅在 Linux 上可用，非 Linux 平台票据接口会返回 400")
	}
	h, _ := newTestServer(t)
	cookie := login(t, h)

	// 通过接口开启终端（免二次密码）
	if w := do(t, h, "PUT", "/api/settings", map[string]any{
		"terminalEnabled":         true,
		"terminalRequirePassword": false,
	}, cookie); w.Code != 200 {
		t.Fatalf("开启终端失败: %d %s", w.Code, w.Body.String())
	}

	w := do(t, h, "POST", "/api/terminal/ticket", map[string]any{}, cookie)
	if w.Code != 200 {
		t.Fatalf("免密码模式应直接发票据，实际 %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Ticket string `json:"ticket"`
		TTL    int    `json:"ttl"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Ticket) < 16 {
		t.Fatalf("票据长度异常: %q", resp.Ticket)
	}
	if resp.TTL != 60 {
		t.Fatalf("票据有效期应为 60 秒，实际 %d", resp.TTL)
	}
}

func TestTerminalWSRejectsBadTicket(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	// 未登录
	if w := do(t, h, "GET", "/api/terminal/ws?ticket=abc", nil, nil); w.Code != 401 {
		t.Fatalf("未登录访问 WS 应返回 401，实际 %d", w.Code)
	}
	// 已登录但终端没开
	if w := do(t, h, "GET", "/api/terminal/ws?ticket=abc", nil, cookie); w.Code != 403 {
		t.Fatalf("终端关闭时 WS 应返回 403，实际 %d", w.Code)
	}
}

// ---------- 设置项 ----------

func TestSettingsTerminalFieldsRoundTrip(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	body := map[string]any{
		"terminalEnabled":         true,
		"terminalShell":           "/bin/zsh",
		"terminalIdleMinutes":     42,
		"terminalRequirePassword": true,
	}
	if w := do(t, h, "PUT", "/api/settings", body, cookie); w.Code != 200 {
		t.Fatalf("保存设置失败: %d %s", w.Code, w.Body.String())
	}

	var got settingsView
	if code := getJSON(t, h, "/api/settings", cookie, &got); code != 200 {
		t.Fatalf("读取设置失败: %d", code)
	}
	if !got.TerminalEnabled || got.TerminalShell != "/bin/zsh" ||
		got.TerminalIdleMinutes != 42 || !got.TerminalRequirePassword {
		t.Fatalf("终端设置未正确保存: %+v", got)
	}
}

func TestSettingsRejectsRelativeShell(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)
	w := do(t, h, "PUT", "/api/settings", map[string]any{"terminalShell": "bash"}, cookie)
	if w.Code != 400 {
		t.Fatalf("相对路径 shell 应被拒绝，实际 %d", w.Code)
	}
}

func TestSettingsClampsIdleMinutes(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)
	if w := do(t, h, "PUT", "/api/settings", map[string]any{"terminalIdleMinutes": 0}, cookie); w.Code != 200 {
		t.Fatalf("保存失败: %d", w.Code)
	}
	var got settingsView
	getJSON(t, h, "/api/settings", cookie, &got)
	if got.TerminalIdleMinutes < 1 {
		t.Fatalf("空闲时间应被夹到至少 1 分钟，实际 %d", got.TerminalIdleMinutes)
	}
}

// ---------- 3x-ui 安装 ----------

func TestXuiStateReportsPlatform(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	var got struct {
		Supported bool           `json:"supported"`
		State     map[string]any `json:"state"`
	}
	if code := getJSON(t, h, "/api/xui/state", cookie, &got); code != 200 {
		t.Fatalf("状态接口应返回 200，实际 %d", code)
	}
	if got.Supported != (runtime.GOOS == "linux") {
		t.Fatalf("supported 与平台不符: %v", got.Supported)
	}
}

func TestXuiInstallRejectedOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("该用例验证非 Linux 平台的拦截")
	}
	h, _ := newTestServer(t)
	cookie := login(t, h)
	w := do(t, h, "POST", "/api/xui/install", map[string]any{
		"port": 2053, "username": "admin", "password": "12345678",
	}, cookie)
	if w.Code != 400 {
		t.Fatalf("非 Linux 平台应拒绝安装，实际 %d", w.Code)
	}
}

func TestXuiInstallValidatesInput(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)
	// 端口 80 不允许
	w := do(t, h, "POST", "/api/xui/install", map[string]any{
		"port": 80, "username": "admin", "password": "12345678",
	}, cookie)
	if w.Code != 400 {
		t.Fatalf("端口 80 应被拒绝，实际 %d %s", w.Code, w.Body.String())
	}
	// 密码过短
	w = do(t, h, "POST", "/api/xui/install", map[string]any{
		"port": 2053, "username": "admin", "password": "1",
	}, cookie)
	if w.Code != 400 {
		t.Fatalf("弱密码应被拒绝，实际 %d", w.Code)
	}
}

// ---------- 证书路径与下载 ----------

func TestPathsAndDownload(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	w := do(t, h, "POST", "/api/certs", map[string]any{
		"name": "p", "domains": []string{"p.example.com"},
		"challenge":      "dns-01-manual",
		"deployCertPath": "/root/cert/{domain}/fullchain.pem",
		"deployKeyPath":  "/root/cert/{domain}/privkey.pem",
	}, cookie)
	if w.Code != 200 {
		t.Fatalf("创建失败: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Cert store.Cert `json:"cert"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	var paths []certPathView
	if code := getJSON(t, h, "/api/paths", cookie, &paths); code != 200 {
		t.Fatalf("路径接口失败: %d", code)
	}
	if len(paths) != 1 {
		t.Fatalf("应有 1 条路径，实际 %d", len(paths))
	}
	// {domain} 占位符必须被展开
	if paths[0].CertPath != "/root/cert/p.example.com/fullchain.pem" {
		t.Fatalf("占位符未展开: %s", paths[0].CertPath)
	}
	if paths[0].KeyPath != "/root/cert/p.example.com/privkey.pem" {
		t.Fatalf("私钥路径不对: %s", paths[0].KeyPath)
	}
	if !paths[0].IsDeployed {
		t.Fatal("配置了部署路径应标记为已部署")
	}

	// 未签发时下载应 404
	if w := do(t, h, "GET", "/api/certs/"+created.Cert.ID+"/download?file=fullchain", nil, cookie); w.Code != 404 {
		t.Fatalf("未签发时下载应返回 404，实际 %d", w.Code)
	}
	// 非法文件类型
	if w := do(t, h, "GET", "/api/certs/"+created.Cert.ID+"/download?file=../../etc/passwd", nil, cookie); w.Code != 400 {
		t.Fatalf("非法文件类型应返回 400，实际 %d", w.Code)
	}
}

func TestDeleteCert(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	w := do(t, h, "POST", "/api/certs", map[string]any{
		"domains": []string{"del.example.com"}, "challenge": "dns-01-manual",
	}, cookie)
	var created struct {
		Cert store.Cert `json:"cert"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	if w := do(t, h, "DELETE", "/api/certs/"+created.Cert.ID, nil, cookie); w.Code != 200 {
		t.Fatalf("删除失败: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, h, "GET", "/api/certs/"+created.Cert.ID, nil, cookie); w.Code != 404 {
		t.Fatalf("删除后查询应返回 404，实际 %d", w.Code)
	}
	// 再删一次
	if w := do(t, h, "DELETE", "/api/certs/"+created.Cert.ID, nil, cookie); w.Code != 404 {
		t.Fatalf("重复删除应返回 404，实际 %d", w.Code)
	}
}

func TestUpdateCertKeepsFields(t *testing.T) {
	h, _ := newTestServer(t)
	cookie := login(t, h)

	w := do(t, h, "POST", "/api/certs", map[string]any{
		"name": "原名称", "domains": []string{"u.example.com"},
		"challenge": "dns-01-manual", "autoRenew": true,
		"deployCmd": "echo hi",
	}, cookie)
	var created struct {
		Cert store.Cert `json:"cert"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	// 只改名称，其余字段应沿用
	w = do(t, h, "PUT", "/api/certs/"+created.Cert.ID, map[string]any{"name": "新名称"}, cookie)
	if w.Code != 200 {
		t.Fatalf("更新失败: %d %s", w.Code, w.Body.String())
	}
	var updated store.Cert
	_ = json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.Name != "新名称" {
		t.Fatalf("名称未更新: %s", updated.Name)
	}
	if updated.DeployCmd != "echo hi" {
		t.Fatalf("未提供的字段被清空了: %q", updated.DeployCmd)
	}
	if !updated.AutoRenew {
		t.Fatal("未提供的 autoRenew 被清空了")
	}
	if len(updated.Domains) != 1 || updated.Domains[0] != "u.example.com" {
		t.Fatalf("域名被清空了: %v", updated.Domains)
	}
}
