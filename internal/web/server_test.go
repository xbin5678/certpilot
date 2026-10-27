package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"certpilot/internal/acme"
	"certpilot/internal/compat"
	"certpilot/internal/notify"
	"certpilot/internal/scheduler"
	"certpilot/internal/store"
)

func newTestServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	var mu sync.Mutex
	cur, err := st.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	get := func() store.Settings { mu.Lock(); defer mu.Unlock(); return cur }
	set := func(s store.Settings) error {
		mu.Lock()
		defer mu.Unlock()
		if err := st.SaveSettings(s); err != nil {
			return err
		}
		cur = s
		return nil
	}
	det := compat.NewDetector(func() string { return get().Compat3XUI })
	nt := notify.New(get)
	mgr := acme.NewManager(st, dir, det, nt, get)
	sched := scheduler.New(st, mgr)
	srv := New(st, mgr, det, sched, "test", get, set)
	return srv.Handler(), st
}

func do(t *testing.T, h http.Handler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "certpilot")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAuthRequired(t *testing.T) {
	h, _ := newTestServer(t)
	w := do(t, h, "GET", "/api/certs", nil, nil)
	if w.Code != 401 {
		t.Fatalf("未登录应返回 401，实际 %d", w.Code)
	}
}

func TestSetupAndCRUD(t *testing.T) {
	h, _ := newTestServer(t)

	w := do(t, h, "POST", "/api/setup", map[string]any{"password": "test12345", "email": "a@b.com"}, nil)
	if w.Code != 200 {
		t.Fatalf("初始化失败: %d %s", w.Code, w.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("初始化后未下发会话 cookie")
	}

	// 密码过短
	if w := do(t, h, "POST", "/api/certs", map[string]any{
		"domains": []string{""}, "challenge": "dns-01-manual",
	}, cookie); w.Code != 400 {
		t.Fatalf("空域名应返回 400，实际 %d", w.Code)
	}

	// 正常创建
	w = do(t, h, "POST", "/api/certs", map[string]any{
		"name":      "站点",
		"domains":   []string{"a.com\nwww.a.com"},
		"ca":        "letsencrypt",
		"keyType":   "ec256",
		"challenge": "dns-01-manual",
		"issueNow":  false,
	}, cookie)
	if w.Code != 200 {
		t.Fatalf("创建失败: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Cert  store.Cert `json:"cert"`
		JobID string     `json:"jobId"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if len(created.Cert.Domains) != 2 {
		t.Fatalf("域名解析错误: %v", created.Cert.Domains)
	}
	if created.Cert.Status != store.StatusPending {
		t.Fatalf("新证书状态应为 pending，实际 %s", created.Cert.Status)
	}

	// 列表
	w = do(t, h, "GET", "/api/certs", nil, cookie)
	var list []store.Cert
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("期望 1 张证书，实际 %d", len(list))
	}

	// 更新
	w = do(t, h, "PUT", "/api/certs/"+created.Cert.ID, map[string]any{
		"name":            "改名了",
		"autoRenew":       false,
		"renewBeforeDays": 15,
	}, cookie)
	if w.Code != 200 {
		t.Fatalf("更新失败: %d %s", w.Code, w.Body.String())
	}
	var updated store.Cert
	_ = json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.Name != "改名了" || updated.AutoRenew || updated.RenewBeforeDays != 15 {
		t.Fatalf("更新未生效: %+v", updated)
	}

	// 概览
	w = do(t, h, "GET", "/api/overview", nil, cookie)
	if w.Code != 200 {
		t.Fatalf("概览失败: %d", w.Code)
	}
	var ov map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ov)
	if ov["total"].(float64) != 1 {
		t.Fatalf("概览数量不对: %v", ov["total"])
	}
	if _, ok := ov["compat"]; !ok {
		t.Fatal("概览应包含兼容性状态")
	}

	// 删除
	if w := do(t, h, "DELETE", "/api/certs/"+created.Cert.ID, nil, cookie); w.Code != 200 {
		t.Fatalf("删除失败: %d", w.Code)
	}
	w = do(t, h, "GET", "/api/certs", nil, cookie)
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("删除后应为空，实际 %d", len(list))
	}
}

func TestCSRFHeaderRequired(t *testing.T) {
	h, _ := newTestServer(t)
	do(t, h, "POST", "/api/setup", map[string]any{"password": "test12345"}, nil)

	req := httptest.NewRequest("POST", "/api/logout", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("缺少自定义头应返回 403，实际 %d", w.Code)
	}
}

func TestSettingsUpdate(t *testing.T) {
	h, _ := newTestServer(t)
	w := do(t, h, "POST", "/api/setup", map[string]any{"password": "test12345"}, nil)
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			cookie = c
		}
	}

	w = do(t, h, "PUT", "/api/settings", map[string]any{
		"acmeEmail":  "new@example.org",
		"compat3xui": "on",
		"defaultCa":  "zerossl",
		"eab":        map[string]any{"gts": map[string]string{"kid": "k", "hmac": "h"}},
	}, cookie)
	if w.Code != 200 {
		t.Fatalf("保存设置失败: %d %s", w.Code, w.Body.String())
	}

	w = do(t, h, "GET", "/api/settings", nil, cookie)
	var s settingsView
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if s.ACMEEmail != "new@example.org" || s.Compat3XUI != "on" || s.DefaultCA != "zerossl" {
		t.Fatalf("设置未生效: %+v", s)
	}
	if s.EAB["gts"].KID != "k" {
		t.Fatalf("EAB 未保存: %+v", s.EAB)
	}
}
