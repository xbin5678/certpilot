package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"certpilot/internal/store"
)

func settingsWith(webhook string, onRenew, onError bool) func() store.Settings {
	return func() store.Settings {
		s := store.DefaultSettings()
		s.WebhookURL = webhook
		s.NotifyOnRenew = onRenew
		s.NotifyOnError = onError
		return s
	}
}

func TestEscapeMarkdown(t *testing.T) {
	cases := map[string]string{
		"普通文本":      "普通文本",
		"a_b":       `a\_b`,
		"*bold*":    `\*bold\*`,
		"1.2.3":     `1\.2\.3`,
		"[link](x)": `\[link\]\(x\)`,
		"a-b+c=d":   `a\-b\+c\=d`,
		"100%":      "100%", // 百分号不是保留字符
	}
	for in, want := range cases {
		if got := escapeMarkdown(in); got != want {
			t.Errorf("escapeMarkdown(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestNotifySendsWebhook(t *testing.T) {
	var (
		mu   sync.Mutex
		body map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := New(settingsWith(srv.URL, true, true))
	n.Notify("测试标题", "正文内容", "success")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := body
		mu.Unlock()
		if got != nil {
			if got["title"] != "测试标题" || got["body"] != "正文内容" {
				t.Fatalf("payload 不对: %+v", got)
			}
			if got["source"] != "certpilot" || got["level"] != "success" {
				t.Fatalf("payload 字段不对: %+v", got)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("超时未收到 webhook 请求")
}

func TestNotifyRespectsSwitches(t *testing.T) {
	var (
		mu    sync.Mutex
		count int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// 两个开关都关：一条都不该发
	n := New(settingsWith(srv.URL, false, false))
	n.Notify("成功", "x", "success")
	n.Notify("失败", "y", "error")

	// 只开 error：只有 error 该发
	n2 := New(settingsWith(srv.URL, false, true))
	n2.Notify("成功", "x", "success")
	n2.Notify("失败", "y", "error")

	time.Sleep(400 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatalf("只应发出 1 条（error），实际 %d", count)
	}
}

func TestNotifyNoChannelConfigured(t *testing.T) {
	// 什么都没配时不应发起请求，也不应 panic
	n := New(settingsWith("", true, true))
	n.Notify("标题", "正文", "success")
	time.Sleep(100 * time.Millisecond)
}

func TestNotifyWebhookErrorDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	n := New(settingsWith(srv.URL, true, true))
	n.Notify("标题", "正文", "success") // 内部忽略错误
	time.Sleep(300 * time.Millisecond)
}

func TestNotifyTelegramSkippedWithoutChatID(t *testing.T) {
	// 只有 token 没有 chat id：不该尝试发 Telegram
	settings := func() store.Settings {
		s := store.DefaultSettings()
		s.TelegramToken = "123:abc"
		s.TelegramChatID = ""
		return s
	}
	n := New(settings)
	n.Notify("标题", "正文", "success")
	time.Sleep(100 * time.Millisecond)
}

func TestPostJSONRejectsBadURL(t *testing.T) {
	if err := postJSON("://bad", map[string]any{}); err == nil {
		t.Fatal("非法 URL 应返回错误")
	}
}

func TestPostJSONNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	err := postJSON(srv.URL, map[string]string{"a": "b"})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("应返回含状态码的错误，实际 %v", err)
	}
}
