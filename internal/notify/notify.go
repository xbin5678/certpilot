package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"certpilot/internal/store"
)

// Notifier 负责把签发结果推送到 Webhook / Telegram
type Notifier struct {
	settings func() store.Settings
}

func New(settings func() store.Settings) *Notifier {
	return &Notifier{settings: settings}
}

// Notify 异步发送通知，失败不影响主流程
func (n *Notifier) Notify(title, body, level string) {
	st := n.settings()
	if level == "error" && !st.NotifyOnError {
		return
	}
	if level != "error" && !st.NotifyOnRenew {
		return
	}
	if st.WebhookURL == "" && (st.TelegramToken == "" || st.TelegramChatID == "") {
		return
	}
	go func() {
		if st.WebhookURL != "" {
			_ = postJSON(st.WebhookURL, map[string]any{
				"source": "certpilot",
				"level":  level,
				"title":  title,
				"body":   body,
				"time":   time.Now().Format(time.RFC3339),
			})
		}
		if st.TelegramToken != "" && st.TelegramChatID != "" {
			_ = sendTelegram(st.TelegramToken, st.TelegramChatID, title, body)
		}
	}()
}

func postJSON(u string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回 %d", resp.StatusCode)
	}
	return nil
}

func sendTelegram(token, chatID, title, body string) error {
	text := fmt.Sprintf("*%s*\n%s", escapeMarkdown(title), escapeMarkdown(body))
	form := url.Values{
		"chat_id":    {chatID},
		"text":       {text},
		"parse_mode": {"MarkdownV2"},
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm("https://api.telegram.org/bot"+token+"/sendMessage", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Markdown 解析失败时退回纯文本
		form.Del("parse_mode")
		form.Set("text", title+"\n"+body)
		resp2, err := client.PostForm("https://api.telegram.org/bot"+token+"/sendMessage", form)
		if err == nil {
			resp2.Body.Close()
		}
		return fmt.Errorf("telegram 返回 %d", resp.StatusCode)
	}
	return nil
}

// escapeMarkdown 转义 Telegram MarkdownV2 保留字符
func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(", "\\(",
		")", "\\)", "~", "\\~", "`", "\\`", ">", "\\>", "#", "\\#",
		"+", "\\+", "-", "\\-", "=", "\\=", "|", "\\|", "{", "\\{",
		"}", "\\}", ".", "\\.", "!", "\\!",
	)
	return replacer.Replace(s)
}
