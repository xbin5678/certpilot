package web

import (
	"log"
	"net/http"
	"runtime"
	"time"

	"certpilot/internal/terminal"

	"golang.org/x/crypto/bcrypt"
)

// handleTerminalStatus 终端可用性与当前会话
func (s *Server) handleTerminalStatus(w http.ResponseWriter, r *http.Request) {
	st := s.getSet()
	writeJSON(w, 200, map[string]any{
		"enabled":     st.TerminalEnabled,
		"supported":   runtime.GOOS == "linux",
		"shell":       st.TerminalShell,
		"idleMinutes": st.TerminalIdleMinutes,
		"sessions":    s.term.Sessions(),
	})
}

// handleTerminalTicket 二次验证管理密码，换取一次性 WebSocket 票据。
// 之所以不直接用会话 cookie 建立终端：cookie 一旦被 XSS 或中间人拿到，
// 就等于把 root shell 交出去；这里要求重新证明一次身份。
func (s *Server) handleTerminalTicket(w http.ResponseWriter, r *http.Request) {
	st := s.getSet()
	if !st.TerminalEnabled {
		writeErr(w, 403, "Web 终端未启用，请先在设置里开启")
		return
	}
	if runtime.GOOS != "linux" {
		writeErr(w, 400, "当前平台不支持 Web 终端")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(st.AdminPasswordHash), []byte(req.Password)) != nil {
		time.Sleep(500 * time.Millisecond)
		s.st.AddEvent("", "warn", "Web 终端二次验证失败")
		writeErr(w, 401, "密码错误")
		return
	}
	if s.term.Active() > 0 {
		writeErr(w, 409, terminal.ErrBusy.Error())
		return
	}
	tk := s.term.IssueTicket()
	s.st.AddEvent("", "warn", "打开 Web 终端（root shell）")
	writeJSON(w, 200, map[string]any{"ok": true, "ticket": tk, "ttl": 60})
}

// handleTerminalWS WebSocket 升级入口。
// 同时要求：会话 cookie 有效 + 设置里已开启 + 一次性票据有效。
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	if !s.term.Enabled() {
		http.Error(w, "Web 终端未启用", http.StatusForbidden)
		return
	}
	if !s.term.ConsumeTicket(r.URL.Query().Get("ticket")) {
		http.Error(w, "终端票据无效或已过期，请重新验证密码", http.StatusForbidden)
		return
	}
	if err := s.term.ServeWS(r.Context(), w, r); err != nil {
		// 握手失败时 ServeWS 可能已经写过响应，这里只记日志
		log.Printf("terminal: %v", err)
		return
	}
	s.st.AddEvent("", "info", "Web 终端会话结束")
}
