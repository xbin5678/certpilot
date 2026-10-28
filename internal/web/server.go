package web

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"certpilot/internal/acme"
	"certpilot/internal/compat"
	"certpilot/internal/scheduler"
	"certpilot/internal/store"
	"certpilot/internal/task"
	"certpilot/internal/terminal"
	"certpilot/internal/xui"

	"golang.org/x/crypto/bcrypt"
)

//go:embed static
var staticFS embed.FS

// Server Web 管理后台
type Server struct {
	st      *store.Store
	mgr     *acme.Manager
	det     *compat.Detector
	sched   *scheduler.Scheduler
	version string

	xuiTasks *task.Manager
	xuiInst  *xui.Installer
	xuiMu    sync.Mutex // 保证「检查是否在装 + 创建任务」原子，避免并发双开
	term     *terminal.Manager

	inflight   int64         // 当前处理中的请求数
	lastActive atomic.Int64  // 最后一次活动时间（UnixNano）
	settingsMu chan struct{} // 串行化设置写入
	getSet     func() store.Settings
	setSet     func(store.Settings) error
}

func New(st *store.Store, mgr *acme.Manager, det *compat.Detector, sched *scheduler.Scheduler, version string,
	getSet func() store.Settings, setSet func(store.Settings) error) *Server {
	s := &Server{
		st: st, mgr: mgr, det: det, sched: sched, version: version,
		getSet: getSet, setSet: setSet,
		xuiTasks:   task.NewManager(),
		xuiInst:    xui.NewInstaller(),
		settingsMu: make(chan struct{}, 1),
	}
	// 终端的开关、shell、空闲超时都实时读设置，改设置后无需重启
	s.term = terminal.NewManager(
		func() bool { return s.getSet().TerminalEnabled },
		func() string { return s.getSet().TerminalShell },
		func() time.Duration {
			m := s.getSet().TerminalIdleMinutes
			if m <= 0 {
				m = 15
			}
			return time.Duration(m) * time.Minute
		},
	)
	s.lastActive.Store(time.Now().UnixNano())
	return s
}

// Handler 构建路由
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 静态资源
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /", s.index)

	// 认证
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("POST /api/password", s.auth(s.handlePassword))

	// 业务
	mux.HandleFunc("GET /api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("GET /api/certs", s.auth(s.handleListCerts))
	mux.HandleFunc("POST /api/certs", s.auth(s.handleCreateCert))
	mux.HandleFunc("GET /api/certs/{id}", s.auth(s.handleGetCert))
	mux.HandleFunc("PUT /api/certs/{id}", s.auth(s.handleUpdateCert))
	mux.HandleFunc("DELETE /api/certs/{id}", s.auth(s.handleDeleteCert))
	mux.HandleFunc("POST /api/certs/{id}/issue", s.auth(s.handleIssue))
	mux.HandleFunc("POST /api/certs/{id}/renew", s.auth(s.handleRenew))
	mux.HandleFunc("POST /api/certs/{id}/revoke", s.auth(s.handleRevoke))
	mux.HandleFunc("GET /api/certs/{id}/download", s.auth(s.handleDownload))
	mux.HandleFunc("GET /api/certs/{id}/inspect", s.auth(s.handleInspect))
	mux.HandleFunc("GET /api/paths", s.auth(s.handlePaths))
	mux.HandleFunc("POST /api/certs/{id}/deploy", s.auth(s.handleDeployNow))

	mux.HandleFunc("GET /api/jobs", s.auth(s.handleJobs))
	mux.HandleFunc("GET /api/jobs/{id}", s.auth(s.handleJob))

	mux.HandleFunc("GET /api/settings", s.auth(s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", s.auth(s.handleUpdateSettings))
	mux.HandleFunc("GET /api/cas", s.auth(s.handleCAs))
	mux.HandleFunc("GET /api/dnsproviders", s.auth(s.handleDNSProviders))
	mux.HandleFunc("GET /api/compat", s.auth(s.handleCompat))
	mux.HandleFunc("GET /api/events", s.auth(s.handleEvents))
	mux.HandleFunc("POST /api/check", s.auth(s.handleCheckNow))

	// 3x-ui 一键安装
	mux.HandleFunc("GET /api/xui/state", s.auth(s.handleXuiState))
	mux.HandleFunc("POST /api/xui/install", s.auth(s.handleXuiInstall))
	mux.HandleFunc("GET /api/xui/tasks", s.auth(s.handleXuiTaskList))
	mux.HandleFunc("GET /api/xui/tasks/{id}", s.auth(s.handleXuiTask))

	// Web 终端（需在设置里开启，且进入时二次验证密码）
	mux.HandleFunc("GET /api/terminal", s.auth(s.handleTerminalStatus))
	mux.HandleFunc("POST /api/terminal/ticket", s.auth(s.handleTerminalTicket))
	mux.HandleFunc("GET /api/terminal/ws", s.handleTerminalWS)

	mux.HandleFunc("GET /api/health", s.handleHealth)

	return s.trackActivity(s.logMiddleware(s.csrfMiddleware(mux)))
}

// trackActivity 记录请求进出，用于空闲退出判断
func (s *Server) trackActivity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&s.inflight, 1)
		s.lastActive.Store(time.Now().UnixNano())
		defer func() {
			s.lastActive.Store(time.Now().UnixNano())
			atomic.AddInt64(&s.inflight, -1)
		}()
		next.ServeHTTP(w, r)
	})
}

// IdleFor 返回已空闲时长；有请求在处理或有终端会话时返回 0
func (s *Server) IdleFor() time.Duration {
	if atomic.LoadInt64(&s.inflight) > 0 {
		return 0
	}
	// WebSocket 终端是长连接，虽然 handler 未返回时 inflight 已经 > 0，
	// 这里再兜一层，避免任何时序缝隙导致终端被"空闲退出"掐断。
	if s.term != nil && s.term.Active() > 0 {
		return 0
	}
	last := s.lastActive.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "界面文件缺失", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/jobs" {
			log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Hijack 必须透传，否则 WebSocket 升级拿不到底层连接
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("底层 ResponseWriter 不支持 hijack")
	}
	return h.Hijack()
}

// Flush 透传给需要流式输出的场景
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// csrfMiddleware 所有写操作必须带自定义头，配合 SameSite=Lax 抵御 CSRF
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-Requested-With") != "certpilot" {
				writeErr(w, 403, "缺少请求头")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- 会话 ----------

const cookieName = "cp_session"

func (s *Server) secret() []byte {
	st := s.getSet()
	sec := st.SessionSecret
	if sec == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		sec = hex.EncodeToString(b)
		st.SessionSecret = sec
		_ = s.setSet(st)
	}
	return []byte(sec)
}

func (s *Server) makeToken(exp time.Time) string {
	payload := strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, s.secret())
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) validToken(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, s.secret())
	mac.Write([]byte(parts[0]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(parts[1]))
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return s.validToken(c.Value)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeErr(w, 401, "未登录")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	st := s.getSet()
	writeJSON(w, 200, map[string]any{
		"needSetup": st.AdminPasswordHash == "",
		"authed":    s.authed(r),
		"version":   s.version,
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	st := s.getSet()
	if st.AdminPasswordHash != "" {
		writeErr(w, 400, "已初始化，请直接登录")
		return
	}
	var req struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Password) < 8 {
		writeErr(w, 400, "密码至少 8 位")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	st.AdminPasswordHash = string(hash)
	if req.Email != "" {
		st.ACMEEmail = req.Email
	}
	if err := s.setSet(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.setCookie(w, r)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	st := s.getSet()
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if st.AdminPasswordHash == "" {
		writeErr(w, 400, "尚未初始化")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(st.AdminPasswordHash), []byte(req.Password)) != nil {
		time.Sleep(400 * time.Millisecond)
		writeErr(w, 401, "密码错误")
		return
	}
	s.setCookie(w, r)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(12 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.makeToken(exp),
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	st := s.getSet()
	if bcrypt.CompareHashAndPassword([]byte(st.AdminPasswordHash), []byte(req.Old)) != nil {
		writeErr(w, 400, "原密码错误")
		return
	}
	if len(req.New) < 8 {
		writeErr(w, 400, "新密码至少 8 位")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
	st.AdminPasswordHash = string(hash)
	if err := s.setSet(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "version": s.version})
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, fmt.Sprintf("请求格式错误: %v", err))
		return false
	}
	return true
}
