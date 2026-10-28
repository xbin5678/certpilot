// Package terminal 提供网页版终端：浏览器 ⇄ WebSocket ⇄ 本地 PTY。
//
// 安全模型（这是本模块最重要的部分）：
//   - 默认关闭，必须在「设置」里显式开启，关闭时所有入口返回 403
//   - 进入终端需要重新输入管理密码，换取的是一次性票据（60 秒、用完即废），
//     票据通过 URL 参数传给 WebSocket —— 因为浏览器 WebSocket 无法带自定义头
//   - 同时只允许一个会话，避免多人抢占同一 shell
//   - 会话空闲超时自动断开
//   - 只记录会话生命周期（开始/结束/时长/流量），**不记录任何输入内容**，
//     否则 sudo 密码、命令行里的密钥都会落进日志
//
// 进程本身以 root 运行，所以终端里直接就是 root shell —— 界面必须明确告知。
package terminal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

var (
	ErrDisabled    = errors.New("Web 终端未启用")
	ErrUnsupported = errors.New("当前平台不支持 Web 终端")
	ErrBusy        = errors.New("已有终端会话在运行，请先关闭")
	ErrBadTicket   = errors.New("终端票据无效或已过期")
)

const ticketTTL = 60 * time.Second

// Session 一次终端会话的元信息
type Session struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	Remote    string    `json:"remote"`

	lastActive atomic.Int64
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

func (s *Session) touch()      { s.lastActive.Store(time.Now().UnixNano()) }
func (s *Session) idleSince() time.Duration {
	return time.Since(time.Unix(0, s.lastActive.Load()))
}

// View 会话快照
type View struct {
	ID       string `json:"id"`
	Started  string `json:"startedAt"`
	Remote   string `json:"remote"`
	IdleSecs int    `json:"idleSecs"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`
}

func (s *Session) View() View {
	return View{
		ID:       s.ID,
		Started:  s.StartedAt.Format(time.RFC3339),
		Remote:   s.Remote,
		IdleSecs: int(s.idleSince().Seconds()),
		BytesIn:  s.bytesIn.Load(),
		BytesOut: s.bytesOut.Load(),
	}
}

// Manager 会话与票据管理
type Manager struct {
	enabledFn func() bool
	shellFn   func() string
	idleFn    func() time.Duration

	mu       sync.Mutex
	tickets  map[string]time.Time
	sessions map[string]*Session
}

func NewManager(enabled func() bool, shell func() string, idle func() time.Duration) *Manager {
	return &Manager{
		enabledFn: enabled,
		shellFn:   shell,
		idleFn:    idle,
		tickets:   map[string]time.Time{},
		sessions:  map[string]*Session{},
	}
}

func (m *Manager) Enabled() bool {
	return m.enabledFn != nil && m.enabledFn()
}

func (m *Manager) idleTimeout() time.Duration {
	if m.idleFn == nil {
		return 15 * time.Minute
	}
	d := m.idleFn()
	if d <= 0 {
		d = 15 * time.Minute
	}
	return d
}

// IssueTicket 生成一次性票据，调用前必须已通过密码校验
func (m *Manager) IssueTicket() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tk := hex.EncodeToString(b)
	m.mu.Lock()
	// 顺手清理过期票据，避免长期累积
	now := time.Now()
	for k, exp := range m.tickets {
		if now.After(exp) {
			delete(m.tickets, k)
		}
	}
	m.tickets[tk] = now.Add(ticketTTL)
	m.mu.Unlock()
	return tk
}

// ConsumeTicket 校验并作废票据
func (m *Manager) ConsumeTicket(tk string) bool {
	if tk == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.tickets[tk]
	if !ok {
		return false
	}
	delete(m.tickets, tk)
	return time.Now().Before(exp)
}

// Active 当前活跃会话数，用于空闲退出判断
func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Sessions 列出活跃会话
func (m *Manager) Sessions() []View {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]View, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s.View())
	}
	return out
}

func (m *Manager) addSession(remote string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) > 0 {
		return nil, ErrBusy
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	s := &Session{
		ID:        hex.EncodeToString(b),
		StartedAt: time.Now(),
		Remote:    remote,
	}
	s.touch()
	m.sessions[s.ID] = s
	return s, nil
}

func (m *Manager) removeSession(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// ServeWS 升级为 WebSocket 并桥接 PTY。调用方需先校验票据。
func (m *Manager) ServeWS(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if !m.Enabled() {
		http.Error(w, ErrDisabled.Error(), http.StatusForbidden)
		return ErrDisabled
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return err
	}
	defer c.CloseNow()

	remote := r.Header.Get("X-Forwarded-For")
	if remote == "" {
		remote = r.RemoteAddr
	}

	sess, err := m.addSession(remote)
	if err != nil {
		_ = c.Close(websocket.StatusPolicyViolation, err.Error())
		return err
	}
	defer m.removeSession(sess.ID)

	shell := "/bin/bash"
	if m.shellFn != nil {
		if s := m.shellFn(); s != "" {
			shell = s
		}
	}

	ptmx, proc, err := startPTY(shell, 120, 32)
	if err != nil {
		_ = c.Close(websocket.StatusInternalError, err.Error())
		return err
	}
	defer func() {
		_ = ptmx.Close()
		if proc != nil && proc.Process != nil {
			_ = proc.Process.Kill()
		}
		if proc != nil {
			_ = proc.Wait()
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 空闲看门狗
	go func() {
		iv := m.idleTimeout()
		tk := time.NewTicker(20 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				if sess.idleSince() > iv {
					_ = c.Close(websocket.StatusGoingAway, "空闲超时，终端已断开")
					cancel()
					return
				}
			}
		}
	}()

	// 浏览器 → PTY
	go func() {
		defer cancel()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			sess.touch()
			if typ == websocket.MessageText {
				var msg struct {
					Type string `json:"type"`
					Cols uint16 `json:"cols"`
					Rows uint16 `json:"rows"`
				}
				if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 {
					_ = resizePTY(ptmx, msg.Cols, msg.Rows)
					continue
				}
			}
			if len(data) == 0 {
				continue
			}
			if _, err := ptmx.Write(data); err != nil {
				return
			}
			sess.bytesIn.Add(int64(len(data)))
		}
	}()

	// PTY → 浏览器
	buf := make([]byte, 32*1024)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			sess.touch()
			sess.bytesOut.Add(int64(n))
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			werr := c.Write(wctx, websocket.MessageBinary, buf[:n])
			wcancel()
			if werr != nil {
				return nil
			}
		}
		if err != nil {
			// PTY 关闭（用户 exit 或 shell 退出）
			_ = c.Close(websocket.StatusNormalClosure, "终端会话已结束")
			return nil
		}
	}
}
