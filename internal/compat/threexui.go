package compat

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"certpilot/internal/store"
)

// PortState 端口占用情况
type PortState struct {
	Port  int    `json:"port"`
	InUse bool   `json:"inUse"`
	Owner string `json:"owner"`
}

// Status 3x-ui 兼容性探测结果
type Status struct {
	Mode          string    `json:"mode"` // auto | on | off
	Installed     bool      `json:"installed"`
	Evidence      []string  `json:"evidence"`
	BinaryPath    string    `json:"binaryPath"`
	ServiceActive bool      `json:"serviceActive"`
	PanelCert     string    `json:"panelCert"`
	PanelKey      string    `json:"panelKey"`
	Port80        PortState `json:"port80"`
	Port443       PortState `json:"port443"`
	XrayOn443     bool      `json:"xrayOn443"`
	XrayOn80      bool      `json:"xrayOn80"`
	Advice        []string  `json:"advice"`
	CheckedAt     string    `json:"checkedAt"`
}

// Detector 周期性探测 3x-ui 是否在位。3x-ui 可能在证书程序之后才安装，
// 因此这里不做任何启动期强依赖，全部运行时探测。
type Detector struct {
	mu     sync.RWMutex
	st     Status
	last   time.Time
	modeFn func() string
}

func NewDetector(modeFn func() string) *Detector {
	d := &Detector{modeFn: modeFn}
	d.st = Status{Mode: "auto", Advice: []string{"尚未探测"}}
	return d
}

// Start 只做一次初始探测。
// 之前是每 45 秒轮询一次，待机时会白白唤醒进程；
// 现在改为按需刷新（Get 发现数据超过 20 秒才重新探测），空闲时零开销。
func (d *Detector) Start(ctx context.Context) {
	d.Refresh()
}

// Get 返回当前状态，超过 20 秒则重新探测
func (d *Detector) Get() Status {
	d.mu.RLock()
	st, last := d.st, d.last
	d.mu.RUnlock()
	if time.Since(last) > 20*time.Second {
		return d.Refresh()
	}
	st.Mode = d.mode()
	return st
}

func (d *Detector) mode() string {
	if d.modeFn == nil {
		return "auto"
	}
	m := d.modeFn()
	if m == "" {
		return "auto"
	}
	return m
}

// Refresh 立即探测一次
func (d *Detector) Refresh() Status {
	st := Status{Mode: d.mode(), CheckedAt: time.Now().Format(time.RFC3339)}
	st.Port80 = CheckPort(80)
	st.Port443 = CheckPort(443)
	st.XrayOn443 = strings.Contains(strings.ToLower(st.Port443.Owner), "xray")
	st.XrayOn80 = strings.Contains(strings.ToLower(st.Port80.Owner), "xray")

	if runtime.GOOS == "linux" {
		for _, p := range []string{"/usr/local/x-ui/x-ui", "/usr/bin/x-ui", "/usr/local/bin/x-ui"} {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				st.Installed = true
				st.BinaryPath = p
				st.Evidence = append(st.Evidence, "可执行文件: "+p)
				break
			}
		}
		for _, p := range []string{"/etc/x-ui/x-ui.db", "/etc/x-ui/x-ui.db-wal"} {
			if _, err := os.Stat(p); err == nil {
				st.Installed = true
				st.Evidence = append(st.Evidence, "配置数据库: "+p)
				break
			}
		}
		for _, p := range []string{"/etc/systemd/system/x-ui.service", "/usr/lib/systemd/system/x-ui.service"} {
			if _, err := os.Stat(p); err == nil {
				st.Installed = true
				st.Evidence = append(st.Evidence, "systemd 单元: "+p)
				break
			}
		}
		if st.Installed {
			if out, err := runCmd(3*time.Second, "systemctl", "is-active", "x-ui"); err == nil {
				st.ServiceActive = strings.TrimSpace(out) == "active"
			}
			st.PanelCert, st.PanelKey = probePanelCert(st.BinaryPath)
		}
	}

	st.Advice = buildAdvice(st)
	d.mu.Lock()
	d.st = st
	d.last = time.Now()
	d.mu.Unlock()
	return st
}

func probePanelCert(binary string) (cert, key string) {
	if binary == "" {
		return "", ""
	}
	out, err := runCmd(4*time.Second, binary, "setting", "-getCert", "true")
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "cert:"):
				cert = strings.TrimSpace(strings.TrimPrefix(line, "cert:"))
			case strings.HasPrefix(line, "key:"):
				key = strings.TrimSpace(strings.TrimPrefix(line, "key:"))
			}
		}
	}
	if cert != "" && key != "" {
		return cert, key
	}

	// 兜底：只读打开 3x-ui 的数据库读取设置（绝不写入）
	db, err := store.OpenReadOnly("/etc/x-ui/x-ui.db")
	if err != nil {
		return cert, key
	}
	defer db.Close()
	rows, err := db.DB().Query(`SELECT key, value FROM settings WHERE key IN ('webCertFile','webKeyFile')`)
	if err != nil {
		return cert, key
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			switch k {
			case "webCertFile":
				cert = v
			case "webKeyFile":
				key = v
			}
		}
	}
	return cert, key
}

func buildAdvice(st Status) []string {
	var a []string
	if !st.Port80.InUse {
		a = append(a, "80 端口空闲：可直接使用「HTTP-01 独立监听」模式，签发时临时占用几秒。")
	} else {
		owner := st.Port80.Owner
		if owner == "" {
			owner = "其它进程"
		}
		lower := strings.ToLower(owner)
		switch {
		case strings.Contains(lower, "nginx"), strings.Contains(lower, "caddy"), strings.Contains(lower, "apache"), strings.Contains(lower, "httpd"):
			a = append(a, fmt.Sprintf("80 被 %s 占用：改用「HTTP-01 Webroot」模式，把 webroot 指向该 Web 服务的站点根目录，零中断、零冲突。", owner))
		case strings.Contains(lower, "xray"):
			a = append(a, "80 被 xray 占用：请使用「DNS-01」或「手动 DNS」，不要试图抢 80 端口。")
		default:
			a = append(a, fmt.Sprintf("80 被 %s 占用：建议使用「DNS-01」或「手动 DNS」模式。", owner))
		}
	}
	if st.Port443.InUse {
		if st.XrayOn443 {
			a = append(a, "443 被 xray 占用：禁止使用 TLS-ALPN-01 验证（它必须独占 443）。HTTP-01 和 DNS-01 不受影响。")
		} else {
			a = append(a, "443 已被占用：不要使用 TLS-ALPN-01 验证。")
		}
	}
	if st.Installed {
		a = append(a, "检测到 3x-ui：部署目标可填 /root/cert/<域名>/，重载命令填 x-ui restart（会短暂断开面板，xray 入站不断流）。")
		if st.PanelCert != "" {
			a = append(a, "当前面板证书路径："+st.PanelCert)
		}
	} else if st.Mode == "on" {
		a = append(a, "兼容模式已开启，但本机未检测到 3x-ui。程序会持续探测，安装后自动生效，无需重启。")
	}
	return a
}

// CheckPort 尝试监听以判断端口是否被占用
func CheckPort(port int) PortState {
	st := PortState{Port: port}
	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err == nil {
		_ = ln.Close()
		return st
	}
	st.InUse = true
	st.Owner = portOwner(port)
	return st
}

func portOwner(port int) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	out, err := runCmd(3*time.Second, "ss", "-lntpH")
	if err != nil {
		out, err = runCmd(3*time.Second, "ss", "-lntp")
		if err != nil {
			return ""
		}
	}
	return parsePortOwner(out, port)
}

// parsePortOwner 从 ss 的输出里挑出监听指定端口的进程名。
// 单独拆出来是为了能拿真实输出做单元测试——之前这段逻辑写错了，
// 标记取成 `users:((`（少了结尾的引号），于是 rest 以引号开头、
// end 恒为 0，`end > 0` 永远不成立，任何端口都被判成「未知进程」。
func parsePortOwner(out string, port int) string {
	suffix := fmt.Sprintf(":%d", port)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if !strings.HasSuffix(fields[3], suffix) {
			continue
		}
		const marker = `users:(("`
		if idx := strings.Index(line, marker); idx >= 0 {
			rest := line[idx+len(marker):]
			if end := strings.Index(rest, `"`); end > 0 {
				return rest[:end]
			}
		}
		return "未知进程"
	}
	return ""
}

// EnsurePortFree 在签发前确认端口可用，并给出可执行的处理建议
func EnsurePortFree(port int) error {
	st := CheckPort(port)
	if !st.InUse {
		return nil
	}
	owner := st.Owner
	if owner == "" {
		owner = "未知进程"
	}
	hint := "请改用「DNS-01」或「手动 DNS」模式，它们完全不需要端口。"
	if port == 443 {
		hint = "TLS-ALPN-01 必须独占 443，而 xray/nginx 通常会占用它。请改用「DNS-01」或「HTTP-01 Webroot」。"
	} else if port == 80 {
		if strings.Contains(strings.ToLower(owner), "nginx") || strings.Contains(strings.ToLower(owner), "caddy") {
			hint = "80 上是 Web 服务，请改用「HTTP-01 Webroot」模式（webroot 指向它的站点目录），无需停服务。"
		}
	}
	return fmt.Errorf("端口 %d 已被 %s 占用，无法绑定。%s", port, owner, hint)
}

// CanBindLowPort 判断当前进程能否绑定 1024 以下端口
func CanBindLowPort() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return os.Geteuid() == 0
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// DefaultCertDir 3x-ui 的证书存放目录
func DefaultCertDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), "cert")
	}
	return "/root/cert"
}
