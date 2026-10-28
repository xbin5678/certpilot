// Package xui 负责在本机一键安装 3x-ui。
//
// 实现策略：不重写安装逻辑，而是调用官方 install.sh 的非交互模式
// （XUI_NONINTERACTIVE=1 + XUI_* 环境变量）。官方脚本已经处理了架构识别、
// 校验和验证、systemd 单元与硬化、fail2ban、数据库迁移等大量细节，
// 自己复刻只会随上游版本漂移。这里只做三件事：
//   1. 安装前体检（root、systemd、已装检测、网络）
//   2. 用受控参数驱动官方脚本，并把输出流式上报
//   3. 安装后验收（二进制、服务、端口）
package xui

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"certpilot/internal/task"
)

const (
	// 官方安装脚本
	scriptURL = "https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh"
	// 官方仓库
	repoURL = "https://github.com/MHSanaei/3x-ui"

	binaryPath  = "/usr/local/x-ui/x-ui"
	dataDir     = "/etc/x-ui"
	serviceName = "x-ui"
)

// InstallOptions 安装参数
type InstallOptions struct {
	Version  string `json:"version"`  // 留空取最新
	Port     int    `json:"port"`     // 面板端口
	Username string `json:"username"` // 面板用户名
	Password string `json:"password"` // 面板密码
	BasePath string `json:"basePath"` // 面板路径前缀，留空由官方脚本随机生成
	SSLMode  string `json:"sslMode"`  // none | ip | domain
	Domain   string `json:"domain"`   // SSLMode=domain 时必填
	Email    string `json:"email"`    // ACME 邮箱
	ServerIP string `json:"serverIp"` // 用于拼接访问地址
	Force    bool   `json:"force"`    // 已安装时是否继续（升级/重装）
}

// State 本机 3x-ui 当前状态
type State struct {
	Installed     bool   `json:"installed"`
	BinaryPath    string `json:"binaryPath"`
	ServiceActive bool   `json:"serviceActive"`
	Version       string `json:"version"`
	PanelPort     int    `json:"panelPort"`
	BasePath      string `json:"basePath"`
	PanelCert     string `json:"panelCert"`
	DataDir       string `json:"dataDir"`
}

// Detect 读取本机 3x-ui 状态。不做缓存，调用方自行控制频率。
func Detect() State {
	st := State{BinaryPath: "", DataDir: dataDir}
	if runtime.GOOS != "linux" {
		return st
	}
	for _, p := range []string{binaryPath, "/usr/bin/x-ui", "/usr/local/bin/x-ui"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			st.Installed = true
			st.BinaryPath = p
			break
		}
	}
	if _, err := os.Stat(dataDir + "/x-ui.db"); err == nil {
		st.Installed = true
	}
	if !st.Installed {
		return st
	}
	if out, err := runQuick(3*time.Second, "systemctl", "is-active", serviceName); err == nil {
		st.ServiceActive = strings.TrimSpace(out) == "active"
	}
	// x-ui setting -show true 会打印当前端口、路径、证书等信息
	if out, err := runQuick(4*time.Second, st.BinaryPath, "setting", "-show", "true"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "port":
				fmt.Sscanf(v, "%d", &st.PanelPort)
			case "webBasePath":
				st.BasePath = strings.Trim(v, "/")
			}
		}
	}
	// 3x-ui 的版本号只能用 -v 取；不带参数运行它会真的去启动服务，
	// 而 `version` 不是合法子命令（会打印一大坨 usage）。
	if out, err := runQuick(4*time.Second, st.BinaryPath, "-v"); err == nil {
		st.Version = sanitizeVersion(out)
	}
	return st
}

var verRe = regexp.MustCompile(`^v?\d+(\.\d+){1,3}([-+.\w]*)?$`)

// sanitizeVersion 只接受形如 3.6.0 / v3.6.0 的字符串。
// 二进制返回 usage、报错或者空内容时一律留空，避免把几百行帮助文本塞进界面。
func sanitizeVersion(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 0 || len(s) > 32 || !verRe.MatchString(s) {
		return ""
	}
	return s
}

// DefaultOptions 给出安全默认值。密码每次随机，避免出现"默认弱口令"。
func DefaultOptions() InstallOptions {
	return InstallOptions{
		Port:     2053,
		Username: "admin",
		Password: RandomPassword(),
		SSLMode:  "none",
	}
}

// Validate 参数校验
func (o *InstallOptions) Validate() error {
	// 重装已有实例时端口可以留 0：官方脚本检测到已有配置后会沿用原端口，
	// 不会读 XUI_PANEL_PORT。
	if o.Port == 0 && o.Force {
		// 沿用现有端口
	} else if o.Port < 1 || o.Port > 65535 {
		return fmt.Errorf("面板端口不合法")
	}
	// 重装已有实例时账号密码可以留空：官方脚本检测到已存在非默认凭据后
	// 会沿用原来的账号密码，不会覆盖。留空即表示「沿用现有」。
	if o.Username != "" || o.Password != "" {
		if len(o.Username) < 3 {
			return fmt.Errorf("用户名至少 3 位")
		}
		if len(o.Password) < 8 {
			return fmt.Errorf("密码至少 8 位")
		}
	}
	switch o.SSLMode {
	case "", "none":
		o.SSLMode = "none"
	case "ip":
		// 官方脚本自动探测公网 IP
	case "domain":
		if o.Domain == "" {
			return fmt.Errorf("选择域名证书时必须填写域名")
		}
	default:
		return fmt.Errorf("未知的 SSL 模式: %s", o.SSLMode)
	}
	// 面板端口不能撞上 certpilot 自己的端口或常见服务端口
	if o.Port == 80 || o.Port == 443 {
		return fmt.Errorf("面板端口不要使用 80/443，会和证书验证或 xray 入站冲突")
	}
	return nil
}

// RandomPassword 生成 16 位随机密码
func RandomPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "CertPilot" + fmt.Sprint(time.Now().UnixNano()%1e8)
	}
	return hex.EncodeToString(b)[:16]
}

// Installer 执行安装
type Installer struct {
	HTTP *http.Client
}

func NewInstaller() *Installer {
	return &Installer{HTTP: &http.Client{Timeout: 90 * time.Second}}
}

// Run 执行安装，全程把进度写入 t
func (in *Installer) Run(ctx context.Context, opts InstallOptions, t *task.Task) error {
	steps := []string{
		"环境检查",
		"下载官方安装脚本",
		"执行安装（下载二进制、写入 systemd）",
		"验收服务状态",
	}
	idx := make([]int, len(steps))
	for i, s := range steps {
		idx[i] = t.AddStep(s)
	}

	// 1. 环境检查
	t.BeginStep(idx[0])
	if runtime.GOOS != "linux" {
		return fail(t, idx[0], "仅支持 Linux")
	}
	if os.Geteuid() != 0 {
		return fail(t, idx[0], "需要 root 权限运行（systemd 单元需要写入 /etc/systemd/system）")
	}
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return fail(t, idx[0], "未检测到 systemd，无法以服务方式安装 3x-ui")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		return fail(t, idx[0], "系统缺少 bash")
	}
	cur := Detect()
	if cur.Installed && !opts.Force {
		t.EndStep(idx[0], "已安装")
		return fail(t, idx[0], fmt.Sprintf("已安装 3x-ui（%s），如需升级或重装请勾选「覆盖安装」", orDash(cur.Version)))
	}
	if cur.Installed {
		t.Log("检测到已安装的 3x-ui（%s），将以覆盖方式重新安装，配置数据库会保留", orDash(cur.Version))
	}
	// 端口检查只对新装有意义：重装时目标端口正被现有的 3x-ui 自己监听，
	// 脚本会先停服务再绑定，此时判定"被占用"是误报。
	if !cur.Installed && opts.Port > 0 {
		if st := checkPortFree(opts.Port); st != "" {
			return fail(t, idx[0], fmt.Sprintf("端口 %d 已被 %s 占用，请换一个端口", opts.Port, st))
		}
	}
	t.EndStep(idx[0], "通过")

	// 2. 下载脚本
	t.BeginStep(idx[1])
	script, err := in.fetchScript(ctx, t)
	if err != nil {
		return fail(t, idx[1], err.Error())
	}
	defer os.Remove(script)
	t.EndStep(idx[1], script)

	// 3. 执行
	t.BeginStep(idx[2])
	if err := in.runScript(ctx, script, opts, t); err != nil {
		return fail(t, idx[2], err.Error())
	}
	t.EndStep(idx[2], "安装脚本执行完成")

	// 4. 验收
	t.BeginStep(idx[3])
	after := Detect()
	if !after.Installed {
		return fail(t, idx[3], "脚本执行完成但未找到 x-ui 可执行文件，请查看日志")
	}
	// 服务刚起来时可能还在启动，给最多 15 秒
	deadline := time.Now().Add(15 * time.Second)
	for !after.ServiceActive && time.Now().Before(deadline) {
		time.Sleep(time.Second)
		after = Detect()
	}
	if !after.ServiceActive {
		t.Log("服务未在 15 秒内变为 active，尝试查看状态")
		if out, err := runQuick(5*time.Second, "systemctl", "status", serviceName, "--no-pager", "-l"); err == nil {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				t.Log("  %s", line)
			}
		}
		return fail(t, idx[3], "服务未启动，请查看上方日志")
	}

	port := after.PanelPort
	if port == 0 {
		port = opts.Port
	}
	basePath := after.BasePath
	host := opts.ServerIP
	if host == "" {
		host = detectPublicIP(ctx, in.HTTP)
	}
	scheme := "http"
	// 面板已经有证书（重装时会沿用原有证书配置）就走 https，
	// 否则拼出来的地址会让用户以为面板是明文
	if opts.SSLMode != "none" || after.PanelCert != "" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	if basePath != "" {
		url += "/" + basePath
	}
	t.SetResult("url", url)
	t.SetResult("port", port)
	t.SetResult("username", opts.Username)
	t.SetResult("password", opts.Password)
	t.SetResult("version", after.Version)
	t.SetResult("basePath", basePath)
	t.SetResult("scheme", scheme)
	t.EndStep(idx[3], fmt.Sprintf("服务运行中，版本 %s", orDash(after.Version)))

	t.Finish(task.Success, fmt.Sprintf("3x-ui 安装完成，面板 %s", url))
	return nil
}

func fail(t *task.Task, step int, msg string) error {
	t.FailStep(step, msg)
	t.Finish(task.Error, msg)
	return fmt.Errorf("%s", msg)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "未知"
	}
	return s
}

// fetchScript 下载官方安装脚本
func (in *Installer) fetchScript(ctx context.Context, t *task.Task) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := in.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载安装脚本失败（检查网络/代理）: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("下载安装脚本失败: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("读取安装脚本失败: %v", err)
	}
	if len(body) < 4096 || !strings.Contains(string(body), "install_x-ui") {
		return "", fmt.Errorf("安装脚本内容异常（长度 %d），可能被中间人劫持或 GitHub 不可达", len(body))
	}
	p := filepath.Join(os.TempDir(), fmt.Sprintf("certpilot-xui-%d.sh", time.Now().UnixNano()))
	if err := os.WriteFile(p, body, 0o700); err != nil {
		return "", fmt.Errorf("写入临时脚本失败: %v", err)
	}
	t.Log("已下载官方 install.sh（%d 字节）", len(body))
	return p, nil
}

// runScript 以非交互模式执行官方脚本
func (in *Installer) runScript(ctx context.Context, script string, opts InstallOptions, t *task.Task) error {
	args := []string{script}
	if v := strings.TrimSpace(opts.Version); v != "" {
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		args = append(args, v)
		t.Log("目标版本: %s", v)
	} else {
		t.Log("目标版本: 最新稳定版")
	}

	cmd := exec.CommandContext(ctx, "bash", args...)
	cmd.Dir = os.TempDir()
	cmd.Env = append(os.Environ(),
		"XUI_NONINTERACTIVE=1",
		"XUI_SSL_MODE="+opts.SSLMode,
		"XUI_ACME_EMAIL="+opts.Email,
		"XUI_SERVER_IP="+opts.ServerIP,
		"XUI_DB_TYPE=sqlite",
		"DEBIAN_FRONTEND=noninteractive",
	)
	if opts.Port > 0 {
		cmd.Env = append(cmd.Env, "XUI_PANEL_PORT="+fmt.Sprint(opts.Port))
	}
	// 留空则不传，让官方脚本沿用数据库里已有的凭据，避免重装把密码改掉
	if opts.Username != "" {
		cmd.Env = append(cmd.Env, "XUI_USERNAME="+opts.Username)
	}
	if opts.Password != "" {
		cmd.Env = append(cmd.Env, "XUI_PASSWORD="+opts.Password)
	}
	if opts.BasePath != "" {
		cmd.Env = append(cmd.Env, "XUI_WEB_BASE_PATH="+opts.BasePath)
	}
	if opts.SSLMode == "domain" {
		cmd.Env = append(cmd.Env, "XUI_DOMAIN="+opts.Domain)
	}
	setProcessGroup(cmd)

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64<<10), 2<<20)
		for sc.Scan() {
			line := cleanANSI(sc.Text())
			if strings.TrimSpace(line) == "" {
				continue
			}
			t.Log("%s", line)
		}
	}()

	if err := cmd.Start(); err != nil {
		pw.Close()
		return fmt.Errorf("启动安装脚本失败: %v", err)
	}
	waitErr := cmd.Wait()
	pw.Close()
	<-done

	if waitErr != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("安装超时或已取消")
		}
		return fmt.Errorf("安装脚本执行失败: %v", waitErr)
	}
	return nil
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][A-Z0-9]`)

func cleanANSI(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// checkPortFree 返回占用者，空字符串表示空闲
func checkPortFree(port int) string {
	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err == nil {
		_ = ln.Close()
		return ""
	}
	out, _ := runQuick(3*time.Second, "ss", "-lntp")
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, fmt.Sprintf(":%d ", port)) && !strings.HasSuffix(strings.TrimSpace(line), fmt.Sprintf(":%d", port)) {
			continue
		}
		if i := strings.Index(line, "users:(("); i >= 0 {
			rest := line[i+len("users:(("):]
			if j := strings.Index(rest, "\""); j > 0 {
				return rest[:j]
			}
		}
	}
	return "其它进程"
}

// detectPublicIP 尽力获取公网地址，仅用于拼展示用的访问地址
func detectPublicIP(ctx context.Context, c *http.Client) string {
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return "127.0.0.1"
}

func runQuick(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
