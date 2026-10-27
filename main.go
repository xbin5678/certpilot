package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"certpilot/internal/acme"
	"certpilot/internal/compat"
	"certpilot/internal/notify"
	"certpilot/internal/scheduler"
	"certpilot/internal/store"
	"certpilot/internal/web"
)

// Version 版本号，发布时由 CI 通过 -X main.Version 注入
var Version = "1.1.2-dev"

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "doctor":
		cmdDoctor(os.Args[2:])
	case "issue":
		cmdIssue(os.Args[2:])
	case "renew":
		cmdRenew(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("certpilot %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`certpilot - 多域名多 CA 证书申请与自动续期

用法:
  certpilot serve   [-listen :8443] [-data DIR]     启动 Web 管理后台
  certpilot doctor  [-data DIR]                     体检：端口占用 / 3x-ui 兼容性
  certpilot issue   -domain a.com,b.com [选项]      命令行签发一张证书
  certpilot renew   [-data DIR] [-dry-run]          检查并续期所有到期证书后退出
  certpilot list    [-data DIR]                     列出所有证书
  certpilot version                                 显示版本

issue 选项:
  -ca letsencrypt|letsencrypt_staging|zerossl|buypass|gts
  -challenge dns-01|dns-01-manual|http-01-webroot|http-01-standalone|tls-alpn-01
  -dns-provider cloudflare|alidns|dnspod|huaweicloud
  -dns-cred KEY=VALUE           可重复，例如 -dns-cred CLOUDFLARE_DNS_API_TOKEN=xxx
  -webroot /var/www/html        http-01-webroot 的站点根目录
  -email you@example.com        ACME 账号邮箱
  -deploy-cert /path/fullchain.pem
  -deploy-key  /path/privkey.pem
  -deploy-cmd  "x-ui restart"
  -renew-days 30
`)
}

func defaultDataDir() string {
	if v := os.Getenv("CERTPILOT_DATA"); v != "" {
		return v
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return "/etc/certpilot"
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, "data")
}

// ---------- 设置缓存 ----------

type settingsStore struct {
	mu  sync.RWMutex
	cur store.Settings
	st  *store.Store
}

func newSettingsStore(st *store.Store) (*settingsStore, error) {
	s, err := st.LoadSettings()
	if err != nil {
		return nil, err
	}
	return &settingsStore{cur: s, st: st}, nil
}

func (s *settingsStore) Get() store.Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

func (s *settingsStore) Set(v store.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.SaveSettings(v); err != nil {
		return err
	}
	s.cur = v
	return nil
}

// ---------- serve ----------

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir(), "数据目录")
	listen := fs.String("listen", "", "监听地址，例如 :8443 或 127.0.0.1:8443")
	tlsCert := fs.String("tls-cert", "", "面板 HTTPS 证书路径，多张用逗号分隔")
	tlsKey := fs.String("tls-key", "", "面板 HTTPS 私钥路径，顺序与证书一一对应")
	idleTimeout := fs.Duration("idle-timeout", 0, "空闲多久后退出（0=常驻）。配合 systemd socket 实现按需启动")
	withScheduler := fs.Bool("scheduler", true, "进程内是否运行续期调度器（按需模式建议关掉，改用 renew 定时器）")
	_ = fs.Parse(args)

	if err := os.MkdirAll(*dataDir, 0o750); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "certpilot.db"))
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	ss, err := newSettingsStore(st)
	if err != nil {
		log.Fatalf("读取设置失败: %v", err)
	}
	// -listen 只覆盖本次运行，不写回数据库，避免一次性调试改掉服务端口
	addr := ss.Get().Listen
	if addr == "" {
		addr = ":8443"
	}
	if *listen != "" {
		addr = *listen
	}

	det := compat.NewDetector(func() string { return ss.Get().Compat3XUI })
	nt := notify.New(ss.Get)
	mgr := acme.NewManager(st, *dataDir, det, nt, ss.Get)
	sched := scheduler.New(st, mgr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	det.Start(ctx)
	if *withScheduler {
		sched.Start(ctx)
	}

	srv := web.New(st, mgr, det, sched, Version, ss.Get, ss.Set)

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	pairs, err := web.ParseCertPairs(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("证书参数错误: %v", err)
	}
	useTLS := len(pairs) > 0

	// 优先使用 systemd socket 激活传入的监听套接字（此时进程无需自己 bind 端口）
	ln := systemdListener()
	activated := ln != nil
	if ln == nil {
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			if isAddrInUse(err) {
				log.Printf("端口 %s 已被占用。如果使用按需模式，请执行：systemctl restart certpilot.socket", addr)
				return
			}
			log.Fatalf("监听失败: %v", err)
		}
	}

	if useTLS {
		httpSrv.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: web.MultiCertReloader(pairs),
		}
		ln = tls.NewListener(ln, httpSrv.TLSConfig)
	}

	banner(addr, *dataDir, ss.Get(), useTLS, len(pairs), activated, *idleTimeout)

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.Serve(ln) }()

	idleDone := make(chan struct{})
	if *idleTimeout > 0 {
		go watchIdle(srv, mgr, *idleTimeout, idleDone)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case <-stop:
		log.Println("收到退出信号")
	case <-idleDone:
		log.Printf("已空闲 %s，进程退出，下次访问时由 systemd 自动拉起", *idleTimeout)
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务异常退出: %v", err)
		}
		return
	}

	shutdownCtx, c2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer c2()
	_ = httpSrv.Shutdown(shutdownCtx)
}

// systemdListener 读取 systemd 通过 LISTEN_FDS 传入的监听套接字
func systemdListener() net.Listener {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil
	}
	f := os.NewFile(uintptr(3), "systemd-listen")
	if f == nil {
		return nil
	}
	ln, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil
	}
	return ln
}

func isAddrInUse(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage") ||
		strings.Contains(msg, "address in use")
}

// watchIdle 空闲超时后通知主流程退出
func watchIdle(srv *web.Server, mgr *acme.Manager, timeout time.Duration, done chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		if mgr.Jobs().AnyRunning() > 0 {
			continue
		}
		if srv.IdleFor() >= timeout {
			close(done)
			return
		}
	}
}

func banner(addr, dataDir string, s store.Settings, useTLS bool, certCount int, activated bool, idle time.Duration) {
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	fmt.Println()
	fmt.Println("  certpilot " + Version + "  证书管理后台")
	fmt.Println("  ----------------------------------------")
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	fmt.Printf("  访问地址 : %s://%s\n", scheme, host)
	if useTLS {
		fmt.Printf("  TLS 证书 : 已加载 %d 张（按 SNI 自动选择）\n", certCount)
	}
	switch {
	case activated && idle > 0:
		fmt.Printf("  运行模式 : 按需启动（空闲 %s 后退出）\n", idle)
	case activated:
		fmt.Println("  运行模式 : socket 激活（常驻）")
	case idle > 0:
		fmt.Printf("  运行模式 : 常驻（空闲 %s 后退出）\n", idle)
	}
	fmt.Printf("  数据目录 : %s\n", dataDir)
	if s.AdminPasswordHash == "" {
		fmt.Println("  首次使用 : 打开页面设置管理密码")
	}
	st := compat.NewDetector(nil).Refresh()
	if st.Installed {
		fmt.Println("  3x-ui    : 已检测到（兼容模式生效中）")
	} else {
		fmt.Println("  3x-ui    : 未检测到（安装后会自动识别，无需重启）")
	}
	fmt.Printf("  80 端口  : %s\n", portLine(st.Port80.InUse, st.Port80.Owner))
	fmt.Printf("  443 端口 : %s\n", portLine(st.Port443.InUse, st.Port443.Owner))
	fmt.Println()
}

func portLine(inUse bool, owner string) string {
	if !inUse {
		return "空闲"
	}
	if owner == "" {
		return "被占用"
	}
	return "被 " + owner + " 占用"
}

// ---------- doctor ----------

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir(), "数据目录")
	_ = fs.Parse(args)

	fmt.Println("certpilot doctor")
	fmt.Println("================")
	fmt.Printf("版本       : %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("数据目录   : %s\n", *dataDir)
	fmt.Printf("低端口权限 : %v\n", compat.CanBindLowPort())

	det := compat.NewDetector(nil)
	st := det.Refresh()

	fmt.Println()
	fmt.Println("端口")
	fmt.Printf("  80  : %s\n", portLine(st.Port80.InUse, st.Port80.Owner))
	fmt.Printf("  443 : %s\n", portLine(st.Port443.InUse, st.Port443.Owner))

	fmt.Println()
	fmt.Println("3x-ui")
	if st.Installed {
		fmt.Println("  状态 : 已安装")
		for _, e := range st.Evidence {
			fmt.Println("  证据 :", e)
		}
		fmt.Printf("  服务 : %v\n", st.ServiceActive)
		if st.PanelCert != "" {
			fmt.Printf("  面板证书 : %s\n", st.PanelCert)
			fmt.Printf("  面板私钥 : %s\n", st.PanelKey)
		}
	} else {
		fmt.Println("  状态 : 未检测到（不影响使用；之后安装会自动识别）")
	}

	fmt.Println()
	fmt.Println("建议")
	for _, a := range st.Advice {
		fmt.Println("  -", a)
	}

	fmt.Println()
	fmt.Println("验证方式可用性")
	fmt.Println("  DNS-01            : 始终可用（不占用端口，推荐）")
	fmt.Println("  手动 DNS          : 始终可用（人工加 TXT，通用兜底）")
	if st.Port80.InUse {
		fmt.Printf("  HTTP-01 Webroot   : 可用（需 80 上已有 Web 服务；当前 80 被 %s 占用）\n", orUnknown(st.Port80.Owner))
	} else {
		fmt.Println("  HTTP-01 Webroot   : 可用（但 80 空闲，直接用独立监听更省事）")
	}
	if st.Port80.InUse {
		fmt.Println("  HTTP-01 独立监听  : 不可用（80 已被占用）")
	} else {
		fmt.Println("  HTTP-01 独立监听  : 可用（签发时临时占用 80 数秒）")
	}
	if st.Port443.InUse {
		fmt.Printf("  TLS-ALPN-01       : 不可用（443 被 %s 占用）\n", orUnknown(st.Port443.Owner))
	} else {
		fmt.Println("  TLS-ALPN-01       : 可用（但不推荐，需独占 443）")
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "未知进程"
	}
	return s
}

// ---------- issue ----------

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func cmdIssue(args []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir(), "数据目录")
	domains := fs.String("domain", "", "域名，多个用逗号分隔")
	name := fs.String("name", "", "备注名")
	caID := fs.String("ca", "letsencrypt", "CA")
	challenge := fs.String("challenge", "dns-01", "验证方式")
	dnsProvider := fs.String("dns-provider", "", "DNS 服务商")
	webroot := fs.String("webroot", "", "Webroot 目录")
	email := fs.String("email", "", "ACME 邮箱")
	deployCert := fs.String("deploy-cert", "", "证书部署路径")
	deployKey := fs.String("deploy-key", "", "私钥部署路径")
	deployCmd := fs.String("deploy-cmd", "", "部署后执行命令")
	renewDays := fs.Int("renew-days", 30, "提前续期天数")
	var creds multiFlag
	fs.Var(&creds, "dns-cred", "DNS 凭据 KEY=VALUE，可重复")
	_ = fs.Parse(args)

	if *domains == "" {
		log.Fatal("必须指定 -domain")
	}
	if err := os.MkdirAll(*dataDir, 0o750); err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "certpilot.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	ss, err := newSettingsStore(st)
	if err != nil {
		log.Fatal(err)
	}
	if *email != "" {
		s := ss.Get()
		s.ACMEEmail = *email
		_ = ss.Set(s)
	}
	if ss.Get().ACMEEmail == "" {
		log.Fatal("请用 -email 指定 ACME 账号邮箱")
	}

	credMap := map[string]string{}
	for _, c := range creds {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) == 2 {
			credMap[parts[0]] = parts[1]
		}
	}

	list, _ := normalizeDomainList(*domains)
	c := &store.Cert{
		ID:              store.NewID(),
		Name:            *name,
		Domains:         list,
		CA:              *caID,
		KeyType:         "ec256",
		Challenge:       *challenge,
		Webroot:         *webroot,
		DNSProvider:     *dnsProvider,
		DNSCredentials:  credMap,
		AutoRenew:       true,
		RenewBeforeDays: *renewDays,
		DeployCertPath:  *deployCert,
		DeployKeyPath:   *deployKey,
		DeployCmd:       *deployCmd,
		Status:          store.StatusPending,
	}
	if c.Name == "" {
		c.Name = list[0]
	}
	if err := st.PutCert(c); err != nil {
		log.Fatal(err)
	}

	det := compat.NewDetector(func() string { return ss.Get().Compat3XUI })
	nt := notify.New(ss.Get)
	mgr := acme.NewManager(st, *dataDir, det, nt, ss.Get)

	job := mgr.Jobs().Create(c.ID, "issue")
	fmt.Printf("开始签发 %s ...\n", strings.Join(list, ", "))
	if err := mgr.Issue(context.Background(), c, "issue", job); err != nil {
		for _, l := range job.Snapshot().Logs {
			fmt.Println("  ", l)
		}
		log.Fatalf("失败: %v", err)
	}
	for _, l := range job.Snapshot().Logs {
		fmt.Println("  ", l)
	}
	fmt.Println("完成")
}

func normalizeDomainList(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, d := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n'
	}) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有有效域名")
	}
	return out, nil
}

// ---------- renew ----------

// cmdRenew 检查所有到期证书并续期，处理完退出。
// 供 systemd timer 调用，进程活几秒就退出，不占待机内存。
func cmdRenew(args []string) {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir(), "数据目录")
	dryRun := fs.Bool("dry-run", false, "只列出待续期的证书，不执行")
	_ = fs.Parse(args)

	if err := os.MkdirAll(*dataDir, 0o750); err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "certpilot.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	ss, err := newSettingsStore(st)
	if err != nil {
		log.Fatal(err)
	}
	det := compat.NewDetector(func() string { return ss.Get().Compat3XUI })
	nt := notify.New(ss.Get)
	mgr := acme.NewManager(st, *dataDir, det, nt, ss.Get)

	certs, err := st.ListCerts()
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()
	var due []*store.Cert
	for _, c := range certs {
		c.RefreshStatus(now)
		_ = st.PutCert(c)
		if !c.AutoRenew || c.Status == store.StatusRevoked {
			continue
		}
		// 从未签发过的不自动申请，交给用户手动触发
		if c.LastIssuedAt == "" || c.NotAfter == "" {
			continue
		}
		if !c.NeedsRenew(now) {
			continue
		}
		due = append(due, c)
	}

	if len(due) == 0 {
		fmt.Println("没有需要续期的证书")
		return
	}

	failed := 0
	for _, c := range due {
		name := strings.Join(c.Domains, ",")
		if c.Challenge == store.ChallengeDNSManual {
			fmt.Printf("跳过 %s：手动 DNS 模式需要人工添加 TXT 记录，请在面板里操作\n", name)
			continue
		}
		if *dryRun {
			fmt.Printf("待续期: %s（剩余 %d 天）\n", name, c.DaysLeft())
			continue
		}
		job := mgr.Jobs().Create(c.ID, "renew")
		if err := mgr.Issue(context.Background(), c, "renew", job); err != nil {
			job.Finish(acme.JobError, err.Error())
			failed++
			fmt.Printf("✘ %s 续期失败: %v\n", name, err)
		} else {
			job.Finish(acme.JobSuccess, "续期成功")
			fmt.Printf("✔ %s 续期成功，新到期时间 %s\n", name, c.NotAfter)
		}
	}

	if failed > 0 {
		os.Exit(1)
	}
}

// ---------- list ----------

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir(), "数据目录")
	_ = fs.Parse(args)

	st, err := store.Open(filepath.Join(*dataDir, "certpilot.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	certs, err := st.ListCerts()
	if err != nil {
		log.Fatal(err)
	}
	if len(certs) == 0 {
		fmt.Println("还没有证书")
		return
	}
	now := time.Now()
	fmt.Printf("%-12s %-28s %-14s %-10s %-8s %s\n", "ID", "域名", "状态", "到期", "剩余", "CA")
	for _, c := range certs {
		c.RefreshStatus(now)
		days := "-"
		if d := c.DaysLeft(); d >= 0 {
			days = fmt.Sprintf("%d 天", d)
		}
		fmt.Printf("%-12s %-28s %-14s %-10s %-8s %s\n",
			c.ID, truncateStr(strings.Join(c.Domains, ","), 28), c.Status,
			truncateStr(c.NotAfter, 10), days, c.CA)
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
