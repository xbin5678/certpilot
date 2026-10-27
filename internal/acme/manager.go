package acme

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"certpilot/internal/compat"
	"certpilot/internal/deploy"
	"certpilot/internal/notify"
	"certpilot/internal/store"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/webroot"
)

// Manager 证书生命周期管理器
type Manager struct {
	st         *store.Store
	dataDir    string
	jobs       *JobManager
	compat     *compat.Detector
	notifier   *notify.Notifier
	settingsFn func() store.Settings

	locks sync.Map // certID -> *sync.Mutex
}

func NewManager(st *store.Store, dataDir string, det *compat.Detector, nt *notify.Notifier, settingsFn func() store.Settings) *Manager {
	return &Manager{
		st:         st,
		dataDir:    dataDir,
		jobs:       NewJobManager(),
		compat:     det,
		notifier:   nt,
		settingsFn: settingsFn,
	}
}

func (m *Manager) Jobs() *JobManager        { return m.jobs }
func (m *Manager) Compat() *compat.Detector { return m.compat }
func (m *Manager) Store() *store.Store      { return m.st }

func (m *Manager) settings() store.Settings {
	if m.settingsFn == nil {
		return store.DefaultSettings()
	}
	return m.settingsFn()
}

func (m *Manager) certLock(id string) *sync.Mutex {
	v, _ := m.locks.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// CertDir 证书的内部存储目录
func (m *Manager) CertDir(id string) string {
	return filepath.Join(m.dataDir, "certs", id)
}

// LoadFiles 读取已落盘的证书文件
func (m *Manager) LoadFiles(id string) (deploy.Files, error) {
	dir := m.CertDir(id)
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil
		}
		return b
	}
	f := deploy.Files{
		FullChain: read("fullchain.pem"),
		PrivKey:   read("privkey.pem"),
		Cert:      read("cert.pem"),
		Chain:     read("chain.pem"),
	}
	if len(f.FullChain) == 0 || len(f.PrivKey) == 0 {
		return f, fmt.Errorf("尚未签发")
	}
	return f, nil
}

// IssueAsync 启动一个异步任务
func (m *Manager) IssueAsync(c *store.Cert, action string) (*Job, error) {
	if j := m.jobs.Running(c.ID); j != nil {
		return j, fmt.Errorf("该证书已有任务在执行中")
	}
	job := m.jobs.Create(c.ID, action)
	// 拷贝一份，避免和外部修改竞争
	cc := *c
	go func() {
		if err := m.Issue(context.Background(), &cc, action, job); err != nil {
			job.Finish(JobError, err.Error())
		} else {
			job.Finish(JobSuccess, actionText(action)+"成功")
		}
	}()
	return job, nil
}

func actionText(a string) string {
	switch a {
	case "renew":
		return "续期"
	case "revoke":
		return "吊销"
	default:
		return "签发"
	}
}

// Issue 执行签发或续期（同步）
func (m *Manager) Issue(ctx context.Context, c *store.Cert, action string, job *Job) error {
	l := m.certLock(c.ID)
	l.Lock()
	defer l.Unlock()

	now := time.Now()
	c.LastAttemptAt = now.Format(time.RFC3339)
	c.Status = store.StatusIssuing
	_ = m.st.PutCert(c)

	m.st.AddEvent(c.ID, "info", fmt.Sprintf("开始%s: %s", actionText(action), strings.Join(c.Domains, ", ")))
	job.AddLog("目标域名: %s", strings.Join(c.Domains, ", "))
	job.AddLog("验证方式: %s", challengeLabel(c.Challenge))

	// 1. 预检（端口/路径/凭据）
	if err := m.preflight(c, job); err != nil {
		return m.fail(c, job, err)
	}

	// 2. 建立 ACME 客户端（首次会自动注册账号）
	ca, _ := GetCA(c.CA)
	job.AddLog("连接 %s ...", ca.Name)
	timeout := 150 * time.Second
	if c.Challenge == store.ChallengeDNSManual {
		timeout = 25 * time.Minute
	}
	client, err := m.newClient(ClientOptions{
		CAID:              c.CA,
		KeyType:           c.KeyType,
		Timeout:           timeout,
		DisableCommonName: isIPDomain(c),
	})
	if err != nil {
		return m.fail(c, job, err)
	}
	job.AddLog("账号就绪")

	// 3. 配置验证方式
	if err := m.setupChallenge(client, c, job); err != nil {
		return m.fail(c, job, err)
	}

	// 4. 提交订单
	var res *certificate.Resource
	if action == "renew" {
		res, err = m.renew(client, c, job)
	} else {
		res, err = m.obtain(client, c, job)
	}
	if err != nil {
		return m.fail(c, job, err)
	}

	files := deploy.Files{
		FullChain: res.Certificate,
		PrivKey:   res.PrivateKey,
		Chain:     res.IssuerCertificate,
	}
	leaf, err := ParseLeaf(files.FullChain)
	if err != nil {
		return m.fail(c, job, fmt.Errorf("解析签发的证书失败: %w", err))
	}
	files.Cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	if err := deploy.Verify(files); err != nil {
		return m.fail(c, job, err)
	}

	// 5. 落盘到内部目录
	dir := m.CertDir(c.ID)
	if err := deploy.WriteAtomic(filepath.Join(dir, "fullchain.pem"), files.FullChain, 0o644); err != nil {
		return m.fail(c, job, err)
	}
	if err := deploy.WriteAtomic(filepath.Join(dir, "privkey.pem"), files.PrivKey, 0o600); err != nil {
		return m.fail(c, job, err)
	}
	if err := deploy.WriteAtomic(filepath.Join(dir, "cert.pem"), files.Cert, 0o644); err != nil {
		return m.fail(c, job, err)
	}
	if err := deploy.WriteAtomic(filepath.Join(dir, "chain.pem"), files.Chain, 0o644); err != nil {
		return m.fail(c, job, err)
	}
	meta, _ := json.MarshalIndent(map[string]any{
		"certUrl":  res.CertURL,
		"issuedAt": time.Now().Format(time.RFC3339),
		"domains":  c.Domains,
		"ca":       c.CA,
		"notAfter": leaf.NotAfter.Format(time.RFC3339),
		"serial":   leaf.SerialNumber.String(),
		"issuer":   leaf.Issuer.CommonName,
	}, "", "  ")
	_ = deploy.WriteAtomic(filepath.Join(dir, "meta.json"), meta, 0o644)
	job.AddLog("证书已保存到 %s", dir)

	// 6. 外部部署
	if c.DeployCertPath != "" || c.DeployKeyPath != "" || c.DeployCmd != "" {
		job.AddLog("执行部署...")
		r, err := deploy.Apply(c, files)
		if err != nil {
			return m.fail(c, job, err)
		}
		for _, p := range r.Paths {
			job.AddLog("已写入 %s", p)
		}
		if r.Output != "" {
			job.AddLog("重载输出: %s", truncate(r.Output, 300))
		}
	}

	// 7. 更新状态
	c.NotBefore = leaf.NotBefore.Format(time.RFC3339)
	c.NotAfter = leaf.NotAfter.Format(time.RFC3339)
	c.Serial = leaf.SerialNumber.Text(16)
	c.LastIssuedAt = time.Now().Format(time.RFC3339)
	c.LastError = ""
	c.FailCount = 0
	c.Status = store.StatusValid
	c.RefreshStatus(time.Now())
	_ = m.st.PutCert(c)

	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	job.AddLog("完成，有效期至 %s（剩余 %d 天）", leaf.NotAfter.Local().Format("2006-01-02 15:04"), days)
	m.st.AddEvent(c.ID, "success", fmt.Sprintf("%s成功，到期时间 %s",
		actionText(action), leaf.NotAfter.Local().Format("2006-01-02")))

	m.notifier.Notify(
		fmt.Sprintf("证书%s成功: %s", actionText(action), c.PrimaryDomain()),
		fmt.Sprintf("域名: %s\n到期: %s\n剩余: %d 天",
			strings.Join(c.Domains, ", "),
			leaf.NotAfter.Local().Format("2006-01-02 15:04"), days),
		"success")
	return nil
}

func (m *Manager) obtain(client *lego.Client, c *store.Cert, job *Job) (*certificate.Resource, error) {
	job.AddLog("提交订单，等待 CA 验证...")
	req := certificate.ObtainRequest{
		Domains: c.Domains,
		Bundle:  true,
		Profile: profileFor(c),
	}
	if req.Profile != "" {
		job.AddLog("使用 ACME profile: %s", req.Profile)
	}
	res, err := client.Certificate.Obtain(req)
	if err != nil {
		return nil, fmt.Errorf("签发失败: %w", err)
	}
	return res, nil
}

// profileFor IP 证书必须走 Let's Encrypt 的 shortlived profile（约 6 天有效期）
func profileFor(c *store.Cert) string {
	for _, d := range c.Domains {
		if net.ParseIP(d) != nil {
			return "shortlived"
		}
	}
	return ""
}

func isIPDomain(c *store.Cert) bool {
	for _, d := range c.Domains {
		if net.ParseIP(d) != nil {
			return true
		}
	}
	return false
}

func (m *Manager) renew(client *lego.Client, c *store.Cert, job *Job) (*certificate.Resource, error) {
	f, err := m.LoadFiles(c.ID)
	if err != nil || len(f.FullChain) == 0 {
		job.AddLog("没有可续期的旧证书，改为全新签发")
		return m.obtain(client, c, job)
	}
	job.AddLog("基于现有证书发起续期（复用私钥）...")
	res, err := client.Certificate.RenewWithOptions(certificate.Resource{
		Domain:      c.PrimaryDomain(),
		Certificate: f.FullChain,
		PrivateKey:  f.PrivKey,
	}, &certificate.RenewOptions{Bundle: true, Profile: profileFor(c)})
	if err != nil {
		job.AddLog("续期失败（%v），回退为全新签发", err)
		return m.obtain(client, c, job)
	}
	return res, nil
}

// preflight 签发前的本地检查，避免白跑一趟 CA 触发限流
func (m *Manager) preflight(c *store.Cert, job *Job) error {
	if len(c.Domains) == 0 {
		return fmt.Errorf("域名不能为空")
	}
	for _, d := range c.Domains {
		if strings.Contains(d, "/") || strings.Contains(d, " ") || d == "" {
			return fmt.Errorf("域名格式非法: %q", d)
		}
	}

	if isIPDomain(c) && (c.Challenge == store.ChallengeDNS || c.Challenge == store.ChallengeDNSManual) {
		return fmt.Errorf("IP 地址证书不支持 DNS-01 验证（CA 无法为 IP 校验 TXT 记录），请改用「HTTP-01 独立监听」或「TLS-ALPN-01」")
	}

	switch c.Challenge {
	case store.ChallengeStandalone:
		port := c.ChallengePort
		if port == 0 {
			port = 80
		}
		if port < 1024 && !compat.CanBindLowPort() {
			return fmt.Errorf("当前进程没有绑定 %d 端口的权限，请用 root 运行或改用 DNS-01", port)
		}
		job.AddLog("检查端口 %d ...", port)
		if err := compat.EnsurePortFree(port); err != nil {
			return err
		}

	case store.ChallengeTLSALPN:
		if !compat.CanBindLowPort() {
			return fmt.Errorf("TLS-ALPN-01 需要绑定 443，请用 root 运行")
		}
		job.AddLog("检查端口 443 ...")
		if err := compat.EnsurePortFree(443); err != nil {
			return err
		}

	case store.ChallengeWebroot:
		if c.Webroot == "" {
			return fmt.Errorf("Webroot 模式必须填写站点根目录")
		}
		fi, err := os.Stat(c.Webroot)
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("Webroot 目录不存在: %s", c.Webroot)
		}
		chDir := filepath.Join(c.Webroot, ".well-known", "acme-challenge")
		if err := os.MkdirAll(chDir, 0o755); err != nil {
			return fmt.Errorf("无法创建验证目录 %s: %w", chDir, err)
		}
		testFile := filepath.Join(chDir, ".cp-write-test")
		if err := os.WriteFile(testFile, []byte("ok"), 0o644); err != nil {
			return fmt.Errorf("Webroot 目录不可写: %w", err)
		}
		_ = os.Remove(testFile)
		job.AddLog("Webroot 可写: %s", chDir)

	case store.ChallengeDNS:
		if c.DNSProvider == "" {
			return fmt.Errorf("请选择 DNS 服务商")
		}
		job.AddLog("DNS 服务商: %s（不占用任何端口）", c.DNSProvider)

	case store.ChallengeDNSManual:
		job.AddLog("手动 DNS 模式：稍后请把 TXT 记录添加到 DNS 解析商")
	}
	return nil
}

func (m *Manager) setupChallenge(client *lego.Client, c *store.Cert, job *Job) error {
	var (
		p   challenge.Provider
		err error
	)
	switch c.Challenge {
	case store.ChallengeDNS:
		p, err = NewDNSProvider(c.DNSProvider, c.DNSCredentials)
		if err != nil {
			return err
		}
		err = client.Challenge.SetDNS01Provider(p)

	case store.ChallengeDNSManual:
		manual := NewManualDNS(func(recs []TXTRecord) {
			job.SetTXT(recs)
			job.AddLog("已生成 %d 条待添加的 TXT 记录，等待 DNS 生效（最长 20 分钟）", len(recs))
		})
		err = client.Challenge.SetDNS01Provider(manual)

	case store.ChallengeWebroot:
		p, err = webroot.NewHTTPProvider(c.Webroot)
		if err != nil {
			return fmt.Errorf("初始化 Webroot 失败: %w", err)
		}
		err = client.Challenge.SetHTTP01Provider(p)

	case store.ChallengeStandalone:
		port := c.ChallengePort
		if port == 0 {
			port = 80
		}
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", strconv.Itoa(port)))

	case store.ChallengeTLSALPN:
		err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "443"))

	default:
		return fmt.Errorf("未知的验证方式: %s", c.Challenge)
	}
	if err != nil {
		return fmt.Errorf("配置验证方式失败: %w", err)
	}
	return nil
}

// Revoke 吊销证书
func (m *Manager) Revoke(ctx context.Context, c *store.Cert, job *Job) error {
	l := m.certLock(c.ID)
	l.Lock()
	defer l.Unlock()

	f, err := m.LoadFiles(c.ID)
	if err != nil {
		return m.fail(c, job, err)
	}
	job.AddLog("连接 CA 准备吊销...")
	client, err := m.newClient(ClientOptions{CAID: c.CA, KeyType: c.KeyType, Timeout: 90 * time.Second})
	if err != nil {
		return m.fail(c, job, err)
	}
	certPEM := f.Cert
	if len(certPEM) == 0 {
		certPEM = f.FullChain
	}
	if err := client.Certificate.Revoke(certPEM); err != nil {
		return m.fail(c, job, fmt.Errorf("吊销失败: %w", err))
	}
	c.Status = store.StatusRevoked
	_ = m.st.PutCert(c)
	m.st.AddEvent(c.ID, "warn", "证书已吊销")
	job.AddLog("证书已吊销")
	m.notifier.Notify("证书已吊销: "+c.PrimaryDomain(), strings.Join(c.Domains, ", "), "warn")
	return nil
}

func (m *Manager) fail(c *store.Cert, job *Job, err error) error {
	c.Status = store.StatusError
	c.FailCount++
	c.LastError = err.Error()
	_ = m.st.PutCert(c)
	m.st.AddEvent(c.ID, "error", err.Error())
	job.AddLog("失败: %v", err)
	m.notifier.Notify("证书操作失败: "+c.PrimaryDomain(), err.Error(), "error")
	return err
}

// ParseLeaf 解析 PEM 中的第一张证书
func ParseLeaf(pemBytes []byte) (*x509.Certificate, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("未找到证书")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

func challengeLabel(ch string) string {
	switch ch {
	case store.ChallengeDNS:
		return "DNS-01（自动，不占端口）"
	case store.ChallengeDNSManual:
		return "DNS-01（手动添加 TXT）"
	case store.ChallengeWebroot:
		return "HTTP-01 Webroot（复用 80）"
	case store.ChallengeStandalone:
		return "HTTP-01 独立监听（独占 80）"
	case store.ChallengeTLSALPN:
		return "TLS-ALPN-01（独占 443）"
	default:
		return ch
	}
}
