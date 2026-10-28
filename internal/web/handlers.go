package web

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"certpilot/internal/acme"
	"certpilot/internal/deploy"
	"certpilot/internal/store"
)

// ---------- 概览 ----------

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	certs, err := s.st.ListCerts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	now := time.Now()
	stats := map[string]int{}
	expiringSoon := 0
	for _, c := range certs {
		c.RefreshStatus(now)
		stats[c.Status]++
		if d := c.DaysLeft(); d >= 0 && d <= 30 {
			expiringSoon++
		}
	}
	writeJSON(w, 200, map[string]any{
		"version":      s.version,
		"certs":        certs,
		"stats":        stats,
		"total":        len(certs),
		"expiringSoon": expiringSoon,
		"compat":       s.det.Get(),
		"jobs":         s.mgr.Jobs().List(8),
		"serverTime":   now.Format(time.RFC3339),
	})
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.st.ListCerts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	now := time.Now()
	for _, c := range certs {
		c.RefreshStatus(now)
	}
	writeJSON(w, 200, certs)
}

// ---------- 证书 CRUD ----------

type certPayload struct {
	Name            string            `json:"name"`
	Domains         []string          `json:"domains"`
	CA              string            `json:"ca"`
	KeyType         string            `json:"keyType"`
	Challenge       string            `json:"challenge"`
	Webroot         string            `json:"webroot"`
	ChallengePort   int               `json:"challengePort"`
	DNSProvider     string            `json:"dnsProvider"`
	DNSCredentials  map[string]string `json:"dnsCredentials"`
	AutoRenew       *bool             `json:"autoRenew"`
	RenewBeforeDays int               `json:"renewBeforeDays"`
	DeployCertPath  string            `json:"deployCertPath"`
	DeployKeyPath   string            `json:"deployKeyPath"`
	DeployCmd       string            `json:"deployCmd"`
	IssueNow        bool              `json:"issueNow"`
}

func normalizeDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		for _, d := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == ';'
		}) {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if strings.ContainsAny(d, "/\\@ ") {
				return nil, fmt.Errorf("域名格式非法: %s", d)
			}
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("请至少填写一个域名")
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("单张证书域名数量过多（上限 100）")
	}
	return out, nil
}

func (s *Server) buildCert(p *certPayload, base *store.Cert) (*store.Cert, error) {
	st := s.getSet()
	domains, err := normalizeDomains(p.Domains)
	if err != nil {
		return nil, err
	}
	c := base
	if c == nil {
		c = &store.Cert{ID: store.NewID()}
	}
	c.Domains = domains
	c.Name = strings.TrimSpace(p.Name)
	if c.Name == "" {
		c.Name = domains[0]
	}
	c.CA = p.CA
	if c.CA == "" {
		c.CA = st.DefaultCA
	}
	if _, ok := acme.GetCA(c.CA); !ok {
		return nil, fmt.Errorf("不支持的 CA: %s", c.CA)
	}
	c.KeyType = p.KeyType
	if c.KeyType == "" {
		c.KeyType = st.DefaultKeyType
	}
	c.Challenge = p.Challenge
	if c.Challenge == "" {
		c.Challenge = store.ChallengeDNS
	}
	switch c.Challenge {
	case store.ChallengeDNS, store.ChallengeDNSManual, store.ChallengeWebroot,
		store.ChallengeStandalone, store.ChallengeTLSALPN:
	default:
		return nil, fmt.Errorf("不支持的验证方式: %s", c.Challenge)
	}
	c.Webroot = strings.TrimSpace(p.Webroot)
	c.ChallengePort = p.ChallengePort
	c.DNSProvider = p.DNSProvider
	c.DNSCredentials = p.DNSCredentials
	if c.DNSCredentials == nil {
		c.DNSCredentials = map[string]string{}
	}
	if p.AutoRenew != nil {
		c.AutoRenew = *p.AutoRenew
	} else if c.CreatedAt == "" {
		c.AutoRenew = true
	}
	c.RenewBeforeDays = p.RenewBeforeDays
	if c.RenewBeforeDays <= 0 {
		c.RenewBeforeDays = st.DefaultRenewDays
	}
	// IP 证书是 6 天短周期，默认提前 2 天续期
	for _, d := range c.Domains {
		if net.ParseIP(d) != nil && p.RenewBeforeDays <= 0 {
			c.RenewBeforeDays = 2
			break
		}
	}
	if c.RenewBeforeDays < 1 {
		c.RenewBeforeDays = 30
	}
	c.DeployCertPath = strings.TrimSpace(p.DeployCertPath)
	c.DeployKeyPath = strings.TrimSpace(p.DeployKeyPath)
	c.DeployCmd = strings.TrimSpace(p.DeployCmd)
	if c.Status == "" {
		c.Status = store.StatusPending
	}
	return c, nil
}

func (s *Server) handleCreateCert(w http.ResponseWriter, r *http.Request) {
	var p certPayload
	if !readJSON(w, r, &p) {
		return
	}
	c, err := s.buildCert(&p, nil)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.st.PutCert(c); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.st.AddEvent(c.ID, "info", "创建证书配置: "+strings.Join(c.Domains, ", "))

	var jobID string
	if p.IssueNow {
		job, err := s.mgr.IssueAsync(c, "issue")
		if err != nil {
			writeJSON(w, 200, map[string]any{"cert": c, "warning": err.Error()})
			return
		}
		jobID = job.ID
	}
	writeJSON(w, 200, map[string]any{"cert": c, "jobId": jobID})
}

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	c, err := s.st.GetCert(r.PathValue("id"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if c == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	c.RefreshStatus(time.Now())
	writeJSON(w, 200, c)
}

func (s *Server) handleUpdateCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur, err := s.st.GetCert(id)
	if err != nil || cur == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	var p certPayload
	if !readJSON(w, r, &p) {
		return
	}
	// 未提供的字段沿用原值
	if len(p.Domains) == 0 {
		p.Domains = cur.Domains
	}
	if p.CA == "" {
		p.CA = cur.CA
	}
	if p.KeyType == "" {
		p.KeyType = cur.KeyType
	}
	if p.Challenge == "" {
		p.Challenge = cur.Challenge
	}
	if p.AutoRenew == nil {
		v := cur.AutoRenew
		p.AutoRenew = &v
	}
	if p.RenewBeforeDays == 0 {
		p.RenewBeforeDays = cur.RenewBeforeDays
	}
	if p.DNSProvider == "" {
		p.DNSProvider = cur.DNSProvider
	}
	if p.DNSCredentials == nil {
		p.DNSCredentials = cur.DNSCredentials
	}
	if p.Webroot == "" {
		p.Webroot = cur.Webroot
	}
	if p.ChallengePort == 0 {
		p.ChallengePort = cur.ChallengePort
	}
	if p.DeployCertPath == "" {
		p.DeployCertPath = cur.DeployCertPath
	}
	if p.DeployKeyPath == "" {
		p.DeployKeyPath = cur.DeployKeyPath
	}
	if p.DeployCmd == "" {
		p.DeployCmd = cur.DeployCmd
	}

	c, err := s.buildCert(&p, cur)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.st.PutCert(c); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, _ := s.st.GetCert(id)
	if c == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	if j := s.mgr.Jobs().Running(id); j != nil {
		writeErr(w, 400, "该证书正在执行任务，请稍后再删")
		return
	}
	if err := s.st.DeleteCert(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_ = os.RemoveAll(s.mgr.CertDir(id))
	s.st.AddEvent("", "warn", "删除证书: "+strings.Join(c.Domains, ", "))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	s.startJob(w, r, "issue")
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	s.startJob(w, r, "renew")
}

func (s *Server) startJob(w http.ResponseWriter, r *http.Request, action string) {
	c, err := s.st.GetCert(r.PathValue("id"))
	if err != nil || c == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	job, err := s.mgr.IssueAsync(c, action)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"jobId": job.ID})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	c, err := s.st.GetCert(r.PathValue("id"))
	if err != nil || c == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	if j := s.mgr.Jobs().Running(c.ID); j != nil {
		writeErr(w, 409, "该证书正在执行任务")
		return
	}
	job := s.mgr.Jobs().Create(c.ID, "revoke")
	go func() {
		if err := s.mgr.Revoke(r.Context(), c, job); err != nil {
			job.Finish(acme.JobError, err.Error())
		} else {
			job.Finish(acme.JobSuccess, "证书已吊销")
		}
	}()
	writeJSON(w, 200, map[string]any{"jobId": job.ID})
}

// ---------- 文件下载与检查 ----------

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	c, err := s.st.GetCert(r.PathValue("id"))
	if err != nil || c == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	name := r.URL.Query().Get("file")
	allowed := map[string]string{
		"fullchain": "fullchain.pem",
		"privkey":   "privkey.pem",
		"cert":      "cert.pem",
		"chain":     "chain.pem",
	}
	file, ok := allowed[name]
	if !ok {
		writeErr(w, 400, "不支持的文件类型")
		return
	}
	path := filepath.Join(s.mgr.CertDir(c.ID), file)
	b, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, 404, "文件不存在，请先签发")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s-%s"`, c.PrimaryDomain(), file))
	_, _ = w.Write(b)
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	c, err := s.st.GetCert(r.PathValue("id"))
	if err != nil || c == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	f, err := s.mgr.LoadFiles(c.ID)
	if err != nil {
		writeErr(w, 404, "尚未签发")
		return
	}
	leaf, err := acme.ParseLeaf(f.FullChain)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var chain []map[string]string
	rest := f.Chain
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cc, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		chain = append(chain, map[string]string{
			"subject":  cc.Subject.String(),
			"issuer":   cc.Issuer.String(),
			"notAfter": cc.NotAfter.Format(time.RFC3339),
		})
	}
	writeJSON(w, 200, map[string]any{
		"subject":   leaf.Subject.String(),
		"issuer":    leaf.Issuer.String(),
		"dnsNames":  leaf.DNSNames,
		"notBefore": leaf.NotBefore.Format(time.RFC3339),
		"notAfter":  leaf.NotAfter.Format(time.RFC3339),
		"daysLeft":  int(time.Until(leaf.NotAfter).Hours() / 24),
		"serial":    leaf.SerialNumber.Text(16),
		"keyType":   leaf.PublicKeyAlgorithm.String(),
		"chain":     chain,
	})
}

// ---------- 证书路径 ----------

type certPathView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Domains      []string `json:"domains"`
	Primary      string   `json:"primary"`
	CertPath     string   `json:"certPath"`
	KeyPath      string   `json:"keyPath"`
	InternalCert string   `json:"internalCert"`
	InternalKey  string   `json:"internalKey"`
	CertExists   bool     `json:"certExists"`
	KeyExists    bool     `json:"keyExists"`
	IsDeployed   bool     `json:"isDeployed"`
	Status       string   `json:"status"`
	NotAfter     string   `json:"notAfter"`
	XuiCommand   string   `json:"xuiCommand"`
	XuiPanelCmd  string   `json:"xuiPanelCmd"`
}

// handlePaths 汇总每张证书的实际文件路径，方便直接复制到 3x-ui
func (s *Server) handlePaths(w http.ResponseWriter, r *http.Request) {
	certs, err := s.st.ListCerts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]certPathView, 0, len(certs))
	for _, c := range certs {
		c.RefreshStatus(time.Now())
		domain := c.PrimaryDomain()
		internalCert := filepath.Join(s.mgr.CertDir(c.ID), "fullchain.pem")
		internalKey := filepath.Join(s.mgr.CertDir(c.ID), "privkey.pem")

		certPath := deploy.Resolve(c.DeployCertPath, domain)
		keyPath := deploy.Resolve(c.DeployKeyPath, domain)
		deployed := certPath != "" || keyPath != ""
		if certPath == "" {
			certPath = internalCert
		}
		if keyPath == "" {
			keyPath = internalKey
		}

		v := certPathView{
			ID: c.ID, Name: c.Name, Domains: c.Domains, Primary: domain,
			CertPath: certPath, KeyPath: keyPath,
			InternalCert: internalCert, InternalKey: internalKey,
			IsDeployed: deployed, Status: c.Status, NotAfter: c.NotAfter,
			XuiCommand:  fmt.Sprintf("x-ui cert -webCert %s -webCertKey %s", certPath, keyPath),
			XuiPanelCmd: fmt.Sprintf("x-ui cert -webCert %s -webCertKey %s && x-ui restart", certPath, keyPath),
		}
		if fi, err := os.Stat(certPath); err == nil && !fi.IsDir() {
			v.CertExists = true
		}
		if fi, err := os.Stat(keyPath); err == nil && !fi.IsDir() {
			v.KeyExists = true
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

// handleDeployNow 把当前证书立即写入部署路径并执行重载命令
func (s *Server) handleDeployNow(w http.ResponseWriter, r *http.Request) {
	c, err := s.st.GetCert(r.PathValue("id"))
	if err != nil || c == nil {
		writeErr(w, 404, "证书不存在")
		return
	}
	f, err := s.mgr.LoadFiles(c.ID)
	if err != nil {
		writeErr(w, 400, "这张证书还没有签发过，无法部署")
		return
	}
	if c.DeployCertPath == "" && c.DeployKeyPath == "" && c.DeployCmd == "" {
		writeErr(w, 400, "请先设置证书路径、私钥路径或重载命令")
		return
	}
	res, err := deploy.Apply(c, f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.st.AddEvent(c.ID, "info", "手动部署到: "+strings.Join(res.Paths, ", "))
	writeJSON(w, 200, res)
}

// ---------- 任务 ----------

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.mgr.Jobs().List(50))
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	j := s.mgr.Jobs().Get(r.PathValue("id"))
	if j == nil {
		writeErr(w, 404, "任务不存在或已过期")
		return
	}
	writeJSON(w, 200, j.Snapshot())
}

// ---------- 设置 ----------

type settingsView struct {
	ACMEEmail        string                   `json:"acmeEmail"`
	DefaultCA        string                   `json:"defaultCa"`
	DefaultKeyType   string                   `json:"defaultKeyType"`
	DefaultRenewDays int                      `json:"defaultRenewDays"`
	Compat3XUI       string                   `json:"compat3xui"`
	CompatCertDir    string                   `json:"compatCertDir"`
	WebhookURL       string                   `json:"webhookUrl"`
	TelegramChatID   string                   `json:"telegramChatId"`
	HasTelegramToken bool                     `json:"hasTelegramToken"`
	NotifyOnRenew    bool                     `json:"notifyOnRenew"`
	NotifyOnError    bool                     `json:"notifyOnError"`
	EAB              map[string]store.EABCred `json:"eab"`
	Listen           string                   `json:"listen"`

	TerminalEnabled     bool   `json:"terminalEnabled"`
	TerminalShell       string `json:"terminalShell"`
	TerminalIdleMinutes int    `json:"terminalIdleMinutes"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	st := s.getSet()
	writeJSON(w, 200, settingsView{
		ACMEEmail:        st.ACMEEmail,
		DefaultCA:        st.DefaultCA,
		DefaultKeyType:   st.DefaultKeyType,
		DefaultRenewDays: st.DefaultRenewDays,
		Compat3XUI:       st.Compat3XUI,
		CompatCertDir:    st.CompatCertDir,
		WebhookURL:       st.WebhookURL,
		TelegramChatID:   st.TelegramChatID,
		HasTelegramToken: st.TelegramToken != "",
		NotifyOnRenew:    st.NotifyOnRenew,
		NotifyOnError:    st.NotifyOnError,
		EAB:              st.EAB,
		Listen:           st.Listen,

		TerminalEnabled:     st.TerminalEnabled,
		TerminalShell:       st.TerminalShell,
		TerminalIdleMinutes: st.TerminalIdleMinutes,
	})
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ACMEEmail        *string                  `json:"acmeEmail"`
		DefaultCA        *string                  `json:"defaultCa"`
		DefaultKeyType   *string                  `json:"defaultKeyType"`
		DefaultRenewDays *int                     `json:"defaultRenewDays"`
		Compat3XUI       *string                  `json:"compat3xui"`
		CompatCertDir    *string                  `json:"compatCertDir"`
		WebhookURL       *string                  `json:"webhookUrl"`
		TelegramToken    *string                  `json:"telegramToken"`
		TelegramChatID   *string                  `json:"telegramChatId"`
		NotifyOnRenew    *bool                    `json:"notifyOnRenew"`
		NotifyOnError    *bool                    `json:"notifyOnError"`
		EAB              map[string]store.EABCred `json:"eab"`

		TerminalEnabled     *bool   `json:"terminalEnabled"`
		TerminalShell       *string `json:"terminalShell"`
		TerminalIdleMinutes *int    `json:"terminalIdleMinutes"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	s.settingsMu <- struct{}{}
	defer func() { <-s.settingsMu }()

	st := s.getSet()
	if req.ACMEEmail != nil {
		st.ACMEEmail = strings.TrimSpace(*req.ACMEEmail)
	}
	if req.DefaultCA != nil {
		st.DefaultCA = *req.DefaultCA
	}
	if req.DefaultKeyType != nil {
		st.DefaultKeyType = *req.DefaultKeyType
	}
	if req.DefaultRenewDays != nil {
		st.DefaultRenewDays = *req.DefaultRenewDays
	}
	if req.Compat3XUI != nil {
		st.Compat3XUI = *req.Compat3XUI
	}
	if req.CompatCertDir != nil {
		st.CompatCertDir = *req.CompatCertDir
	}
	if req.WebhookURL != nil {
		st.WebhookURL = strings.TrimSpace(*req.WebhookURL)
	}
	if req.TelegramToken != nil && *req.TelegramToken != "" {
		st.TelegramToken = strings.TrimSpace(*req.TelegramToken)
	}
	if req.TelegramChatID != nil {
		st.TelegramChatID = strings.TrimSpace(*req.TelegramChatID)
	}
	if req.NotifyOnRenew != nil {
		st.NotifyOnRenew = *req.NotifyOnRenew
	}
	if req.NotifyOnError != nil {
		st.NotifyOnError = *req.NotifyOnError
	}
	if req.EAB != nil {
		st.EAB = req.EAB
	}
	if req.TerminalEnabled != nil {
		st.TerminalEnabled = *req.TerminalEnabled
	}
	if req.TerminalShell != nil {
		sh := strings.TrimSpace(*req.TerminalShell)
		if sh != "" && !strings.HasPrefix(sh, "/") {
			writeErr(w, 400, "shell 必须是绝对路径")
			return
		}
		st.TerminalShell = sh
	}
	if req.TerminalIdleMinutes != nil {
		m := *req.TerminalIdleMinutes
		if m < 1 {
			m = 1
		}
		if m > 720 {
			m = 720
		}
		st.TerminalIdleMinutes = m
	}
	if err := s.setSet(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.st.AddEvent("", "info", "更新全局设置")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- 元数据 ----------

func (s *Server) handleCAs(w http.ResponseWriter, r *http.Request) {
	st := s.getSet()
	type caView struct {
		acme.CA
		EABConfigured bool `json:"eabConfigured"`
	}
	out := make([]caView, 0, len(acme.CAs))
	for _, c := range acme.CAs {
		_, ok := st.EAB[c.ID]
		out = append(out, caView{CA: c, EABConfigured: ok})
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleDNSProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, acme.ListDNSProviders())
}

func (s *Server) handleCompat(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.det.Refresh())
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	ev, err := s.st.ListEvents(limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].ID > ev[j].ID })
	writeJSON(w, 200, ev)
}

func (s *Server) handleCheckNow(w http.ResponseWriter, r *http.Request) {
	n, err := s.sched.RunOnce()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"triggered": n})
}
