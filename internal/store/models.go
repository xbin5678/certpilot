package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Status 证书状态
const (
	StatusPending  = "pending" // 从未签发
	StatusIssuing  = "issuing" // 正在签发/续期
	StatusValid    = "valid"
	StatusExpiring = "expiring" // 进入续期窗口
	StatusExpired  = "expired"
	StatusError    = "error"
	StatusRevoked  = "revoked"
)

// ChallengeType 验证方式
const (
	ChallengeDNS        = "dns-01"             // 自动 DNS（API）
	ChallengeDNSManual  = "dns-01-manual"      // 手动 DNS（人工加 TXT）
	ChallengeWebroot    = "http-01-webroot"    // 复用已有 80 上的 Web 服务
	ChallengeStandalone = "http-01-standalone" // 独占 80
	ChallengeTLSALPN    = "tls-alpn-01"        // 独占 443（与 Xray 冲突）
)

// Cert 一张证书的完整定义与状态
type Cert struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"` // 第一个为主域名
	CA      string   `json:"ca"`
	KeyType string   `json:"keyType"`

	Challenge      string            `json:"challenge"`
	Webroot        string            `json:"webroot,omitempty"`
	ChallengePort  int               `json:"challengePort,omitempty"`
	DNSProvider    string            `json:"dnsProvider,omitempty"`
	DNSCredentials map[string]string `json:"dnsCredentials,omitempty"`

	AutoRenew       bool `json:"autoRenew"`
	RenewBeforeDays int  `json:"renewBeforeDays"`

	DeployCertPath string `json:"deployCertPath,omitempty"`
	DeployKeyPath  string `json:"deployKeyPath,omitempty"`
	DeployCmd      string `json:"deployCmd,omitempty"`

	Status        string `json:"status"`
	NotBefore     string `json:"notBefore,omitempty"`
	NotAfter      string `json:"notAfter,omitempty"`
	Serial        string `json:"serial,omitempty"`
	LastError     string `json:"lastError,omitempty"`
	LastIssuedAt  string `json:"lastIssuedAt,omitempty"`
	LastAttemptAt string `json:"lastAttemptAt,omitempty"`
	FailCount     int    `json:"failCount"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// PrimaryDomain 返回主域名
func (c *Cert) PrimaryDomain() string {
	if len(c.Domains) == 0 {
		return ""
	}
	return c.Domains[0]
}

// DaysLeft 距离到期的天数，未签发返回 -1
func (c *Cert) DaysLeft() int {
	if c.NotAfter == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, c.NotAfter)
	if err != nil {
		return -1
	}
	return int(time.Until(t).Hours() / 24)
}

// NeedsRenew 是否进入续期窗口。
// 短周期证书（如 Let's Encrypt 的 6 天 IP 证书）不能套用 30 天窗口，
// 否则每次签发完立刻又满足条件，会陷入无限续期。这里按有效期长度的 1/3 封顶。
func (c *Cert) NeedsRenew(now time.Time) bool {
	if c.NotAfter == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, c.NotAfter)
	if err != nil {
		return true
	}
	window := c.RenewBeforeDays
	if window <= 0 {
		window = 30
	}
	if nb, err := time.Parse(time.RFC3339, c.NotBefore); err == nil {
		if lifetime := t.Sub(nb); lifetime > 0 {
			if maxWindow := int(lifetime.Hours() / 24 / 3); maxWindow > 0 && window > maxWindow {
				window = maxWindow
			}
		}
	}
	return now.AddDate(0, 0, window).After(t)
}

// RefreshStatus 依据到期时间刷新展示状态（不落库）
func (c *Cert) RefreshStatus(now time.Time) {
	if c.Status == StatusIssuing || c.Status == StatusPending || c.Status == StatusError || c.Status == StatusRevoked {
		return
	}
	if c.NotAfter == "" {
		c.Status = StatusPending
		return
	}
	t, err := time.Parse(time.RFC3339, c.NotAfter)
	if err != nil {
		c.Status = StatusError
		return
	}
	window := c.RenewBeforeDays
	if window <= 0 {
		window = 30
	}
	if nb, err := time.Parse(time.RFC3339, c.NotBefore); err == nil {
		if lifetime := t.Sub(nb); lifetime > 0 {
			if maxWindow := int(lifetime.Hours() / 24 / 3); maxWindow > 0 && window > maxWindow {
				window = maxWindow
			}
		}
	}
	switch {
	case now.After(t):
		c.Status = StatusExpired
	case now.AddDate(0, 0, window).After(t):
		c.Status = StatusExpiring
	default:
		c.Status = StatusValid
	}
}

// Account 某个 CA 的 ACME 账号（含账号私钥）
type Account struct {
	CA           string `json:"ca"`
	Email        string `json:"email"`
	KeyPEM       string `json:"keyPem"`
	Registration string `json:"registration"`
	UpdatedAt    string `json:"updatedAt"`
}

// Event 操作日志
type Event struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	CertID  string `json:"certId"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// EABCred 某个 CA 的外部账号绑定凭据
type EABCred struct {
	KID  string `json:"kid"`
	HMAC string `json:"hmac"`
}

// Settings 全局设置（KV 落库）
type Settings struct {
	AdminPasswordHash string             `json:"adminPasswordHash"`
	Listen            string             `json:"listen"`
	ACMEEmail         string             `json:"acmeEmail"`
	DefaultCA         string             `json:"defaultCa"`
	DefaultKeyType    string             `json:"defaultKeyType"`
	DefaultRenewDays  int                `json:"defaultRenewDays"`
	Compat3XUI        string             `json:"compat3xui"` // auto | on | off
	CompatCertDir     string             `json:"compatCertDir"`
	WebhookURL        string             `json:"webhookUrl"`
	TelegramToken     string             `json:"telegramToken"`
	TelegramChatID    string             `json:"telegramChatId"`
	NotifyOnRenew     bool               `json:"notifyOnRenew"`
	NotifyOnError     bool               `json:"notifyOnError"`
	SessionSecret     string             `json:"sessionSecret"`
	EAB               map[string]EABCred `json:"eab,omitempty"`

	// Web 终端（默认关闭，属高危功能，需显式开启）
	TerminalEnabled     bool   `json:"terminalEnabled"`
	TerminalShell       string `json:"terminalShell"`
	TerminalIdleMinutes int    `json:"terminalIdleMinutes"`
}

// DefaultSettings 出厂默认值
func DefaultSettings() Settings {
	return Settings{
		Listen:           ":8443",
		DefaultCA:        "letsencrypt",
		DefaultKeyType:   "ec256",
		DefaultRenewDays: 30,
		Compat3XUI:       "auto",
		CompatCertDir:    "/root/cert",
		NotifyOnRenew:    true,
		NotifyOnError:    true,

		TerminalEnabled:     false,
		TerminalShell:       "/bin/bash",
		TerminalIdleMinutes: 15,
	}
}

// NewID 生成短 ID
func NewID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("150405.000")))
	}
	return hex.EncodeToString(b)
}

// EncodeStrings / DecodeStrings 用于把 []string 存进 TEXT 列
func EncodeStrings(v []string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func DecodeStrings(s string) []string {
	var v []string
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func EncodeMap(m map[string]string) string {
	if m == nil {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func DecodeMap(s string) map[string]string {
	m := map[string]string{}
	_ = json.Unmarshal([]byte(s), &m)
	return m
}
