package acme

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CA 一个 ACME 证书颁发机构的定义
type CA struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DirectoryURL string `json:"directoryUrl"`
	RequiresEAB  bool   `json:"requiresEab"`
	EABAuto      bool   `json:"eabAuto"` // 可自动获取 EAB（ZeroSSL）
	Staging      bool   `json:"staging"`
	Website      string `json:"website"`
	Note         string `json:"note"`
	MaxDays      int    `json:"maxDays"`
}

// CAs 内置支持的免费 CA。全部遵循 ACME 协议，验证方式由客户端选择。
var CAs = []CA{
	{
		ID:           "letsencrypt",
		Name:         "Let's Encrypt",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Website:      "https://letsencrypt.org",
		Note:         "最通用，90 天有效期，无需注册即可签发。",
		MaxDays:      90,
	},
	{
		ID:           "letsencrypt_staging",
		Name:         "Let's Encrypt (测试环境)",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		Staging:      true,
		Website:      "https://letsencrypt.org/docs/staging-environment/",
		Note:         "签发的证书不被浏览器信任，但完全不占用生产限流，强烈建议调试时使用。",
		MaxDays:      90,
	},
	{
		ID:           "zerossl",
		Name:         "ZeroSSL",
		DirectoryURL: "https://acme.zerossl.com/v2/DV90",
		RequiresEAB:  true,
		EABAuto:      true,
		Website:      "https://zerossl.com",
		Note:         "90 天有效期，需要 EAB；填了邮箱可自动获取。",
		MaxDays:      90,
	},
	{
		ID:           "buypass",
		Name:         "Buypass Go SSL",
		DirectoryURL: "https://api.buypass.com/acme/directory",
		Website:      "https://www.buypass.com/ssl/products/acme",
		Note:         "180 天有效期，续期频率最低，但 2025 年后已停止新签发（存量可续）。",
		MaxDays:      180,
	},
	{
		ID:           "gts",
		Name:         "Google Trust Services",
		DirectoryURL: "https://dv.acme-v02.api.pki.goog/directory",
		RequiresEAB:  true,
		Website:      "https://pki.goog",
		Note:         "90 天有效期，需要手动填写 EAB KID 与 HMAC。",
		MaxDays:      90,
	},
}

// GetCA 按 ID 查找 CA
func GetCA(id string) (CA, bool) {
	for _, c := range CAs {
		if c.ID == id {
			return c, true
		}
	}
	return CA{}, false
}

// FetchZeroSSLEAB 用邮箱向 ZeroSSL 申请 EAB 凭据
func FetchZeroSSLEAB(email string) (kid, hmac string, err error) {
	form := url.Values{"email": {email}}
	req, err := http.NewRequest(http.MethodPost,
		"https://api.zerossl.com/acme/eab-credentials-email",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("请求 ZeroSSL EAB 失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var out struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", fmt.Errorf("解析 ZeroSSL 响应失败: %w (原始: %s)", err, truncate(string(body), 200))
	}
	if !out.Success || out.EABKID == "" {
		return "", "", fmt.Errorf("ZeroSSL 未返回 EAB 凭据（邮箱可能未注册或已达限额），请到 ZeroSSL 控制台手动获取 KID/HMAC 后填入")
	}
	return out.EABKID, out.EABHMACKey, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
