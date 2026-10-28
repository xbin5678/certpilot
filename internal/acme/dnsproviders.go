package acme

import (
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/huaweicloud"
)

// Field 一个凭据输入项
type Field struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// DNSProviderInfo DNS 服务商描述
type DNSProviderInfo struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Help   string  `json:"help"`
	Fields []Field `json:"fields"`
	build  func(map[string]string) (challenge.Provider, error)
}

var (
	dnsEnvMu sync.Mutex
	registry = map[string]DNSProviderInfo{}
)

func registerDNS(p DNSProviderInfo) { registry[p.ID] = p }

func init() {
	registerDNS(DNSProviderInfo{
		ID:   "cloudflare",
		Name: "Cloudflare",
		Help: "推荐使用 Zone:DNS:Edit 权限的 API Token（不要用 Global Key）。",
		Fields: []Field{
			{Key: "CLOUDFLARE_DNS_API_TOKEN", Label: "API Token", Placeholder: "具有 Zone.DNS 编辑权限的 Token", Secret: true, Required: true},
		},
		build: func(c map[string]string) (challenge.Provider, error) {
			return withEnv(c, func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() })
		},
	})

	registerDNS(DNSProviderInfo{
		ID:   "alidns",
		Name: "阿里云 DNS",
		Help: "RAM 用户需具备 AliyunDNSFullAccess 权限，AccessKey 建议使用子账号。",
		Fields: []Field{
			{Key: "ALICLOUD_ACCESS_KEY", Label: "AccessKey ID", Placeholder: "LTAI...", Required: true},
			{Key: "ALICLOUD_SECRET_KEY", Label: "AccessKey Secret", Placeholder: "••••••", Secret: true, Required: true},
			{Key: "ALICLOUD_REGION_ID", Label: "Region（可选）", Placeholder: "cn-hangzhou", Required: false},
		},
		build: func(c map[string]string) (challenge.Provider, error) {
			return withEnv(c, func() (challenge.Provider, error) { return alidns.NewDNSProvider() })
		},
	})

	registerDNS(DNSProviderInfo{
		ID:   "dnspod",
		Name: "DNSPod / 腾讯云",
		Help: "在 DNSPod 控制台「用户中心 → 密钥管理」创建 API Token。",
		Fields: []Field{
			{Key: "DNSPOD_API_KEY", Label: "API Token", Placeholder: "ID,Token 格式", Secret: true, Required: true},
		},
		build: func(c map[string]string) (challenge.Provider, error) {
			return withEnv(c, func() (challenge.Provider, error) { return dnspod.NewDNSProvider() })
		},
	})

	registerDNS(DNSProviderInfo{
		ID:   "huaweicloud",
		Name: "华为云 DNS",
		Help: "使用 IAM 用户的永久 AK/SK，需具备 DNS FullAccess。",
		Fields: []Field{
			{Key: "HUAWEICLOUD_ACCESS_KEY_ID", Label: "Access Key ID", Placeholder: "AK", Required: true},
			{Key: "HUAWEICLOUD_SECRET_ACCESS_KEY", Label: "Secret Access Key", Placeholder: "SK", Secret: true, Required: true},
			{Key: "HUAWEICLOUD_REGION", Label: "Region", Placeholder: "cn-north-1", Required: true, Default: "cn-north-1"},
		},
		build: func(c map[string]string) (challenge.Provider, error) {
			return withEnv(c, func() (challenge.Provider, error) { return huaweicloud.NewDNSProvider() })
		},
	})
}

// withEnv 在互斥区内临时注入环境变量并构造 provider。
// lego 的 provider 只在构造时读环境变量，因此构造完成后可以安全还原。
func withEnv(creds map[string]string, build func() (challenge.Provider, error)) (challenge.Provider, error) {
	dnsEnvMu.Lock()
	defer dnsEnvMu.Unlock()

	type backup struct {
		key   string
		value string
		had   bool
	}
	var saved []backup
	for k, v := range creds {
		if v == "" {
			continue
		}
		old, had := os.LookupEnv(k)
		saved = append(saved, backup{key: k, value: old, had: had})
		_ = os.Setenv(k, v)
	}
	defer func() {
		for _, b := range saved {
			if b.had {
				_ = os.Setenv(b.key, b.value)
			} else {
				_ = os.Unsetenv(b.key)
			}
		}
	}()

	p, err := build()
	if err != nil {
		return nil, fmt.Errorf("初始化 DNS 服务商失败: %w", err)
	}
	return p, nil
}

// ListDNSProviders 返回可用的 DNS 服务商（按名称排序）
func ListDNSProviders() []DNSProviderInfo {
	out := make([]DNSProviderInfo, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// NewDNSProvider 按 ID 构造 DNS provider
func NewDNSProvider(id string, creds map[string]string) (challenge.Provider, error) {
	p, ok := registry[id]
	if !ok {
		return nil, fmt.Errorf("不支持的 DNS 服务商: %s", id)
	}
	// 拷贝一份再补默认值：直接改调用方的 map 有两个问题 ——
	// 一是 nil map 赋值会 panic（旧数据或 CLI 路径可能传 nil），
	// 二是会把默认值悄悄写回调用方的凭据表。
	cp := make(map[string]string, len(creds)+2)
	for k, v := range creds {
		cp[k] = v
	}
	for _, f := range p.Fields {
		if f.Required && cp[f.Key] == "" {
			if f.Default != "" {
				cp[f.Key] = f.Default
				continue
			}
			return nil, fmt.Errorf("%s 缺少必填项: %s", p.Name, f.Label)
		}
	}
	return p.build(cp)
}
