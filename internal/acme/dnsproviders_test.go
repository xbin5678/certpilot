package acme

import (
	"os"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
)

func TestCAsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range CAs {
		if seen[c.ID] {
			t.Fatalf("CA ID 重复: %s", c.ID)
		}
		seen[c.ID] = true
		if !strings.HasPrefix(c.DirectoryURL, "https://") {
			t.Fatalf("CA %s 的目录地址必须是 https: %s", c.ID, c.DirectoryURL)
		}
	}
}

// 按字节截断会把中文切成乱码，必须按字符截
func TestTruncateRuneSafe(t *testing.T) {
	s := "签发失败：域名解析不到本机，请检查 A 记录"
	got := truncate(s, 5)
	if got != "签发失败：..." {
		t.Fatalf("按字符截断结果不对: %q", got)
	}
	if !strings.HasPrefix(got, "签发失败") {
		t.Fatalf("截断后出现乱码: %q", got)
	}
	// 不超长时原样返回
	if truncate("短", 10) != "短" {
		t.Fatal("未超长时不应加省略号")
	}
	if truncate("", 5) != "" {
		t.Fatal("空串应返回空串")
	}
}

func TestNewDNSProviderUnknown(t *testing.T) {
	if _, err := NewDNSProvider("not-a-provider", nil); err == nil {
		t.Fatal("未知服务商应报错")
	}
}

func TestNewDNSProviderMissingRequired(t *testing.T) {
	if _, err := NewDNSProvider("cloudflare", nil); err == nil {
		t.Fatal("缺少必填凭据应报错")
	}
	if _, err := NewDNSProvider("alidns", map[string]string{"ALICLOUD_ACCESS_KEY": "x"}); err == nil {
		t.Fatal("缺少 SecretKey 应报错")
	}
}

// nil 凭据不能 panic：旧数据或 CLI 路径可能传 nil
func TestNewDNSProviderNilCredsNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("传 nil 凭据不应 panic: %v", r)
		}
	}()
	_, _ = NewDNSProvider("huaweicloud", nil)
	_, _ = NewDNSProvider("dnspod", nil)
}

// 补默认值不能污染调用方的 map
func TestNewDNSProviderDoesNotMutateCallerMap(t *testing.T) {
	creds := map[string]string{
		"HUAWEICLOUD_ACCESS_KEY_ID":     "AK",
		"HUAWEICLOUD_SECRET_ACCESS_KEY": "SK",
	}
	before := len(creds)
	_, _ = NewDNSProvider("huaweicloud", creds)
	if len(creds) != before {
		t.Fatalf("调用方的凭据表被写入了默认值: %+v", creds)
	}
	if _, ok := creds["HUAWEICLOUD_REGION"]; ok {
		t.Fatal("默认 Region 不应写回调用方的 map")
	}
}

func TestListDNSProvidersSorted(t *testing.T) {
	list := ListDNSProviders()
	if len(list) < 4 {
		t.Fatalf("应至少注册 4 个服务商，实际 %d", len(list))
	}
	// 按名称排序
	for i := 1; i < len(list); i++ {
		if list[i-1].Name > list[i].Name {
			t.Fatalf("未按名称排序: %s > %s", list[i-1].Name, list[i].Name)
		}
	}
	// 每个服务商都要有 ID、名称和字段定义
	for _, p := range list {
		if p.ID == "" || p.Name == "" || len(p.Fields) == 0 {
			t.Fatalf("服务商定义不完整: %+v", p)
		}
		for _, f := range p.Fields {
			if f.Key == "" || f.Label == "" {
				t.Fatalf("%s 的字段定义不完整: %+v", p.ID, f)
			}
		}
	}
}

func TestWithEnvRestoresEnvironment(t *testing.T) {
	const k = "CERTPILOT_TEST_ENV_KEY"
	t.Setenv(k, "original")

	_, _ = withEnv(map[string]string{k: "temporary"}, func() (challenge.Provider, error) {
		if got := os.Getenv(k); got != "temporary" {
			t.Fatalf("互斥区内应看到临时值，实际 %q", got)
		}
		return nil, nil
	})
	if got := os.Getenv(k); got != "original" {
		t.Fatalf("退出后应还原为原值，实际 %q", got)
	}
}

// 原本不存在的环境变量，注入后必须被清掉，不能残留
func TestWithEnvUnsetsNewKey(t *testing.T) {
	const k = "CERTPILOT_TEST_ENV_NEW"
	os.Unsetenv(k)

	_, _ = withEnv(map[string]string{k: "v"}, func() (challenge.Provider, error) {
		return nil, nil
	})
	if _, ok := os.LookupEnv(k); ok {
		t.Fatalf("%s 应被清除，实际仍存在", k)
	}
}
