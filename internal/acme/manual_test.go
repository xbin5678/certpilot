package acme

import (
	"strings"
	"testing"
)

func TestManualDNSRecords(t *testing.T) {
	var last []TXTRecord
	p := NewManualDNS(func(recs []TXTRecord) { last = recs })

	if err := p.Present("example.com", "tok1", "keyauth-1"); err != nil {
		t.Fatalf("Present 失败: %v", err)
	}
	if err := p.Present("www.example.com", "tok2", "keyauth-2"); err != nil {
		t.Fatalf("Present 失败: %v", err)
	}

	recs := p.Records()
	if len(recs) != 2 {
		t.Fatalf("期望 2 条记录，实际 %d", len(recs))
	}
	if len(last) != 2 {
		t.Fatalf("回调未收到完整记录，实际 %d", len(last))
	}
	for _, r := range recs {
		if !strings.HasPrefix(r.FQDN, "_acme-challenge.") {
			t.Errorf("FQDN 异常: %s", r.FQDN)
		}
		if r.Value == "" {
			t.Errorf("TXT 值为空: %s", r.FQDN)
		}
	}

	if err := p.CleanUp("example.com", "tok1", "keyauth-1"); err != nil {
		t.Fatalf("CleanUp 失败: %v", err)
	}
	if len(p.Records()) != 1 {
		t.Fatalf("清理后期望 1 条记录，实际 %d", len(p.Records()))
	}
}

func TestManualDNSTimeout(t *testing.T) {
	p := NewManualDNS(nil)
	timeout, interval := p.Timeout()
	if timeout <= 0 || interval <= 0 {
		t.Fatalf("超时参数非法: %v %v", timeout, interval)
	}
	if interval >= timeout {
		t.Fatalf("轮询间隔不应大于总超时")
	}
}

func TestGetCA(t *testing.T) {
	for _, id := range []string{"letsencrypt", "letsencrypt_staging", "zerossl", "buypass", "gts"} {
		ca, ok := GetCA(id)
		if !ok {
			t.Fatalf("缺少 CA: %s", id)
		}
		if !strings.HasPrefix(ca.DirectoryURL, "https://") {
			t.Errorf("%s 的 DirectoryURL 非法: %s", id, ca.DirectoryURL)
		}
	}
	if _, ok := GetCA("nope"); ok {
		t.Error("未知 CA 不应存在")
	}
}

func TestListDNSProviders(t *testing.T) {
	ps := ListDNSProviders()
	if len(ps) == 0 {
		t.Fatal("没有注册任何 DNS 服务商")
	}
	for _, p := range ps {
		if len(p.Fields) == 0 {
			t.Errorf("%s 没有凭据字段", p.ID)
		}
	}
	if _, err := NewDNSProvider("nope", nil); err == nil {
		t.Error("未知服务商应返回错误")
	}
	if _, err := NewDNSProvider("cloudflare", map[string]string{}); err == nil {
		t.Error("缺少必填凭据时应返回错误")
	}
}
