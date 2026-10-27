package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestSettingsRoundTrip(t *testing.T) {
	st := newTestStore(t)

	s, err := st.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if s.DefaultCA != "letsencrypt" || s.DefaultRenewDays != 30 {
		t.Fatalf("默认值不对: %+v", s)
	}

	s.ACMEEmail = "a@b.com"
	s.Compat3XUI = "on"
	s.NotifyOnError = false
	s.EAB = map[string]EABCred{"gts": {KID: "kid1", HMAC: "hmac1"}}
	if err := st.SaveSettings(s); err != nil {
		t.Fatal(err)
	}

	got, err := st.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.ACMEEmail != "a@b.com" || got.Compat3XUI != "on" || got.NotifyOnError {
		t.Fatalf("设置未正确保存: %+v", got)
	}
	if got.EAB["gts"].KID != "kid1" {
		t.Fatalf("EAB 未正确保存: %+v", got.EAB)
	}
}

func TestCertCRUD(t *testing.T) {
	st := newTestStore(t)

	c := &Cert{
		ID:              NewID(),
		Name:            "站点",
		Domains:         []string{"a.com", "www.a.com"},
		CA:              "letsencrypt",
		KeyType:         "ec256",
		Challenge:       ChallengeDNS,
		DNSProvider:     "cloudflare",
		DNSCredentials:  map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "x"},
		AutoRenew:       true,
		RenewBeforeDays: 30,
		Status:          StatusPending,
	}
	if err := st.PutCert(c); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetCert(c.ID)
	if err != nil || got == nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(got.Domains) != 2 || got.Domains[1] != "www.a.com" {
		t.Fatalf("域名未正确保存: %v", got.Domains)
	}
	if got.DNSCredentials["CLOUDFLARE_DNS_API_TOKEN"] != "x" {
		t.Fatalf("DNS 凭据未正确保存: %v", got.DNSCredentials)
	}
	if !got.AutoRenew {
		t.Fatal("自动续期标记丢失")
	}

	got.Status = StatusValid
	got.NotAfter = time.Now().Add(60 * 24 * time.Hour).Format(time.RFC3339)
	if err := st.PutCert(got); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListCerts()
	if err != nil || len(list) != 1 {
		t.Fatalf("列表异常: %v %d", err, len(list))
	}
	if list[0].Status != StatusValid {
		t.Fatalf("状态未更新: %s", list[0].Status)
	}

	if err := st.DeleteCert(c.ID); err != nil {
		t.Fatal(err)
	}
	gone, _ := st.GetCert(c.ID)
	if gone != nil {
		t.Fatal("删除失败")
	}
}

func TestCertStatusTransitions(t *testing.T) {
	now := time.Now()

	fresh := &Cert{Status: StatusValid, NotAfter: now.Add(80 * 24 * time.Hour).Format(time.RFC3339), RenewBeforeDays: 30}
	fresh.RefreshStatus(now)
	if fresh.Status != StatusValid {
		t.Errorf("80 天后到期应为 valid，实际 %s", fresh.Status)
	}

	soon := &Cert{Status: StatusValid, NotAfter: now.Add(10 * 24 * time.Hour).Format(time.RFC3339), RenewBeforeDays: 30}
	soon.RefreshStatus(now)
	if soon.Status != StatusExpiring {
		t.Errorf("10 天后到期应为 expiring，实际 %s", soon.Status)
	}

	expired := &Cert{Status: StatusValid, NotAfter: now.Add(-24 * time.Hour).Format(time.RFC3339), RenewBeforeDays: 30}
	expired.RefreshStatus(now)
	if expired.Status != StatusExpired {
		t.Errorf("已过期应为 expired，实际 %s", expired.Status)
	}

	if !soon.NeedsRenew(now) {
		t.Error("10 天后到期应触发续期")
	}
	if fresh.NeedsRenew(now) {
		t.Error("80 天后到期不应触发续期")
	}

	revoked := &Cert{Status: StatusRevoked, NotAfter: now.Add(10 * 24 * time.Hour).Format(time.RFC3339)}
	revoked.RefreshStatus(now)
	if revoked.Status != StatusRevoked {
		t.Error("已吊销状态不应被覆盖")
	}
}

func TestEvents(t *testing.T) {
	st := newTestStore(t)
	st.AddEvent("c1", "info", "测试消息")
	ev, err := st.ListEvents(10)
	if err != nil || len(ev) != 1 {
		t.Fatalf("日志异常: %v %d", err, len(ev))
	}
	if ev[0].Message != "测试消息" || ev[0].CertID != "c1" {
		t.Fatalf("日志内容不对: %+v", ev[0])
	}
}
