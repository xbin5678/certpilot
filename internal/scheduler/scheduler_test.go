package scheduler

import (
	"testing"
	"time"

	"certpilot/internal/store"
)

// 构造一张「已签发、即将到期」的证书，作为各用例的基线
func baseCert() *store.Cert {
	now := time.Now()
	return &store.Cert{
		ID:              "abc123",
		Domains:         []string{"example.com"},
		AutoRenew:       true,
		Challenge:       store.ChallengeDNS,
		Status:          store.StatusExpiring,
		NotBefore:       now.AddDate(0, 0, -85).Format(time.RFC3339),
		NotAfter:        now.AddDate(0, 0, 5).Format(time.RFC3339),
		LastIssuedAt:    now.AddDate(0, 0, -85).Format(time.RFC3339),
		LastAttemptAt:   now.AddDate(0, 0, -85).Format(time.RFC3339),
		RenewBeforeDays: 30,
	}
}

func TestDecideShouldRenew(t *testing.T) {
	now := time.Now()
	c := baseCert()
	ok, reason := Decide(c, now, false)
	if !ok {
		t.Fatalf("即将到期且自动续订开启时应续期，实际跳过（原因 %q）", reason)
	}
}

func TestDecideAutoRenewOff(t *testing.T) {
	c := baseCert()
	c.AutoRenew = false
	if ok, _ := Decide(c, time.Now(), false); ok {
		t.Fatal("关闭自动续订后不应续期")
	}
}

func TestDecideRevoked(t *testing.T) {
	c := baseCert()
	c.Status = store.StatusRevoked
	if ok, _ := Decide(c, time.Now(), false); ok {
		t.Fatal("已吊销的证书不应自动续期")
	}
}

func TestDecideNeverIssued(t *testing.T) {
	c := baseCert()
	c.LastIssuedAt = ""
	c.NotAfter = ""
	if ok, _ := Decide(c, time.Now(), false); ok {
		t.Fatal("从未签发过的证书不应自动申请")
	}
}

func TestDecideNotDueYet(t *testing.T) {
	c := baseCert()
	now := time.Now()
	c.NotBefore = now.Format(time.RFC3339)
	c.NotAfter = now.AddDate(0, 0, 80).Format(time.RFC3339)
	if ok, _ := Decide(c, now, false); ok {
		t.Fatal("还没进入续期窗口时不应续期")
	}
}

func TestDecideJobRunning(t *testing.T) {
	c := baseCert()
	if ok, _ := Decide(c, time.Now(), true); ok {
		t.Fatal("已有任务在执行时不应重复触发")
	}
}

func TestDecideManualDNS(t *testing.T) {
	c := baseCert()
	c.Challenge = store.ChallengeDNSManual
	ok, reason := Decide(c, time.Now(), false)
	if ok {
		t.Fatal("手动 DNS 模式不应自动续期")
	}
	if reason == "" {
		t.Fatal("手动 DNS 跳过时应给出原因")
	}
}

func TestDecideFailLimit(t *testing.T) {
	c := baseCert()
	c.FailCount = MaxFailCount
	ok, reason := Decide(c, time.Now(), false)
	if ok {
		t.Fatal("达到失败上限后不应继续自动续期")
	}
	if reason == "" {
		t.Fatal("达到上限时应给出原因")
	}
}

func TestDecideBackoff(t *testing.T) {
	c := baseCert()
	now := time.Now()
	c.FailCount = 2
	c.LastAttemptAt = now.Add(-10 * time.Minute).Format(time.RFC3339)
	if ok, reason := Decide(c, now, false); ok {
		t.Fatalf("失败 2 次后 10 分钟应仍在退避（需 60 分钟），实际放行（原因 %q）", reason)
	}

	// 超过退避窗口后放行
	c.LastAttemptAt = now.Add(-61 * time.Minute).Format(time.RFC3339)
	if ok, _ := Decide(c, now, false); !ok {
		t.Fatal("退避窗口已过，应允许重试")
	}
}

func TestBackoffElapsed(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		fail     int
		lastAt   string
		expected bool
	}{
		{"从未尝试", 0, "", true},
		{"时间格式错误", 3, "not-a-time", true},
		{"失败1次未满30分钟", 1, now.Add(-10 * time.Minute).Format(time.RFC3339), false},
		{"失败1次已过30分钟", 1, now.Add(-31 * time.Minute).Format(time.RFC3339), true},
		{"失败5次未满2.5小时", 5, now.Add(-2 * time.Hour).Format(time.RFC3339), false},
		{"失败5次已过2.5小时", 5, now.Add(-151 * time.Minute).Format(time.RFC3339), true},
		// 20 次 × 30 分钟 = 10 小时，但封顶 6 小时
		{"失败20次封顶6小时", 20, now.Add(-7 * time.Hour).Format(time.RFC3339), true},
		{"失败20次未满6小时", 20, now.Add(-5 * time.Hour).Format(time.RFC3339), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &store.Cert{FailCount: tc.fail, LastAttemptAt: tc.lastAt}
			if got := backoffElapsed(c, now); got != tc.expected {
				t.Fatalf("期望 %v，实际 %v", tc.expected, got)
			}
		})
	}
}
