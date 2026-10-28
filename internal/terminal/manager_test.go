package terminal

import (
	"testing"
	"time"
)

func newTestManager(enabled bool) *Manager {
	return NewManager(
		func() bool { return enabled },
		func() string { return "/bin/bash" },
		func() time.Duration { return 10 * time.Minute },
	)
}

func TestTicketLifecycle(t *testing.T) {
	m := newTestManager(true)

	tk := m.IssueTicket()
	if tk == "" {
		t.Fatal("票据不应为空")
	}
	if !m.ConsumeTicket(tk) {
		t.Fatal("首次使用票据应通过")
	}
	if m.ConsumeTicket(tk) {
		t.Fatal("票据只能使用一次，第二次必须失败")
	}
}

func TestTicketRejectsUnknownAndEmpty(t *testing.T) {
	m := newTestManager(true)
	if m.ConsumeTicket("") {
		t.Fatal("空票据必须被拒绝")
	}
	if m.ConsumeTicket("deadbeef") {
		t.Fatal("未知票据必须被拒绝")
	}
}

func TestTicketExpires(t *testing.T) {
	m := newTestManager(true)
	tk := m.IssueTicket()

	// 直接把过期时间拨到过去，模拟超时
	m.mu.Lock()
	m.tickets[tk] = time.Now().Add(-time.Second)
	m.mu.Unlock()

	if m.ConsumeTicket(tk) {
		t.Fatal("过期票据必须被拒绝")
	}
}

func TestIssueTicketClearsExpired(t *testing.T) {
	m := newTestManager(true)
	old := m.IssueTicket()
	m.mu.Lock()
	m.tickets[old] = time.Now().Add(-time.Minute)
	m.mu.Unlock()

	_ = m.IssueTicket()
	m.mu.Lock()
	_, still := m.tickets[old]
	m.mu.Unlock()
	if still {
		t.Fatal("签发新票据时应清理过期票据")
	}
}

func TestSingleSessionLimit(t *testing.T) {
	m := newTestManager(true)
	if _, err := m.addSession("1.2.3.4:1111"); err != nil {
		t.Fatalf("第一个会话应允许: %v", err)
	}
	if m.Active() != 1 {
		t.Fatalf("活跃会话数应为 1，实际 %d", m.Active())
	}
	if _, err := m.addSession("1.2.3.5:2222"); err != ErrBusy {
		t.Fatalf("第二个会话应返回 ErrBusy，实际 %v", err)
	}

	sessions := m.Sessions()
	m.removeSession(sessions[0].ID)
	if m.Active() != 0 {
		t.Fatalf("移除后活跃会话数应为 0，实际 %d", m.Active())
	}
	// 释放后可以再建
	if _, err := m.addSession("1.2.3.6:3333"); err != nil {
		t.Fatalf("释放后应能新建会话: %v", err)
	}
}

func TestEnabledReflectsCallback(t *testing.T) {
	off := newTestManager(false)
	if off.Enabled() {
		t.Fatal("enabled=false 时应返回 false")
	}
	on := newTestManager(true)
	if !on.Enabled() {
		t.Fatal("enabled=true 时应返回 true")
	}
}

func TestIdleTimeoutFallback(t *testing.T) {
	m := NewManager(func() bool { return true }, nil, func() time.Duration { return 0 })
	if got := m.idleTimeout(); got != 15*time.Minute {
		t.Fatalf("空闲超时应回落到 15 分钟，实际 %v", got)
	}
	m2 := NewManager(func() bool { return true }, nil, func() time.Duration { return 3 * time.Minute })
	if got := m2.idleTimeout(); got != 3*time.Minute {
		t.Fatalf("空闲超时应为 3 分钟，实际 %v", got)
	}
}
