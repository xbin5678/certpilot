package scheduler

import (
	"context"
	"log"
	"time"

	"certpilot/internal/acme"
	"certpilot/internal/store"
)

// Scheduler 自动续期调度器：每 10 分钟扫一次，进入窗口就续
type Scheduler struct {
	st  *store.Store
	mgr *acme.Manager
}

func New(st *store.Store, mgr *acme.Manager) *Scheduler {
	return &Scheduler{st: st, mgr: mgr}
}

// Start 后台运行
func (s *Scheduler) Start(ctx context.Context) {
	go func() {
		// 启动后延迟 20 秒再跑第一轮，避免和面板启动抢资源
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
		s.tick()
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.tick()
			}
		}
	}()
}

func (s *Scheduler) tick() {
	n, err := s.RunOnce()
	if err != nil {
		log.Printf("[scheduler] 扫描失败: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[scheduler] 本轮触发 %d 张证书续期", n)
	}
}

// RunOnce 立即执行一轮检查，返回触发的续期数量
func (s *Scheduler) RunOnce() (int, error) {
	certs, err := s.st.ListCerts()
	if err != nil {
		return 0, err
	}
	now := time.Now()
	triggered := 0

	for _, c := range certs {
		// 刷新展示状态
		c.RefreshStatus(now)
		_ = s.st.PutCert(c)

		if !c.AutoRenew || c.Status == store.StatusRevoked {
			continue
		}
		// 从未成功签发过的证书不自动申请，避免建好配置就半夜乱跑
		if c.LastIssuedAt == "" || c.NotAfter == "" {
			continue
		}
		if !c.NeedsRenew(now) {
			continue
		}
		if s.mgr.Jobs().Running(c.ID) != nil {
			continue
		}
		if c.FailCount > 0 && !backoffElapsed(c, now) {
			continue
		}
		if c.FailCount >= 8 {
			s.st.AddEvent(c.ID, "error", "连续失败 8 次，已暂停自动续期，请手动处理")
			continue
		}
		if _, err := s.mgr.IssueAsync(c, "renew"); err != nil {
			continue
		}
		triggered++
	}
	return triggered, nil
}

// backoffElapsed 失败后退避：30 分钟 × 失败次数，最长 6 小时
func backoffElapsed(c *store.Cert, now time.Time) bool {
	if c.LastAttemptAt == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, c.LastAttemptAt)
	if err != nil {
		return true
	}
	backoff := time.Duration(c.FailCount) * 30 * time.Minute
	if backoff > 6*time.Hour {
		backoff = 6 * time.Hour
	}
	return now.After(t.Add(backoff))
}
