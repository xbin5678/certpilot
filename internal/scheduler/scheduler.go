package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"certpilot/internal/acme"
	"certpilot/internal/store"
)

// Scheduler 自动续期调度器：每 10 分钟扫一次，进入窗口就续
type Scheduler struct {
	st  *store.Store
	mgr *acme.Manager

	// warned 记录已经播报过「连续失败已达上限」的证书，避免每轮都写一条事件
	warned sync.Map // certID -> struct{}
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
		// 只在展示状态真的变化时才写库。之前是每轮无条件 PutCert，
		// 低配 VPS 上每 10 分钟对全表做一次 UPDATE，纯属写放大。
		before := c.Status
		c.RefreshStatus(now)
		if c.Status != before {
			_ = s.st.PutCert(c)
		}

		// 达到失败上限时只播报一次，否则每 10 分钟刷一条同样的错误
		if c.FailCount >= MaxFailCount {
			if _, seen := s.warned.Load(c.ID); !seen {
				s.warned.Store(c.ID, struct{}{})
				s.st.AddEvent(c.ID, "error", "连续失败已达上限，已暂停自动续期，请手动处理")
			}
		} else {
			s.warned.Delete(c.ID)
		}

		ok, _ := Decide(c, now, s.mgr.Jobs().Running(c.ID) != nil)
		if !ok {
			continue
		}
		if _, err := s.mgr.IssueAsync(c, "renew"); err != nil {
			continue
		}
		triggered++
	}
	return triggered, nil
}

// MaxFailCount 连续失败多少次后暂停自动续期
const MaxFailCount = 8

// Decide 判断一张证书本轮是否该续期，返回 (是否续期, 跳过原因)。
//
// scheduler 和 `certpilot renew` 必须共用同一套规则：按需部署（默认）走的是
// renew 子命令，如果那边少了退避和失败上限，失败的证书会每 6 小时重试一次、
// 永不停止，而常驻模式却会退避 —— 同一份配置在两种部署方式下行为不一致。
func Decide(c *store.Cert, now time.Time, jobRunning bool) (bool, string) {
	if !c.AutoRenew {
		return false, ""
	}
	if c.Status == store.StatusRevoked {
		return false, ""
	}
	// 从未成功签发过的证书不自动申请，避免建好配置就半夜乱跑
	if c.LastIssuedAt == "" || c.NotAfter == "" {
		return false, ""
	}
	if !c.NeedsRenew(now) {
		return false, ""
	}
	if jobRunning {
		return false, ""
	}
	// 手动 DNS 需要人工加 TXT，自动发起只会挂在那里等 20 分钟
	if c.Challenge == store.ChallengeDNSManual {
		return false, "手动 DNS 模式需要人工添加 TXT 记录"
	}
	if c.FailCount >= MaxFailCount {
		return false, "连续失败已达上限，已暂停自动续期"
	}
	if c.FailCount > 0 && !backoffElapsed(c, now) {
		return false, "失败退避中"
	}
	return true, ""
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
