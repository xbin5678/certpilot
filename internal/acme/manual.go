package acme

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// TXTRecord 一条需要人工添加的 DNS 记录
type TXTRecord struct {
	Domain string `json:"domain"`
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
}

// ManualDNS 手动 DNS 验证：把 TXT 记录暴露给界面，由用户去 DNS 服务商添加。
// lego 会按照 Timeout() 返回的间隔轮询 DNS，记录生效后自动继续，无需用户点"继续"。
type ManualDNS struct {
	mu       sync.Mutex
	records  map[string]TXTRecord
	order    []string
	onUpdate func([]TXTRecord)
}

// NewManualDNS 创建手动 DNS provider
func NewManualDNS(onUpdate func([]TXTRecord)) *ManualDNS {
	return &ManualDNS{records: map[string]TXTRecord{}, onUpdate: onUpdate}
}

func (m *ManualDNS) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	rec := TXTRecord{
		Domain: domain,
		FQDN:   info.EffectiveFQDN,
		Value:  info.Value,
	}

	m.mu.Lock()
	if _, exists := m.records[rec.FQDN]; !exists {
		m.order = append(m.order, rec.FQDN)
	}
	m.records[rec.FQDN] = rec
	snapshot := m.snapshotLocked()
	m.mu.Unlock()

	if m.onUpdate != nil {
		m.onUpdate(snapshot)
	}
	return nil
}

func (m *ManualDNS) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	m.mu.Lock()
	delete(m.records, info.EffectiveFQDN)
	for i, k := range m.order {
		if k == info.EffectiveFQDN {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	snapshot := m.snapshotLocked()
	m.mu.Unlock()

	if m.onUpdate != nil {
		m.onUpdate(snapshot)
	}
	return nil
}

// Timeout 让 lego 轮询 DNS 最长 20 分钟，每 10 秒查一次
func (m *ManualDNS) Timeout() (time.Duration, time.Duration) {
	return 20 * time.Minute, 10 * time.Second
}

// Sequential 让多个域名的验证串行执行，避免用户一次面对一堆记录
func (m *ManualDNS) Sequential() time.Duration { return 3 * time.Second }

func (m *ManualDNS) snapshotLocked() []TXTRecord {
	out := make([]TXTRecord, 0, len(m.order))
	for _, k := range m.order {
		if r, ok := m.records[k]; ok {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// Records 当前待添加的记录
func (m *ManualDNS) Records() []TXTRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}

func (m *ManualDNS) String() string { return fmt.Sprintf("manual(%d)", len(m.records)) }
