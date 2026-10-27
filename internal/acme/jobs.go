package acme

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"certpilot/internal/store"
)

// 任务状态
const (
	JobRunning = "running"
	JobSuccess = "success"
	JobError   = "error"
)

// JobView 任务的可序列化快照（不含互斥锁）
type JobView struct {
	ID        string      `json:"id"`
	CertID    string      `json:"certId"`
	Action    string      `json:"action"`
	Status    string      `json:"status"`
	Message   string      `json:"message"`
	TXT       []TXTRecord `json:"txt,omitempty"`
	Logs      []string    `json:"logs"`
	StartedAt time.Time   `json:"startedAt"`
	EndedAt   *time.Time  `json:"endedAt,omitempty"`
}

// Job 一次签发/续期/吊销任务
type Job struct {
	ID        string      `json:"id"`
	CertID    string      `json:"certId"`
	Action    string      `json:"action"`
	Status    string      `json:"status"`
	Message   string      `json:"message"`
	TXT       []TXTRecord `json:"txt,omitempty"`
	Logs      []string    `json:"logs"`
	StartedAt time.Time   `json:"startedAt"`
	EndedAt   *time.Time  `json:"endedAt,omitempty"`

	mu sync.Mutex
}

// AddLog 追加一行进度日志
func (j *Job) AddLog(format string, args ...any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	line := fmt.Sprintf("%s  %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	j.Logs = append(j.Logs, line)
	if len(j.Logs) > 300 {
		j.Logs = j.Logs[len(j.Logs)-300:]
	}
	j.Message = fmt.Sprintf(format, args...)
}

// SetTXT 更新待添加的 DNS 记录
func (j *Job) SetTXT(recs []TXTRecord) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.TXT = recs
}

// Finish 结束任务
func (j *Job) Finish(status string, msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	j.EndedAt = &now
	j.Status = status
	j.Message = msg
	j.Logs = append(j.Logs, fmt.Sprintf("%s  %s", now.Format("15:04:05"), msg))
}

// Snapshot 返回一份可安全序列化的副本
func (j *Job) Snapshot() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := JobView{
		ID:        j.ID,
		CertID:    j.CertID,
		Action:    j.Action,
		Status:    j.Status,
		Message:   j.Message,
		StartedAt: j.StartedAt,
		EndedAt:   j.EndedAt,
		TXT:       append([]TXTRecord(nil), j.TXT...),
		Logs:      append([]string(nil), j.Logs...),
	}
	return cp
}

// JobManager 内存任务表
type JobManager struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

func NewJobManager() *JobManager {
	return &JobManager{jobs: map[string]*Job{}}
}

func (jm *JobManager) Create(certID, action string) *Job {
	j := &Job{
		ID:        store.NewID(),
		CertID:    certID,
		Action:    action,
		Status:    JobRunning,
		StartedAt: time.Now(),
	}
	j.AddLog("任务已创建")
	jm.mu.Lock()
	jm.jobs[j.ID] = j
	jm.mu.Unlock()
	go jm.gc()
	return j
}

func (jm *JobManager) Get(id string) *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.jobs[id]
}

// Running 该证书是否已有任务在跑
func (jm *JobManager) Running(certID string) *Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	for _, j := range jm.jobs {
		if j.CertID == certID && j.Status == JobRunning {
			return j
		}
	}
	return nil
}

// List 最近的任务
func (jm *JobManager) List(limit int) []JobView {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	out := make([]JobView, 0, len(jm.jobs))
	for _, j := range jm.jobs {
		out = append(out, j.Snapshot())
	}
	sort.Slice(out, func(i, k int) bool { return out[i].StartedAt.After(out[k].StartedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// gc 清理 2 小时前结束的任务
func (jm *JobManager) gc() {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	cut := time.Now().Add(-2 * time.Hour)
	for id, j := range jm.jobs {
		j.mu.Lock()
		ended := j.EndedAt
		j.mu.Unlock()
		if ended != nil && ended.Before(cut) {
			delete(jm.jobs, id)
		}
	}
}
