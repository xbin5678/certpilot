// Package task 提供带步骤与日志的内存任务，用于长耗时操作（如安装 3x-ui）的
// 进度上报。任务只存在于进程内，进程重启后丢失，符合"一次性操作"的语义。
package task

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"certpilot/internal/store"
)

// 任务状态
const (
	Running = "running"
	Success = "success"
	Error   = "error"
)

// 步骤状态
const (
	StepPending = "pending"
	StepActive  = "running"
	StepDone    = "done"
	StepFailed  = "error"
	StepSkipped = "skip"
)

// Step 一个可见的安装步骤
type Step struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// View 可安全序列化的任务快照
type View struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Status    string         `json:"status"`
	Message   string         `json:"message"`
	Steps     []Step         `json:"steps"`
	Logs      []string       `json:"logs"`
	Result    map[string]any `json:"result,omitempty"`
	StartedAt time.Time      `json:"startedAt"`
	EndedAt   *time.Time     `json:"endedAt,omitempty"`
}

// Task 一次长耗时操作
type Task struct {
	ID        string
	Kind      string
	Status    string
	Message   string
	Steps     []Step
	Logs      []string
	Result    map[string]any
	StartedAt time.Time
	EndedAt   *time.Time

	mu sync.Mutex
}

// AddStep 追加一个待执行步骤，返回其下标
func (t *Task) AddStep(name string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Steps = append(t.Steps, Step{Name: name, Status: StepPending})
	return len(t.Steps) - 1
}

// BeginStep 标记步骤开始
func (t *Task) BeginStep(i int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i >= 0 && i < len(t.Steps) {
		t.Steps[i].Status = StepActive
		t.Message = t.Steps[i].Name
	}
}

// EndStep 标记步骤完成
func (t *Task) EndStep(i int, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i >= 0 && i < len(t.Steps) {
		t.Steps[i].Status = StepDone
		t.Steps[i].Detail = detail
	}
}

// FailStep 标记步骤失败
func (t *Task) FailStep(i int, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i >= 0 && i < len(t.Steps) {
		t.Steps[i].Status = StepFailed
		t.Steps[i].Detail = detail
	}
}

// SkipStep 标记步骤跳过
func (t *Task) SkipStep(i int, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i >= 0 && i < len(t.Steps) {
		t.Steps[i].Status = StepSkipped
		t.Steps[i].Detail = detail
	}
}

// Log 追加一行日志
func (t *Task) Log(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	line := fmt.Sprintf("%s  %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	t.Logs = append(t.Logs, line)
	// 安装日志可能很长，只保留末尾 800 行，前端轮询足够看
	if len(t.Logs) > 800 {
		t.Logs = t.Logs[len(t.Logs)-800:]
	}
}

// SetMessage 更新当前进度描述
func (t *Task) SetMessage(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Message = fmt.Sprintf(format, args...)
}

// SetResult 记录结构化结果（如面板地址、账号）
func (t *Task) SetResult(k string, v any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Result == nil {
		t.Result = map[string]any{}
	}
	t.Result[k] = v
}

// Finish 结束任务
func (t *Task) Finish(status, msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.EndedAt = &now
	t.Status = status
	t.Message = msg
	t.Logs = append(t.Logs, fmt.Sprintf("%s  %s", now.Format("15:04:05"), msg))
}

// Snapshot 返回快照
func (t *Task) Snapshot() View {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := View{
		ID:        t.ID,
		Kind:      t.Kind,
		Status:    t.Status,
		Message:   t.Message,
		Steps:     append([]Step(nil), t.Steps...),
		Logs:      append([]string(nil), t.Logs...),
		StartedAt: t.StartedAt,
		EndedAt:   t.EndedAt,
	}
	if t.Result != nil {
		v.Result = make(map[string]any, len(t.Result))
		for k, val := range t.Result {
			v.Result[k] = val
		}
	}
	return v
}

// Manager 任务表
type Manager struct {
	mu   sync.RWMutex
	jobs map[string]*Task
}

func NewManager() *Manager {
	return &Manager{jobs: map[string]*Task{}}
}

// Create 新建任务
func (m *Manager) Create(kind string) *Task {
	t := &Task{
		ID:        store.NewID(),
		Kind:      kind,
		Status:    Running,
		StartedAt: time.Now(),
	}
	m.mu.Lock()
	m.jobs[t.ID] = t
	m.mu.Unlock()
	go m.gc()
	return t
}

func (m *Manager) Get(id string) *Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.jobs[id]
}

// Running 指定类型的任务是否正在执行
func (m *Manager) Running(kind string) *Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.jobs {
		t.mu.Lock()
		ok := t.Kind == kind && t.Status == Running
		t.mu.Unlock()
		if ok {
			return t
		}
	}
	return nil
}

// AnyRunning 正在执行的任务数
func (m *Manager) AnyRunning() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, t := range m.jobs {
		t.mu.Lock()
		if t.Status == Running {
			n++
		}
		t.mu.Unlock()
	}
	return n
}

// List 按开始时间倒序返回
func (m *Manager) List(limit int) []View {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]View, 0, len(m.jobs))
	for _, t := range m.jobs {
		out = append(out, t.Snapshot())
	}
	sort.Slice(out, func(i, k int) bool { return out[i].StartedAt.After(out[k].StartedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// gc 清理 6 小时前结束的任务
func (m *Manager) gc() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cut := time.Now().Add(-6 * time.Hour)
	for id, t := range m.jobs {
		t.mu.Lock()
		ended := t.EndedAt
		t.mu.Unlock()
		if ended != nil && ended.Before(cut) {
			delete(m.jobs, id)
		}
	}
}
