package task

import (
	"strings"
	"testing"
)

func TestTaskStepsAndLogs(t *testing.T) {
	m := NewManager()
	tk := m.Create("install")

	i := tk.AddStep("环境检查")
	tk.BeginStep(i)
	if v := tk.Snapshot(); v.Steps[i].Status != StepActive {
		t.Fatalf("步骤状态应为 running，实际 %s", v.Steps[i].Status)
	}
	tk.EndStep(i, "通过")
	tk.Log("下载完成")
	tk.SetResult("url", "https://x")

	v := tk.Snapshot()
	if v.Steps[i].Status != StepDone || v.Steps[i].Detail != "通过" {
		t.Fatalf("步骤未正确完成: %+v", v.Steps[i])
	}
	if len(v.Logs) != 1 || !strings.Contains(v.Logs[0], "下载完成") {
		t.Fatalf("日志不正确: %v", v.Logs)
	}
	if v.Result["url"] != "https://x" {
		t.Fatalf("结果未写入: %v", v.Result)
	}
}

func TestFailStepAndFinish(t *testing.T) {
	m := NewManager()
	tk := m.Create("install")
	i := tk.AddStep("执行安装")
	tk.BeginStep(i)
	tk.FailStep(i, "脚本退出码 1")
	tk.Finish(Error, "安装失败")

	v := tk.Snapshot()
	if v.Steps[i].Status != StepFailed {
		t.Fatalf("步骤应为 error，实际 %s", v.Steps[i].Status)
	}
	if v.Status != Error || v.EndedAt == nil {
		t.Fatalf("任务未正确结束: %+v", v)
	}
	if m.AnyRunning() != 0 {
		t.Fatal("已结束的任务不应计入 running")
	}
}

func TestRunningDedup(t *testing.T) {
	m := NewManager()
	a := m.Create("install")
	if got := m.Running("install"); got == nil || got.ID != a.ID {
		t.Fatal("应能找到正在执行的任务")
	}
	if m.Running("other") != nil {
		t.Fatal("不同类型不应命中")
	}
	a.Finish(Success, "完成")
	if m.Running("install") != nil {
		t.Fatal("结束后不应再返回运行中任务")
	}
}

func TestSnapshotIsCopy(t *testing.T) {
	m := NewManager()
	tk := m.Create("install")
	tk.AddStep("步骤")
	tk.Log("一行")

	v := tk.Snapshot()
	v.Steps[0].Name = "被改掉了"
	v.Logs[0] = "被改掉了"

	again := tk.Snapshot()
	if again.Steps[0].Name != "步骤" {
		t.Fatal("快照的步骤应与内部状态隔离")
	}
	if again.Logs[0] == "被改掉了" {
		t.Fatal("快照的日志应与内部状态隔离")
	}
}

func TestLogRingBuffer(t *testing.T) {
	m := NewManager()
	tk := m.Create("install")
	for i := 0; i < 900; i++ {
		tk.Log("第 %d 行", i)
	}
	v := tk.Snapshot()
	if len(v.Logs) != 800 {
		t.Fatalf("日志应被截断到 800 行，实际 %d", len(v.Logs))
	}
	if !strings.Contains(v.Logs[len(v.Logs)-1], "第 899 行") {
		t.Fatalf("应保留最新日志，实际末尾 %q", v.Logs[len(v.Logs)-1])
	}
}

func TestListOrder(t *testing.T) {
	m := NewManager()
	a := m.Create("install")
	b := m.Create("install")
	b.StartedAt = a.StartedAt.Add(1e9)
	list := m.List(10)
	if len(list) != 2 || list[0].ID != b.ID {
		t.Fatalf("列表应按开始时间倒序: %+v", list)
	}
}
