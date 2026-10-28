package web

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"certpilot/internal/xui"
)

// handleXuiState 返回本机 3x-ui 现状，用于页面顶部状态卡
func (s *Server) handleXuiState(w http.ResponseWriter, r *http.Request) {
	st := xui.Detect()
	running := s.xuiTasks.Running("install")
	out := map[string]any{
		"state":        st,
		"supported":    runtime.GOOS == "linux",
		"installing":   running != nil,
		"defaults":     xui.DefaultOptions(),
		"listen":       s.getSet().Listen,
		"compat":       s.det.Get(),
		"recentTasks":  s.xuiTasks.List(5),
		"scriptSource": "https://github.com/MHSanaei/3x-ui",
	}
	if running != nil {
		out["currentTask"] = running.Snapshot()
	}
	writeJSON(w, 200, out)
}

// handleXuiInstall 启动安装任务，立即返回任务 ID，前端轮询进度
func (s *Server) handleXuiInstall(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "linux" {
		writeErr(w, 400, "仅支持在 Linux 上安装 3x-ui")
		return
	}
	var opts xui.InstallOptions
	if !readJSON(w, r, &opts) {
		return
	}
	if err := opts.Validate(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 同步预检：已安装但没勾「覆盖安装」时直接告诉用户，不让他等一个注定失败的任务
	if cur := xui.Detect(); cur.Installed && !opts.Force {
		ver := cur.Version
		if ver == "" {
			ver = "已安装版本"
		} else {
			ver = "v" + strings.TrimPrefix(ver, "v")
		}
		writeErr(w, 400, fmt.Sprintf("本机已安装 3x-ui（%s），如需升级或重装请勾选「覆盖安装」", ver))
		return
	}
	if t := s.xuiTasks.Running("install"); t != nil {
		writeErr(w, 409, "已有安装任务在执行，请等待完成")
		return
	}
	// 两个请求同时进来时上面的检查可能都通过，用 TryLock 兜住
	if !s.xuiMu.TryLock() {
		writeErr(w, 409, "已有安装任务在执行，请等待完成")
		return
	}

	t := s.xuiTasks.Create("install")
	if opts.Port > 0 {
		t.Log("目标：3x-ui %s，面板端口 %d，SSL 模式 %s", orAuto(opts.Version), opts.Port, opts.SSLMode)
	} else {
		t.Log("目标：3x-ui %s，沿用现有面板端口，SSL 模式 %s", orAuto(opts.Version), opts.SSLMode)
	}
	s.st.AddEvent("", "info", "开始安装 3x-ui")

	// 不能用 r.Context()：请求返回后会被取消，安装必须继续跑
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	go func() {
		defer cancel()
		defer s.xuiMu.Unlock()
		if err := s.xuiInst.Run(ctx, opts, t); err != nil {
			s.st.AddEvent("", "error", "3x-ui 安装失败: "+err.Error())
			return
		}
		s.st.AddEvent("", "info", "3x-ui 安装完成")
		// 装完立刻刷新兼容性探测，界面马上能看到 3x-ui
		s.det.Refresh()
	}()

	writeJSON(w, 200, map[string]any{"ok": true, "taskId": t.ID})
}

func (s *Server) handleXuiTaskList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.xuiTasks.List(20))
}

func (s *Server) handleXuiTask(w http.ResponseWriter, r *http.Request) {
	t := s.xuiTasks.Get(r.PathValue("id"))
	if t == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	writeJSON(w, 200, t.Snapshot())
}

func orAuto(v string) string {
	if v == "" {
		return "最新稳定版"
	}
	return v
}
