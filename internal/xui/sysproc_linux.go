//go:build linux

package xui

import (
	"os/exec"
	"syscall"
)

// setProcessGroup 让安装脚本独占一个进程组，超时时整组杀掉，
// 避免残留的 curl/tar 子进程继续跑。
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
