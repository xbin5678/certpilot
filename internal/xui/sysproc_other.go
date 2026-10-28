//go:build !linux

package xui

import "os/exec"

// setProcessGroup 非 Linux 平台不需要进程组处理（也不支持安装 3x-ui）。
func setProcessGroup(cmd *exec.Cmd) {}
