//go:build !(linux || darwin || freebsd || openbsd || netbsd)

package terminal

import (
	"os"
	"os/exec"
)

// startPTY 非 Unix 平台没有 PTY 支持。Windows 上若要支持需引入 ConPTY，
// 而本程序的目标环境是 Linux VPS，这里直接拒绝。
func startPTY(shell string, cols, rows uint16) (*os.File, *exec.Cmd, error) {
	return nil, nil, ErrUnsupported
}

func resizePTY(f *os.File, cols, rows uint16) error {
	return ErrUnsupported
}
