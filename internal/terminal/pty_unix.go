//go:build linux || darwin || freebsd || openbsd || netbsd

package terminal

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// startPTY 在伪终端里启动登录 shell
func startPTY(shell string, cols, rows uint16) (*os.File, *exec.Cmd, error) {
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-l")
	// 以 root 运行时落到 /root；非 root 运行时 /root 不可读，退回 /
	dir := "/root"
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		dir = "/"
	}
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"LANG=C.UTF-8",
		// 让程序识别出自己是交互式终端
		"PS1=\\u@\\h:\\w\\$ ",
	)
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, nil, err
	}
	return f, cmd, nil
}

func resizePTY(f *os.File, cols, rows uint16) error {
	return pty.Setsize(f, &pty.Winsize{Cols: cols, Rows: rows})
}
