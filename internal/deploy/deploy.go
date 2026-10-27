package deploy

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"certpilot/internal/store"
)

// Files 一次签发产出的全部文件内容
type Files struct {
	FullChain []byte // 叶子证书 + 中间证书
	PrivKey   []byte
	Chain     []byte
	Cert      []byte
}

// Result 部署结果
type Result struct {
	Paths  []string `json:"paths"`
	Output string   `json:"output"`
}

// Verify 校验证书与私钥是否配对，避免把错误文件写到生产路径
func Verify(f Files) error {
	if len(f.FullChain) == 0 || len(f.PrivKey) == 0 {
		return fmt.Errorf("证书或私钥为空")
	}
	if _, err := tls.X509KeyPair(f.FullChain, f.PrivKey); err != nil {
		return fmt.Errorf("证书与私钥不匹配，已拒绝写入: %w", err)
	}
	return nil
}

// WriteAtomic 原子写入，避免服务读到写了一半的文件
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建目录 %s 失败: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".certpilot-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Resolve 把配置里的路径模板解析成实际路径（导出给界面展示用）
func Resolve(tpl, domain string) string { return expand(tpl, domain) }

// expand 支持 {domain} 占位符和环境变量
func expand(s, domain string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "{domain}", domain)
	return os.ExpandEnv(s)
}

// Apply 把证书写到用户配置的目标路径，并执行重载命令
func Apply(c *store.Cert, f Files) (Result, error) {
	var res Result
	if err := Verify(f); err != nil {
		return res, err
	}

	domain := c.PrimaryDomain()
	certPath := expand(c.DeployCertPath, domain)
	keyPath := expand(c.DeployKeyPath, domain)

	if certPath != "" {
		if err := WriteAtomic(certPath, f.FullChain, 0o644); err != nil {
			return res, fmt.Errorf("写入证书 %s 失败: %w", certPath, err)
		}
		res.Paths = append(res.Paths, certPath)
	}
	if keyPath != "" {
		if err := WriteAtomic(keyPath, f.PrivKey, 0o600); err != nil {
			return res, fmt.Errorf("写入私钥 %s 失败: %w", keyPath, err)
		}
		res.Paths = append(res.Paths, keyPath)
	}

	cmdStr := expand(c.DeployCmd, domain)
	if cmdStr != "" {
		out, err := RunShell(cmdStr, 90*time.Second)
		res.Output = strings.TrimSpace(out)
		if err != nil {
			return res, fmt.Errorf("重载命令执行失败: %w\n输出: %s", err, truncate(out, 500))
		}
	}
	return res, nil
}

// RunShell 执行一条 shell 命令并返回合并输出
func RunShell(cmdStr string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", cmdStr)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
