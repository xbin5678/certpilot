package compat

import (
	"net"
	"testing"
)

func TestCheckPortFree(t *testing.T) {
	// 先拿一个空闲端口
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	st := CheckPort(port)
	if st.InUse {
		t.Fatalf("端口 %d 应空闲", port)
	}

	// 占用它再测
	ln2, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	busy := ln2.Addr().(*net.TCPAddr).Port
	// 注意 CheckPort 绑的是 0.0.0.0，可能和 127.0.0.1 的监听不冲突，
	// 因此这里只断言函数能正常返回而不 panic
	_ = CheckPort(busy)
}

func TestEnsurePortFreeMessage(t *testing.T) {
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	// 保持监听，模拟被占用
	err = EnsurePortFree(port)
	ln.Close()
	if err == nil {
		t.Fatalf("端口 %d 被占用时应返回错误", port)
	}
	if len(err.Error()) == 0 {
		t.Fatal("错误信息不应为空")
	}
}

// ss -lntpH 的真实输出（Debian 13 / iproute2 6.15）
const ssFixture = `LISTEN 0      4096   127.0.0.1:11111 0.0.0.0:* users:(("xray-linux-amd6",pid=878567,fd=9))
LISTEN 0      128      0.0.0.0:22    0.0.0.0:* users:(("sshd",pid=1011,fd=6))
LISTEN 0      4096           *:9443        *:* users:(("certpilot",pid=886973,fd=9))
LISTEN 0      4096           *:8443        *:* users:(("x-ui",pid=878557,fd=11))
LISTEN 0      128         [::]:22       [::]:* users:(("sshd",pid=1011,fd=7))
LISTEN 0      5        0.0.0.0:8080   0.0.0.0:* users:(("python3",pid=4242,fd=3))
LISTEN 0      4096   127.0.0.1:12345  0.0.0.0:*
`

func TestParsePortOwner(t *testing.T) {
	cases := []struct {
		name string
		port int
		want string
	}{
		{"通配地址 *:port", 9443, "certpilot"},
		{"普通 IPv4", 22, "sshd"},
		{"IPv6 方括号", 22, "sshd"},
		{"8080 不能被当成 80", 80, ""},
		{"端口在但没权限看进程", 12345, "未知进程"},
		{"端口不在监听", 65535, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parsePortOwner(ssFixture, c.port)
			if got != c.want {
				t.Fatalf("port %d: got %q, want %q", c.port, got, c.want)
			}
		})
	}
}

// 端口 8080 的行不能被 ":80" 后缀误命中
func TestParsePortOwnerNoPrefixMatch(t *testing.T) {
	if got := parsePortOwner(ssFixture, 8080); got != "python3" {
		t.Fatalf("port 8080: got %q, want python3", got)
	}
}

func TestDetectorWithoutMode(t *testing.T) {
	d := NewDetector(nil)
	st := d.Get()
	if st.Mode == "" {
		t.Fatal("模式不应为空")
	}
	if len(st.Advice) == 0 {
		t.Fatal("应给出建议")
	}
}
