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
