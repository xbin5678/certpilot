package xui

import (
	"strings"
	"testing"
)

func TestValidatePort(t *testing.T) {
	base := InstallOptions{Port: 2053, Username: "admin", Password: "12345678", SSLMode: "none"}

	cases := []struct {
		name string
		mod  func(*InstallOptions)
		want bool
	}{
		{"默认参数通过", func(o *InstallOptions) {}, true},
		{"端口为 0", func(o *InstallOptions) { o.Port = 0 }, false},
		{"端口越界", func(o *InstallOptions) { o.Port = 70000 }, false},
		{"占用 80", func(o *InstallOptions) { o.Port = 80 }, false},
		{"占用 443", func(o *InstallOptions) { o.Port = 443 }, false},
		{"用户名过短", func(o *InstallOptions) { o.Username = "ab" }, false},
		{"密码过短", func(o *InstallOptions) { o.Password = "123" }, false},
		{"空 SSL 归一化为 none", func(o *InstallOptions) { o.SSLMode = "" }, true},
		{"域名模式缺域名", func(o *InstallOptions) { o.SSLMode = "domain" }, false},
		{"域名模式带域名", func(o *InstallOptions) { o.SSLMode = "domain"; o.Domain = "a.com" }, true},
		{"未知 SSL 模式", func(o *InstallOptions) { o.SSLMode = "self" }, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := base
			c.mod(&o)
			err := o.Validate()
			if (err == nil) != c.want {
				t.Fatalf("期望通过=%v，实际 err=%v", c.want, err)
			}
		})
	}
}

func TestValidateNormalizesEmptySSLMode(t *testing.T) {
	o := InstallOptions{Port: 2053, Username: "admin", Password: "12345678"}
	if err := o.Validate(); err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if o.SSLMode != "none" {
		t.Fatalf("空 SSLMode 应归一化为 none，实际 %q", o.SSLMode)
	}
}

// 重装已有实例时，官方脚本会保留原有端口与账号密码，
// 因此这两个字段留空是合法的，不能被校验拦下。
func TestValidateReinstallWithoutCredentials(t *testing.T) {
	o := InstallOptions{Force: true, SSLMode: "none"}
	if err := o.Validate(); err != nil {
		t.Fatalf("重装且沿用现有配置时不应报错: %v", err)
	}
	// 但没勾覆盖安装、端口又是 0，就必须报错
	o2 := InstallOptions{Port: 0, Username: "admin", Password: "12345678", SSLMode: "none"}
	if err := o2.Validate(); err == nil {
		t.Fatal("新装时端口为 0 应报错")
	}
}

func TestRandomPassword(t *testing.T) {
	a, b := RandomPassword(), RandomPassword()
	if len(a) != 16 {
		t.Fatalf("密码长度应为 16，实际 %d", len(a))
	}
	if a == b {
		t.Fatal("两次生成的密码不应相同")
	}
	for _, r := range a {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", r) {
			t.Fatalf("密码含非法字符 %q", r)
		}
	}
}

func TestCleanANSI(t *testing.T) {
	cases := map[string]string{
		"\x1b[32m成功\x1b[0m":       "成功",
		"\x1b[1;31m错误\x1b[m":      "错误",
		"普通文本":                     "普通文本",
		"\r\n进度 50%\r":             "\n进度 50%",
		"\x1b]0;标题\x07正文":         "正文",
	}
	for in, want := range cases {
		if got := cleanANSI(in); got != want {
			t.Errorf("cleanANSI(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestDefaultOptions(t *testing.T) {
	d := DefaultOptions()
	if d.Port != 2053 {
		t.Fatalf("默认端口应为 2053，实际 %d", d.Port)
	}
	if d.SSLMode != "none" {
		t.Fatalf("默认 SSL 应为 none，实际 %q", d.SSLMode)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("默认参数应通过校验: %v", err)
	}
}
