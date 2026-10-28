package web

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// CertPair 一组证书与私钥
type CertPair struct {
	CertFile string
	KeyFile  string
}

type certEntry struct {
	cert  *tls.Certificate
	leaf  *x509.Certificate
	mtime time.Time
}

// MultiCertReloader 支持同时挂多张证书，按 SNI 自动选择，并在文件变化时热加载。
// 这样面板既可以用域名证书访问，也可以用 IP 证书访问，互不影响。
func MultiCertReloader(pairs []CertPair) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var (
		mu      sync.Mutex
		entries = make([]*certEntry, len(pairs))
	)

	load := func(i int) *certEntry {
		p := pairs[i]
		fi, err := os.Stat(p.CertFile)
		if err != nil {
			return entries[i]
		}
		if entries[i] != nil && !fi.ModTime().After(entries[i].mtime) {
			return entries[i]
		}
		cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			// 新证书有问题时继续用旧的，避免面板直接不可用
			return entries[i]
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return entries[i]
		}
		cert.Leaf = leaf
		entries[i] = &certEntry{cert: &cert, leaf: leaf, mtime: fi.ModTime()}
		return entries[i]
	}

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()

		for i := range pairs {
			load(i)
		}

		name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
		if name != "" {
			// 优先精确匹配
			for _, e := range entries {
				if e == nil {
					continue
				}
				for _, n := range e.leaf.DNSNames {
					if strings.EqualFold(n, name) {
						return e.cert, nil
					}
				}
				if strings.EqualFold(e.leaf.Subject.CommonName, name) {
					return e.cert, nil
				}
			}
			// 再尝试通配符
			for _, e := range entries {
				if e == nil {
					continue
				}
				for _, n := range e.leaf.DNSNames {
					if !strings.HasPrefix(n, "*.") {
						continue
					}
					suffix := strings.ToLower(n[1:]) // ".example.com"
					if !strings.HasSuffix(name, suffix) {
						continue
					}
					// 通配符只匹配一级：a.example.com 命中，a.b.example.com 不命中。
					// 之前用「点数相等」来比较，但 name 比 suffix 多一个 label，
					// 点数永远不等，导致通配符证书永远匹配不上。
					if !strings.Contains(strings.TrimSuffix(name, suffix), ".") {
						return e.cert, nil
					}
				}
			}
		} else {
			// 没有 SNI（直接用 IP 访问）：优先返回带 IP SAN 的证书
			for _, e := range entries {
				if e == nil {
					continue
				}
				if len(e.leaf.IPAddresses) > 0 {
					return e.cert, nil
				}
			}
		}

		// 兜底：第一张可用的证书
		for _, e := range entries {
			if e != nil {
				return e.cert, nil
			}
		}
		return nil, fmt.Errorf("没有可用的证书")
	}
}

// ParseCertPairs 解析逗号分隔的证书/私钥路径
func ParseCertPairs(certs, keys string) ([]CertPair, error) {
	cs := splitList(certs)
	ks := splitList(keys)
	if len(cs) == 0 && len(ks) == 0 {
		return nil, nil // 两个都没给 = 不启用 HTTPS
	}
	// 只给一边属于配置错误。之前直接返回 nil,nil，结果是面板静默降级成
	// 明文 HTTP —— 用户以为开了 HTTPS，其实密码在裸奔。
	if len(cs) == 0 || len(ks) == 0 {
		return nil, fmt.Errorf("证书与私钥必须同时提供（证书 %d 个，私钥 %d 个）", len(cs), len(ks))
	}
	if len(cs) != len(ks) {
		return nil, fmt.Errorf("证书与私钥数量不一致：%d vs %d", len(cs), len(ks))
	}
	out := make([]CertPair, 0, len(cs))
	for i := range cs {
		out = append(out, CertPair{CertFile: cs[i], KeyFile: ks[i]})
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
