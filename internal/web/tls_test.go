package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert 生成一张自签名证书并写盘，返回 (certPath, keyPath)
func writeTestCert(t *testing.T, dir, name string, dnsNames []string, ips []net.IP) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestMultiCertReloaderExactMatch(t *testing.T) {
	dir := t.TempDir()
	cp1, kp1 := writeTestCert(t, dir, "example", []string{"example.com", "www.example.com"}, nil)
	cp2, kp2 := writeTestCert(t, dir, "other", []string{"other.net"}, nil)

	cb := MultiCertReloader([]CertPair{{cp1, kp1}, {cp2, kp2}})

	got, err := cb(&tls.ClientHelloInfo{ServerName: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf == nil || got.Leaf.Subject.CommonName != "example" {
		t.Fatalf("精确匹配选错了证书: %+v", got.Leaf)
	}

	got, _ = cb(&tls.ClientHelloInfo{ServerName: "OTHER.NET"})
	if got.Leaf.Subject.CommonName != "other" {
		t.Fatalf("大小写不敏感匹配失败，实际 %s", got.Leaf.Subject.CommonName)
	}

	// 末尾带点的 FQDN 也要能匹配
	got, _ = cb(&tls.ClientHelloInfo{ServerName: "example.com."})
	if got.Leaf.Subject.CommonName != "example" {
		t.Fatalf("带尾点的域名匹配失败，实际 %s", got.Leaf.Subject.CommonName)
	}
}

// 通配符只匹配一级。之前用「点数相等」比较，name 比 suffix 永远多一个 label，
// 导致通配符证书一次都没命中过。
func TestMultiCertReloaderWildcard(t *testing.T) {
	dir := t.TempDir()
	wc, wk := writeTestCert(t, dir, "wild", []string{"*.example.com"}, nil)
	ipc, ipk := writeTestCert(t, dir, "ipcert", nil, []net.IP{net.ParseIP("203.0.113.9")})

	cb := MultiCertReloader([]CertPair{{ipc, ipk}, {wc, wk}})

	// 一级子域：命中通配符
	got, err := cb(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.Subject.CommonName != "wild" {
		t.Fatalf("*.example.com 应匹配 api.example.com，实际选了 %s", got.Leaf.Subject.CommonName)
	}

	// 二级子域：不该命中通配符，应兜底到第一张（IP 证书）
	got, _ = cb(&tls.ClientHelloInfo{ServerName: "a.b.example.com"})
	if got.Leaf.Subject.CommonName == "wild" {
		t.Fatal("*.example.com 不应匹配 a.b.example.com")
	}

	// 完全无关的域名：兜底
	got, _ = cb(&tls.ClientHelloInfo{ServerName: "nope.org"})
	if got == nil {
		t.Fatal("无匹配时应兜底返回一张证书")
	}
}

// 直接用 IP 访问时浏览器不发 SNI，应优先挑带 IP SAN 的证书
func TestMultiCertReloaderNoSNIPrefersIPCert(t *testing.T) {
	dir := t.TempDir()
	dc, dk := writeTestCert(t, dir, "domain", []string{"example.com"}, nil)
	ic, ik := writeTestCert(t, dir, "ipcert", nil, []net.IP{net.ParseIP("198.51.100.7")})

	cb := MultiCertReloader([]CertPair{{dc, dk}, {ic, ik}})
	got, err := cb(&tls.ClientHelloInfo{ServerName: ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Leaf.IPAddresses) == 0 {
		t.Fatal("无 SNI 时应优先返回带 IP SAN 的证书")
	}
}

func TestMultiCertReloaderMissingFile(t *testing.T) {
	cb := MultiCertReloader([]CertPair{{"/nonexistent/a.crt", "/nonexistent/a.key"}})
	if _, err := cb(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Fatal("证书文件不存在时应返回错误")
	}
}

func TestParseCertPairs(t *testing.T) {
	// 都为空 → 不启用 TLS
	if p, err := ParseCertPairs("", ""); err != nil || p != nil {
		t.Fatalf("空参数应返回 nil,nil，实际 %v %v", p, err)
	}

	p, err := ParseCertPairs(" /a.crt , /b.crt ", "/a.key,/b.key")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 2 || p[0].CertFile != "/a.crt" || p[1].KeyFile != "/b.key" {
		t.Fatalf("解析结果不对: %+v", p)
	}

	if _, err := ParseCertPairs("/a.crt,/b.crt", "/a.key"); err == nil {
		t.Fatal("数量不一致时应报错")
	}

	// 只给了一边也属于配置错误
	if _, err := ParseCertPairs("/a.crt", ""); err == nil {
		t.Fatal("只提供证书没有私钥时应报错")
	}
	if _, err := ParseCertPairs("", "/a.key"); err == nil {
		t.Fatal("只提供私钥没有证书时应报错")
	}
}
