package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"certpilot/internal/store"
)

// selfSigned 生成一对自签证书用于测试
func selfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestVerify(t *testing.T) {
	certPEM, keyPEM := selfSigned(t, "a.com")
	if err := Verify(Files{FullChain: certPEM, PrivKey: keyPEM}); err != nil {
		t.Fatalf("合法证书校验失败: %v", err)
	}

	_, otherKey := selfSigned(t, "b.com")
	if err := Verify(Files{FullChain: certPEM, PrivKey: otherKey}); err == nil {
		t.Fatal("私钥不匹配时应报错")
	}
	if err := Verify(Files{}); err == nil {
		t.Fatal("空内容应报错")
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "cert.pem")
	if err := WriteAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "hello" {
		t.Fatalf("写入内容不对: %v %s", err, b)
	}
	// 覆盖写
	if err := WriteAtomic(path, []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if string(b) != "world" {
		t.Fatalf("覆盖写失败: %s", b)
	}
}

func TestApplyWritesFiles(t *testing.T) {
	certPEM, keyPEM := selfSigned(t, "a.com")
	dir := t.TempDir()

	c := &store.Cert{
		ID:             "x",
		Domains:        []string{"a.com"},
		DeployCertPath: filepath.Join(dir, "{domain}", "fullchain.pem"),
		DeployKeyPath:  filepath.Join(dir, "{domain}", "privkey.pem"),
	}
	res, err := Apply(c, Files{FullChain: certPEM, PrivKey: keyPEM})
	if err != nil {
		t.Fatalf("部署失败: %v", err)
	}
	if len(res.Paths) != 2 {
		t.Fatalf("期望写入 2 个文件，实际 %d", len(res.Paths))
	}
	if _, err := os.Stat(filepath.Join(dir, "a.com", "fullchain.pem")); err != nil {
		t.Fatal("证书未写入")
	}
	if _, err := os.Stat(filepath.Join(dir, "a.com", "privkey.pem")); err != nil {
		t.Fatal("私钥未写入")
	}
}

func TestApplyRejectsMismatch(t *testing.T) {
	certPEM, _ := selfSigned(t, "a.com")
	_, otherKey := selfSigned(t, "b.com")
	c := &store.Cert{ID: "x", Domains: []string{"a.com"},
		DeployCertPath: filepath.Join(t.TempDir(), "c.pem")}
	if _, err := Apply(c, Files{FullChain: certPEM, PrivKey: otherKey}); err == nil {
		t.Fatal("证书与私钥不匹配时必须拒绝写入")
	}
}
