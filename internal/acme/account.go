package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"certpilot/internal/store"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// acmeUser 实现 lego 要求的 registration.User 接口
type acmeUser struct {
	Email string
	Key   crypto.PrivateKey
	Reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.Key }

// KeyTypeFromString 把界面上的字符串映射到 lego 的密钥类型
func KeyTypeFromString(s string) certcrypto.KeyType {
	switch s {
	case "ec384":
		return certcrypto.EC384
	case "rsa2048":
		return certcrypto.RSA2048
	case "rsa4096":
		return certcrypto.RSA4096
	default:
		return certcrypto.EC256
	}
}

// generateAccountKey 生成 ACME 账号私钥（ECDSA P-256，体积小、握手快）
func generateAccountKey() (crypto.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return key, pemStr, nil
}

func parseAccountKey(pemStr string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("账号私钥格式错误")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析账号私钥失败: %w", err)
	}
	return key, nil
}

// ClientOptions 创建 ACME 客户端的参数
type ClientOptions struct {
	CAID    string
	Email   string
	KeyType string
	EABKID  string
	EABHMAC string
	Timeout time.Duration
	// DisableCommonName IP 证书必须置空 CN，否则 CA 会拒绝（RFC 8738）
	DisableCommonName bool
}

// newClient 加载（或注册）指定 CA 的账号，返回可用的 lego 客户端
func (m *Manager) newClient(opt ClientOptions) (*lego.Client, error) {
	ca, ok := GetCA(opt.CAID)
	if !ok {
		return nil, fmt.Errorf("未知的 CA: %s", opt.CAID)
	}
	email := opt.Email
	if email == "" {
		email = m.settings().ACMEEmail
	}
	if email == "" {
		return nil, fmt.Errorf("请先在设置里填写 ACME 联系邮箱")
	}

	acc, err := m.st.GetAccount(ca.ID)
	if err != nil {
		return nil, err
	}

	var user *acmeUser
	if acc == nil {
		key, pemStr, err := generateAccountKey()
		if err != nil {
			return nil, err
		}
		user = &acmeUser{Email: email, Key: key}
		acc = &store.Account{CA: ca.ID, Email: email, KeyPEM: pemStr}
	} else {
		key, err := parseAccountKey(acc.KeyPEM)
		if err != nil {
			return nil, err
		}
		user = &acmeUser{Email: acc.Email, Key: key}
		if acc.Registration != "" {
			var reg registration.Resource
			if err := json.Unmarshal([]byte(acc.Registration), &reg); err == nil {
				user.Reg = &reg
			}
		}
	}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = ca.DirectoryURL
	cfg.Certificate.KeyType = KeyTypeFromString(opt.KeyType)
	cfg.Certificate.Timeout = 120 * time.Second
	if opt.Timeout > 0 {
		cfg.Certificate.Timeout = opt.Timeout
	}
	if opt.DisableCommonName {
		cfg.Certificate.DisableCommonName = true
	}
	cfg.UserAgent = "certpilot/1.0"

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("连接 CA 失败（%s）: %w", ca.Name, err)
	}

	if user.Reg != nil {
		// 已有账号：向 CA 确认一次，避免账号被删后仍用旧 KID
		if reg, err := client.Registration.ResolveAccountByKey(); err == nil {
			user.Reg = reg
		}
	}

	if user.Reg == nil {
		if err := m.register(client, user, ca, opt); err != nil {
			return nil, err
		}
	}

	regJSON, _ := json.Marshal(user.Reg)
	acc.Registration = string(regJSON)
	acc.Email = user.Email
	if err := m.st.PutAccount(acc); err != nil {
		return nil, err
	}
	return client, nil
}

func (m *Manager) register(client *lego.Client, user *acmeUser, ca CA, opt ClientOptions) error {
	if ca.RequiresEAB {
		kid, hmac := opt.EABKID, opt.EABHMAC
		if kid == "" || hmac == "" {
			if cred, ok := m.settings().EAB[ca.ID]; ok {
				kid, hmac = cred.KID, cred.HMAC
			}
		}
		if kid == "" || hmac == "" {
			if ca.EABAuto {
				k, h, err := FetchZeroSSLEAB(user.Email)
				if err != nil {
					return err
				}
				kid, hmac = k, h
			} else {
				return fmt.Errorf("%s 要求提供 EAB 凭据（KID 与 HMAC），请在证书配置里填写", ca.Name)
			}
		}
		reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  kid,
			HmacEncoded:          hmac,
		})
		if err != nil {
			return fmt.Errorf("注册 %s 账号失败: %w", ca.Name, err)
		}
		user.Reg = reg
		return nil
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("注册 %s 账号失败: %w", ca.Name, err)
	}
	user.Reg = reg
	return nil
}
