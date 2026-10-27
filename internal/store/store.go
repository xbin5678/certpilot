package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store 基于 SQLite 的持久层
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  domains TEXT NOT NULL,
  ca TEXT NOT NULL,
  key_type TEXT NOT NULL,
  challenge TEXT NOT NULL,
  webroot TEXT NOT NULL DEFAULT '',
  challenge_port INTEGER NOT NULL DEFAULT 0,
  dns_provider TEXT NOT NULL DEFAULT '',
  dns_credentials TEXT NOT NULL DEFAULT '{}',
  auto_renew INTEGER NOT NULL DEFAULT 1,
  renew_before_days INTEGER NOT NULL DEFAULT 30,
  deploy_cert_path TEXT NOT NULL DEFAULT '',
  deploy_key_path TEXT NOT NULL DEFAULT '',
  deploy_cmd TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  not_before TEXT NOT NULL DEFAULT '',
  not_after TEXT NOT NULL DEFAULT '',
  serial TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  last_issued_at TEXT NOT NULL DEFAULT '',
  last_attempt_at TEXT NOT NULL DEFAULT '',
  fail_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  ca TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  registration TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  cert_id TEXT NOT NULL DEFAULT '',
  level TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
`

// Open 打开（不存在则创建）数据库
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(8000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化表结构失败: %w", err)
	}
	return &Store{db: db}, nil
}

// OpenReadOnly 只读打开（用于探测 3x-ui 的数据库，绝不写入）
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB { return s.db }

// ---------- settings ----------

func (s *Store) GetSetting(k string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM settings WHERE k = ?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO settings(k, v) VALUES(?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

// LoadSettings 读取全部设置，缺省项用默认值补齐
func (s *Store) LoadSettings() (Settings, error) {
	st := DefaultSettings()
	rows, err := s.db.Query(`SELECT k, v FROM settings`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return st, err
		}
		switch k {
		case "adminPasswordHash":
			st.AdminPasswordHash = v
		case "listen":
			st.Listen = v
		case "acmeEmail":
			st.ACMEEmail = v
		case "defaultCa":
			st.DefaultCA = v
		case "defaultKeyType":
			st.DefaultKeyType = v
		case "defaultRenewDays":
			fmt.Sscanf(v, "%d", &st.DefaultRenewDays)
		case "compat3xui":
			st.Compat3XUI = v
		case "compatCertDir":
			st.CompatCertDir = v
		case "webhookUrl":
			st.WebhookURL = v
		case "telegramToken":
			st.TelegramToken = v
		case "telegramChatId":
			st.TelegramChatID = v
		case "notifyOnRenew":
			st.NotifyOnRenew = v == "1" || v == "true"
		case "notifyOnError":
			st.NotifyOnError = v == "1" || v == "true"
		case "sessionSecret":
			st.SessionSecret = v
		case "eab":
			var m map[string]EABCred
			if json.Unmarshal([]byte(v), &m) == nil {
				st.EAB = m
			}
		}
	}
	return st, rows.Err()
}

// SaveSettings 全量写回
func (s *Store) SaveSettings(st Settings) error {
	kv := map[string]string{
		"adminPasswordHash": st.AdminPasswordHash,
		"listen":            st.Listen,
		"acmeEmail":         st.ACMEEmail,
		"defaultCa":         st.DefaultCA,
		"defaultKeyType":    st.DefaultKeyType,
		"defaultRenewDays":  fmt.Sprintf("%d", st.DefaultRenewDays),
		"compat3xui":        st.Compat3XUI,
		"compatCertDir":     st.CompatCertDir,
		"webhookUrl":        st.WebhookURL,
		"telegramToken":     st.TelegramToken,
		"telegramChatId":    st.TelegramChatID,
		"sessionSecret":     st.SessionSecret,
	}
	kv["notifyOnRenew"] = boolStr(st.NotifyOnRenew)
	kv["notifyOnError"] = boolStr(st.NotifyOnError)
	if st.EAB != nil {
		b, _ := json.Marshal(st.EAB)
		kv["eab"] = string(b)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range kv {
		if _, err := tx.Exec(`INSERT INTO settings(k, v) VALUES(?, ?)
			ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ---------- certs ----------

const certCols = `id, name, domains, ca, key_type, challenge, webroot, challenge_port,
 dns_provider, dns_credentials, auto_renew, renew_before_days,
 deploy_cert_path, deploy_key_path, deploy_cmd, status, not_before, not_after,
 serial, last_error, last_issued_at, last_attempt_at, fail_count, created_at, updated_at`

func scanCert(sc interface{ Scan(...any) error }) (*Cert, error) {
	c := &Cert{}
	var domains, dnsCred string
	var autoRenew int
	err := sc.Scan(&c.ID, &c.Name, &domains, &c.CA, &c.KeyType, &c.Challenge,
		&c.Webroot, &c.ChallengePort, &c.DNSProvider, &dnsCred, &autoRenew,
		&c.RenewBeforeDays, &c.DeployCertPath, &c.DeployKeyPath, &c.DeployCmd,
		&c.Status, &c.NotBefore, &c.NotAfter, &c.Serial, &c.LastError,
		&c.LastIssuedAt, &c.LastAttemptAt, &c.FailCount, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c.Domains = DecodeStrings(domains)
	c.DNSCredentials = DecodeMap(dnsCred)
	c.AutoRenew = autoRenew == 1
	return c, nil
}

func (s *Store) ListCerts() ([]*Cert, error) {
	rows, err := s.db.Query(`SELECT ` + certCols + ` FROM certs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCert(id string) (*Cert, error) {
	row := s.db.QueryRow(`SELECT `+certCols+` FROM certs WHERE id = ?`, id)
	c, err := scanCert(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *Store) PutCert(c *Cert) error {
	c.UpdatedAt = time.Now().Format(time.RFC3339)
	if c.CreatedAt == "" {
		c.CreatedAt = c.UpdatedAt
	}
	_, err := s.db.Exec(`INSERT INTO certs(`+certCols+`)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		  name=excluded.name, domains=excluded.domains, ca=excluded.ca,
		  key_type=excluded.key_type, challenge=excluded.challenge,
		  webroot=excluded.webroot, challenge_port=excluded.challenge_port,
		  dns_provider=excluded.dns_provider, dns_credentials=excluded.dns_credentials,
		  auto_renew=excluded.auto_renew, renew_before_days=excluded.renew_before_days,
		  deploy_cert_path=excluded.deploy_cert_path, deploy_key_path=excluded.deploy_key_path,
		  deploy_cmd=excluded.deploy_cmd, status=excluded.status,
		  not_before=excluded.not_before, not_after=excluded.not_after,
		  serial=excluded.serial, last_error=excluded.last_error,
		  last_issued_at=excluded.last_issued_at, last_attempt_at=excluded.last_attempt_at,
		  fail_count=excluded.fail_count, updated_at=excluded.updated_at`,
		c.ID, c.Name, EncodeStrings(c.Domains), c.CA, c.KeyType, c.Challenge,
		c.Webroot, c.ChallengePort, c.DNSProvider, EncodeMap(c.DNSCredentials),
		boolInt(c.AutoRenew), c.RenewBeforeDays, c.DeployCertPath, c.DeployKeyPath,
		c.DeployCmd, c.Status, c.NotBefore, c.NotAfter, c.Serial, c.LastError,
		c.LastIssuedAt, c.LastAttemptAt, c.FailCount, c.CreatedAt, c.UpdatedAt)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) DeleteCert(id string) error {
	_, err := s.db.Exec(`DELETE FROM certs WHERE id = ?`, id)
	return err
}

// ---------- accounts ----------

func (s *Store) GetAccount(ca string) (*Account, error) {
	a := &Account{}
	err := s.db.QueryRow(`SELECT ca, email, key_pem, registration, updated_at
		FROM accounts WHERE ca = ?`, ca).Scan(&a.CA, &a.Email, &a.KeyPEM, &a.Registration, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (s *Store) PutAccount(a *Account) error {
	a.UpdatedAt = time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO accounts(ca, email, key_pem, registration, updated_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(ca) DO UPDATE SET email=excluded.email, key_pem=excluded.key_pem,
		  registration=excluded.registration, updated_at=excluded.updated_at`,
		a.CA, a.Email, a.KeyPEM, a.Registration, a.UpdatedAt)
	return err
}

// ---------- events ----------

func (s *Store) AddEvent(certID, level, msg string) {
	_, _ = s.db.Exec(`INSERT INTO events(ts, cert_id, level, message) VALUES(?,?,?,?)`,
		time.Now().Format(time.RFC3339), certID, level, msg)
	// 只保留最近 2000 条
	_, _ = s.db.Exec(`DELETE FROM events WHERE id NOT IN
		(SELECT id FROM events ORDER BY id DESC LIMIT 2000)`)
}

func (s *Store) ListEvents(limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, ts, cert_id, level, message FROM events
		ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.CertID, &e.Level, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountByStatus 概览统计
func (s *Store) CountByStatus() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT status, COUNT(*) FROM certs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[strings.TrimSpace(k)] = n
	}
	return out, rows.Err()
}
