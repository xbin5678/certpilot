# CertPilot

多域名、多 CA、多验证方式的免费证书申请与自动续期服务。单个 Go 二进制，自带 Web 管理后台，可与 3x-ui 共存而不抢端口。

![证书列表](docs/screenshots/03-certs.png)

## 它解决什么问题

3x-ui 的面板只能绑定一组证书（`webCertFile` / `webKeyFile`），菜单里的签发流程一次只处理一个域名；更麻烦的是它用 `acme.sh --standalone --httpport 80` 签发，**不会主动避让端口**，80 被占用时直接失败，而续期失败是静默的——证书到期了才发现。

CertPilot 把证书管理从面板里独立出来：

- 一个界面管理任意多张证书，每张可绑定不同域名、不同 CA、不同验证方式
- 默认走 DNS-01，**完全不占用任何端口**，与 xray/nginx 零冲突
- 需要 HTTP 验证时，优先用 Webroot 复用已有的 80，而不是抢占它
- 签发前做端口预检，冲突时直接给出可执行的替代方案，而不是让你等 CA 报错
- 到期前自动续期，失败退避重试并推送通知

## 核心设计：为什么不会抢端口

证书验证有三种方式，占用的端口完全不同。**选哪种由客户端决定，跟证书商无关**：

| 验证方式 | 需要端口 | 与 3x-ui 共存 | 说明 |
|---|---|---|---|
| `dns-01` | 不占端口 | 完全无冲突 | 通过 DNS API 写 TXT，推荐 |
| `dns-01-manual` | 不占端口 | 完全无冲突 | 界面给出 TXT，人工添加，自动轮询生效 |
| `http-01-webroot` | 复用 80 | 无冲突 | 复用 nginx/caddy 的站点目录 |
| `http-01-standalone` | 独占 80 | 80 空闲时可用 | 签发时临时占用数秒 |
| `tls-alpn-01` | 独占 443 | 与 xray 冲突 | 仅在 443 空闲时使用 |

> 注意：443 不参与 HTTP-01 验证。Let's Encrypt 官方规定 HTTP-01 **只能走 80**，TLS-ALPN-01 **只能走 443**，DNS-01 只查 DNS。所以"443 被 xray 占着"本身不影响签发。

签发前会自动预检：

- standalone / alpn 会先尝试监听目标端口，被占用则直接报错并给出替代方案
- webroot 会检查目录存在、可写
- DNS 会检查必填凭据

## 功能

**证书**
- 多域名 / 通配符 / SAN，单张证书最多 100 个域名
- CA：Let's Encrypt（含 staging）、ZeroSSL、Buypass、Google Trust Services
- 密钥：ECDSA P-256/P-384、RSA 2048/4096
- 签发、续期、吊销、下载（fullchain / privkey / cert / chain）
- 列表里每张证书都有**自动续订开关**：打开则到期前自动续期，关闭则只保留手动续期
- 每行都有**删除**按钮，二次确认后才会执行；只删本程序的记录与存储文件，不动已部署到 `/root/cert/` 的副本
- 证书链、SAN、序列号、剩余天数可视化
- 自动续期窗口可调（默认提前 30 天），失败按 30 分钟 × 次数退避，最多 6 小时

**验证方式**
- DNS 自动：Cloudflare、阿里云、DNSPod、华为云
- DNS 手动：任何 DNS 服务商，界面展示 TXT 记录，自动轮询生效（最长 20 分钟）
- HTTP Webroot：复用现有 Web 服务，零中断
- HTTP 独立监听：临时占用 80
- TLS-ALPN-01：独占 443（会提示与 xray 的冲突）

**证书路径页**
- 每张证书的实际文件路径集中展示，一键复制
- 自动解析 `{domain}` 占位符，直接给出绝对路径（如 `/root/cert/a.com/fullchain.pem`）
- 标注文件是否已生成，并提供 `x-ui cert -webCert ... -webCertKey ...` 命令一键复制
- 未配置部署路径的证书可一键设为 3x-ui 约定路径，并立即写入
- 支持「立即重新部署」，不用等下次续期

**部署**
- 签发成功后原子写入目标路径（先校验证书与私钥配对，不匹配拒绝落盘）
- 支持 `{domain}` 占位符
- 可执行重载命令，例如 `x-ui restart`
- 一键填入 3x-ui 预设：`/root/cert/{domain}/fullchain.pem` + `privkey.pem` + `x-ui restart`

**3x-ui 兼容模式**
- 运行时探测，不做启动期强依赖——3x-ui 可以装在本程序之前，也可以之后
- 每 45 秒自动探测一次，识别后立即生效，无需重启
- 探测项：可执行文件、`/etc/x-ui/x-ui.db`、systemd 单元、服务状态、面板当前证书路径
- 只读方式读取 3x-ui 的数据库，**绝不写入**
- 输出针对当前端口占用情况的具体建议

**其他**
- 单管理员密码（bcrypt）、HttpOnly 会话、CSRF 头校验
- Webhook / Telegram 通知
- 全量操作日志
- 命令行：`serve` / `doctor` / `issue` / `list`

## 安装

### 方式一：一条命令（在线）

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | sudo bash
```

带参数安装（端口、管理员密码、ACME 邮箱）：

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh \
  | sudo bash -s -- --port 9443 --password 'YourPass123' --email you@example.com
```

### 方式二：离线包

把 `certpilot-offline-amd64.tar.gz` 上传到服务器：

```bash
tar xzf certpilot-offline-amd64.tar.gz
cd bundle
sudo ./install.sh --password 'YourPass123'
```

脚本会优先使用同目录下的 `certpilot` 二进制，不需要联网。

### 低配 VPS：按需启动（默认）

默认安装为 **systemd socket 激活**模式，待机时**没有任何常驻进程**：

| 状态 | 内存占用 | 说明 |
|---|---|---|
| 待机（无人访问） | **0 MB** | 进程已退出，只有 systemd 持有监听端口 |
| 打开网页时 | ~18-22 MB | 首次连接自动拉起，实测 168ms 响应 |
| 空闲 10 分钟后 | 0 MB | 自动退出，下次访问再拉起 |
| 证书续期 | ~20 MB / 4 秒 | systemd 定时器每天跑 4 次，跑完立即退出 |

续期不再依赖常驻进程：`certpilot-renew.timer` 每 6 小时调用一次 `certpilot renew`，检查到期证书、续期、退出。

想改回常驻模式：

```bash
sudo ./install.sh --mode always
```

调整空闲退出时间：

```bash
sudo ./install.sh --idle 30m
```

按需模式下，端口由 `certpilot.socket` 持有，管理入口是 socket 而不是 service：

```bash
systemctl status certpilot.socket      # 看监听状态（即使没有进程也在监听）
systemctl restart certpilot.socket     # 重启（连带重启服务）
systemctl stop certpilot.socket        # 完全停止（连带停进程、释放端口）
systemctl list-timers certpilot-renew.timer
```

服务单元带 `BindsTo=certpilot.socket`，所以停 socket 会同步停进程，不会出现"进程还在、socket 却起不来"的僵局。

> 注意：`systemctl restart certpilot` 在按需模式下没有监听套接字可继承，会直接退出，请操作 `certpilot.socket`。

### 安装脚本做了什么

1. 校验 root 权限与 systemd，识别 `amd64` / `arm64`
2. 优先使用脚本同目录的二进制，否则从 GitHub Release 下载对应架构
3. 安装到 `/usr/local/bin/certpilot`
4. 创建数据目录 `/etc/certpilot`（权限 0750）
5. 生成 systemd 单元、设置开机自启、启动服务
6. 调用 `/api/health` 做健康检查
7. 如果传了 `--password` / `--email`，自动完成管理员初始化

全程无外部依赖：二进制是静态编译的，不需要装 Go、不需要数据库、不需要 Docker。

### 常用命令

| 操作 | 命令 |
|---|---|
| 升级到最新版 | `sudo ./install.sh` |
| 切换按需/常驻 | `sudo ./install.sh --mode ondemand` / `--mode always` |
| 改端口重装 | `sudo ./install.sh --port 8080` |
| 卸载（保留证书与配置） | `sudo ./install.sh --uninstall` |
| 彻底卸载（连数据一起删） | `sudo ./install.sh --purge` |
| 查看状态 | `systemctl status certpilot` |
| 实时日志 | `journalctl -u certpilot -f` |
| 环境体检 | `certpilot doctor` |

`--uninstall` 只删除服务与二进制，`/etc/certpilot` 里的证书和配置会保留；`--purge` 才会连数据一起删除。

### 发布自己的版本

把 `install.sh` 里的 `__REPO__` 换成 `你的用户名/certpilot`（或用 `--repo owner/repo` 指定），然后打 tag：

```bash
git tag v1.0.0 && git push --tags
```

GitHub Actions 会自动跑测试、构建 `amd64` 与 `arm64` 两个包，并把 `install.sh`、`uninstall.sh` 一起发布到 Release。

本地构建同样可用：

```bash
make release   # dist/certpilot-linux-{amd64,arm64}.tar.gz
make bundle    # dist/certpilot-offline-amd64.tar.gz（离线包）
```

### 源码运行

```bash
go build -o certpilot .
sudo ./certpilot serve -data ./data -listen :8443
```

## 命令行

```bash
certpilot serve   [-listen :8443] [-data DIR] \
                  [-tls-cert fullchain.pem] [-tls-key privkey.pem]   启动 Web 后台（带 TLS 参数则启用 HTTPS）
certpilot doctor  [-data DIR]                     体检
certpilot list    [-data DIR]                     列出证书
certpilot version

certpilot issue -domain a.com,www.a.com \
  -ca letsencrypt -challenge dns-01 \
  -dns-provider cloudflare \
  -dns-cred CLOUDFLARE_DNS_API_TOKEN=xxx \
  -email you@example.com \
  -deploy-cert /root/cert/{domain}/fullchain.pem \
  -deploy-key  /root/cert/{domain}/privkey.pem \
  -deploy-cmd  "x-ui restart"
```

`issue` 适合放进 CI 或一次性脚本；日常用 Web 界面即可。

## 面板自身启用 HTTPS（支持多张证书）

用本程序签出的证书给自己加 TLS。可以同时挂多张，按 SNI 自动选择，证书续期后自动重载，无需重启：

```bash
certpilot serve -data /etc/certpilot -listen :9443 \
  -tls-cert /root/cert/a.example.com/fullchain.pem,/root/cert/203.0.113.10/fullchain.pem \
  -tls-key  /root/cert/a.example.com/privkey.pem,/root/cert/203.0.113.10/privkey.pem
```

访问 `https://a.example.com:9443` 用域名证书，访问 `https://203.0.113.10:9443` 用 IP 证书，两者都校验通过。

## IP 证书

没有域名也能签发：Let's Encrypt 支持为公网 IP 签发短期证书（约 6 天，自动续期）。

- 程序检测到域名是 IP 时，自动使用 `shortlived` profile，并自动置空 CSR 的 CN（RFC 8738 要求）
- 验证方式只能是 HTTP-01 或 TLS-ALPN-01，DNS-01 对 IP 不可用，程序会在预检阶段直接拦下
- 续期窗口按证书有效期自动收敛（有效期的 1/3 封顶），避免 6 天证书套用 30 天窗口导致无限续期

```bash
certpilot issue -domain 203.0.113.10 -challenge http-01-standalone -email you@example.com
```

## 3x-ui 共存实践

**推荐拓扑**

```
80  → nginx（常驻，只做 ACME webroot 与 301）
443 → xray（所有节点）
8443 → certpilot 面板
```

- 证书全部走 `dns-01`，或 `http-01-webroot` 指向 nginx 站点根目录
- 部署目标填 `/root/cert/{domain}/`，重载命令填 `x-ui restart`
- 面板证书变化才重启 3x-ui；纯入站证书可以不重启（xray 读取文件路径）

**如果 3x-ui 是后装的**

不用做任何事。CertPilot 每 45 秒探测一次，识别到之后「环境与兼容」页面会出现面板证书路径与针对性建议，部署预设也会自动可用。

**如果 80 被 xray fallback 占着**

不要用 standalone。选 `dns-01` 或 `dns-01-manual`，一行端口都不碰。

## 配置

配置存在 `<数据目录>/certpilot.db`（SQLite），包括：

| 项 | 说明 |
|---|---|
| `acmeEmail` | ACME 账号邮箱 |
| `defaultCa` / `defaultKeyType` / `defaultRenewDays` | 新建证书默认值 |
| `compat3xui` | `auto` / `on` / `off` |
| `compatCertDir` | 3x-ui 证书目录前缀，默认 `/root/cert` |
| `webhookUrl` / `telegramToken` / `telegramChatId` | 通知 |
| `eab` | 各 CA 的外部账号绑定凭据（ZeroSSL 可用邮箱自动获取） |

证书文件存放在 `<数据目录>/certs/<证书ID>/`：`fullchain.pem`、`privkey.pem`、`cert.pem`、`chain.pem`、`meta.json`。

## HTTP API

全部接口位于 `/api`，需要会话 Cookie；写操作需带 `X-Requested-With: certpilot`。

```
GET    /api/session              登录状态 / 是否首次使用
POST   /api/setup                首次设置密码
POST   /api/login  /api/logout
GET    /api/overview             概览（含兼容性状态）
GET    /api/certs                列表
POST   /api/certs                创建（issueNow 可直接签发）
GET    /api/certs/{id}           详情
PUT    /api/certs/{id}           修改
DELETE /api/certs/{id}           删除
POST   /api/certs/{id}/issue     签发
POST   /api/certs/{id}/renew     续期
POST   /api/certs/{id}/revoke    吊销
GET    /api/certs/{id}/download?file=fullchain|privkey|cert|chain
GET    /api/certs/{id}/inspect   解析证书内容
GET    /api/jobs  /api/jobs/{id} 任务进度（含待添加的 TXT 记录）
GET    /api/settings  PUT /api/settings
GET    /api/cas  /api/dnsproviders  /api/compat  /api/events
POST   /api/check                立即执行一轮续期检查
```

## 目录结构

```
main.go                  CLI 入口
internal/acme/           ACME 客户端、CA 目录、DNS provider、任务
internal/store/          SQLite 持久层
internal/compat/         3x-ui 探测与端口守卫
internal/deploy/         原子写入与重载
internal/scheduler/      自动续期调度
internal/notify/         Webhook / Telegram
internal/web/            HTTP 服务与内嵌前端
deploy/                  systemd 单元与安装脚本
```

## 关于数据安全

程序**不会自动删除任何证书记录**。删除只有一条路径：界面上点「删除」并二次确认（对应 `DELETE /api/certs/{id}`）。签发失败只会把状态标为「失败」并保留记录，不会清理。

## 安全说明

- 面板默认只监听 `:8443`，建议放在内网或用 nginx 加 TLS
- 首次访问必须设置密码，密码 bcrypt 存储
- 会话 Cookie 为 HttpOnly + SameSite=Lax；HTTPS 下自动加 Secure
- 所有写接口校验 `X-Requested-With`，配合 SameSite 抵御 CSRF
- DNS API 凭据存在本地 SQLite，请确保数据目录权限为 `0750`
- 建议使用最小权限的 DNS Token（如 Cloudflare 只给 Zone:DNS:Edit）

## 开发

```bash
go test ./...          # 单元测试
go vet ./...
go build -o certpilot .
```

跨平台构建见 `Makefile`。

## 许可证

MIT
