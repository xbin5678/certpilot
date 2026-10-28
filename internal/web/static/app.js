'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const state = {
  view: 'overview',
  certs: [],
  compat: null,
  settings: null,
  cas: [],
  providers: [],
  jobTimer: null,
};

const STATUS = {
  pending: ['未签发', 'plain'],
  issuing: ['进行中', 'info'],
  valid: ['有效', 'ok'],
  expiring: ['即将到期', 'warn'],
  expired: ['已过期', 'bad'],
  error: ['失败', 'bad'],
  revoked: ['已吊销', 'plain'],
};

const CHALLENGE_LABEL = {
  'dns-01': 'DNS-01 自动',
  'dns-01-manual': 'DNS-01 手动',
  'http-01-webroot': 'HTTP-01 Webroot',
  'http-01-standalone': 'HTTP-01 独立监听',
  'tls-alpn-01': 'TLS-ALPN-01',
};

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function toast(msg, kind) {
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || '');
  el.textContent = msg;
  $('#toast-root').appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

async function api(path, opts = {}) {
  const o = Object.assign({}, opts);
  o.headers = Object.assign({
    'Content-Type': 'application/json',
    'X-Requested-With': 'certpilot',
  }, opts.headers || {});
  const res = await fetch('/api' + path, o);
  if (res.status === 401) {
    showLogin(false);
    throw new Error('登录已失效');
  }
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { error: text }; }
  if (!res.ok) throw new Error((data && data.error) || ('HTTP ' + res.status));
  return data;
}

function daysLeft(iso) {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (isNaN(t)) return null;
  return Math.floor((t - Date.now()) / 86400000);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
    ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

/* ---------------- 登录 ---------------- */

function showLogin(needSetup) {
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#boot').hidden = true;
  $('#login-title').textContent = needSetup ? '初始化 CertPilot' : '登录 CertPilot';
  $('#login-sub').textContent = needSetup ? '首次使用，请设置管理密码' : '请输入管理密码';
  $('#email-field').hidden = !needSetup;
  $('#login-btn').textContent = needSetup ? '创建并进入' : '登录';
  $('#login-form').dataset.setup = needSetup ? '1' : '';
  setTimeout(() => $('#login-password').focus(), 60);
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const setup = $('#login-form').dataset.setup === '1';
  const password = $('#login-password').value;
  const email = $('#login-email').value;
  $('#login-err').textContent = '';
  $('#login-btn').disabled = true;
  try {
    await api(setup ? '/setup' : '/login', {
      method: 'POST',
      body: JSON.stringify({ password, email }),
    });
    $('#login-password').value = '';
    $('#login').hidden = true;
    await boot();
  } catch (err) {
    $('#login-err').textContent = err.message;
  } finally {
    $('#login-btn').disabled = false;
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
  location.reload();
});

/* ---------------- 导航 ---------------- */

$$('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

function switchView(v) {
  // 离开终端页必须销毁 PTY 连接，否则 shell 会一直挂在服务器上
  if (state.view === 'terminal' && v !== 'terminal') termDispose();
  // 离开 3x-ui 页停止进度轮询
  if (v !== 'xui' && state.xuiTimer) { clearTimeout(state.xuiTimer); state.xuiTimer = null; }
  state.view = v;
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === v));
  const titles = {
    overview: ['概览', '证书状态一览'],
    certs: ['证书', '申请、续期与部署'],
    paths: ['证书路径', '复制后填入 3x-ui 的证书设置'],
    xui: ['3x-ui', '一键安装面板，与证书自动衔接'],
    compat: ['环境与兼容', '端口占用与 3x-ui 共存状态'],
    terminal: ['终端', '在浏览器里直接操作这台服务器'],
    logs: ['日志', '最近的签发与变更记录'],
    settings: ['设置', 'ACME 账号、默认值与通知'],
  };
  $('#page-title').textContent = titles[v][0];
  $('#page-sub').textContent = titles[v][1];
  $('#topbar-actions').innerHTML = '';
  render();
}

function render() {
  if (state.view === 'overview') renderOverview();
  else if (state.view === 'certs') renderCerts();
  else if (state.view === 'paths') renderPaths();
  else if (state.view === 'xui') renderXui();
  else if (state.view === 'compat') renderCompat();
  else if (state.view === 'terminal') renderTerminal();
  else if (state.view === 'logs') renderLogs();
  else if (state.view === 'settings') renderSettings();
}

/* ---------------- 概览 ---------------- */

async function renderOverview() {
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  let data;
  try { data = await api('/overview'); } catch (e) { $('#content').innerHTML = errBox(e); return; }
  state.certs = data.certs || [];
  state.compat = data.compat;
  $('#ver').textContent = 'v' + data.version;

  const stats = data.stats || {};
  const valid = (stats.valid || 0) + (stats.expiring || 0);
  const bad = (stats.error || 0) + (stats.expired || 0);
  const c = data.compat || {};

  $('#topbar-actions').innerHTML =
    '<button class="btn primary" onclick="openCertForm()">+ 新建证书</button>';

  let html = '<div class="grid c4">';
  html += statCard('证书总数', data.total || 0, '含未签发', '');
  html += statCard('有效', valid, '正常服务中', 'ok');
  html += statCard('30 天内到期', data.expiringSoon || 0, '自动续期会处理', 'warn');
  html += statCard('异常', bad, '需人工介入', 'bad');
  html += '</div>';

  html += '<div class="section-title">环境</div><div class="grid c2">';
  html += '<div class="card"><h3>3x-ui 兼容</h3>';
  if (c.installed) {
    html += '<p class="sub" style="margin:0 0 10px">已检测到 3x-ui' +
      (c.serviceActive ? '，服务运行中' : '，服务未运行') + '</p>';
    html += '<dl class="kv"><dt>面板证书</dt><dd class="mono">' + esc(c.panelCert || '未配置') + '</dd>' +
      '<dt>面板私钥</dt><dd class="mono">' + esc(c.panelKey || '未配置') + '</dd></dl>';
  } else {
    html += '<p class="sub" style="margin:0 0 8px">本机未检测到 3x-ui。</p>' +
      '<p class="sub" style="margin:0">不影响使用；之后安装 3x-ui 会被自动识别，无需重启本程序。</p>';
  }
  html += '</div>';

  html += '<div class="card"><h3>端口</h3><dl class="kv">' +
    '<dt>80</dt><dd>' + portBadge(c.port80) + '</dd>' +
    '<dt>443</dt><dd>' + portBadge(c.port443) + '</dd>' +
    '</dl><p class="sub" style="margin:12px 0 0">DNS-01 验证不占用任何端口，是与 3x-ui 共存最稳的方式。</p></div>';
  html += '</div>';

  html += '<div class="section-title">最近任务</div>';
  const jobs = data.jobs || [];
  if (!jobs.length) {
    html += '<div class="card"><div class="empty">暂无任务记录</div></div>';
  } else {
    html += '<div class="table-wrap"><table><thead><tr><th>证书</th><th>动作</th><th>状态</th><th>开始时间</th><th></th></tr></thead><tbody>';
    jobs.forEach(j => {
      const c2 = state.certs.find(x => x.id === j.certId);
      html += '<tr><td>' + esc(c2 ? c2.name : j.certId) + '</td>' +
        '<td>' + esc(j.action) + '</td>' +
        '<td>' + jobPill(j.status) + '</td>' +
        '<td class="mono">' + fmtDate(j.startedAt) + '</td>' +
        '<td class="row-actions"><button class="btn sm ghost" onclick="openJob(\'' + j.id + '\')">查看</button></td></tr>';
    });
    html += '</tbody></table></div>';
  }

  $('#content').innerHTML = html;
}

function autoRenewSwitch(c) {
  const on = !!c.autoRenew;
  return '<label class="sw" title="' + (on ? '已开启：到期前自动续期' : '已关闭：不会自动续期') + '">' +
    '<input type="checkbox"' + (on ? ' checked' : '') +
    ' onchange="toggleAutoRenew(\'' + c.id + '\', this.checked)"><i></i>' +
    '<em>' + (on ? '开' : '关') + '</em></label>';
}

async function toggleAutoRenew(id, on) {
  try {
    await api('/certs/' + id, { method: 'PUT', body: JSON.stringify({ autoRenew: on }) });
    const c = state.certs.find(x => x.id === id);
    if (c) c.autoRenew = on;
    toast(on ? '已开启自动续订' : '已关闭自动续订，到期需手动续期', 'ok');
    render();
  } catch (e) {
    toast(e.message, 'bad');
    render();
  }
}

function statCard(k, v, d, cls) {
  return '<div class="card stat ' + cls + '"><div class="k">' + k + '</div><div class="v">' + v + '</div><div class="d">' + d + '</div></div>';
}

function portBadge(p) {
  if (!p) return '<span class="pill plain">未知</span>';
  if (!p.inUse) return '<span class="pill ok">空闲</span>';
  return '<span class="pill warn">' + esc(p.owner || '被占用') + '</span>';
}

function jobPill(s) {
  if (s === 'running') return '<span class="pill info">进行中</span>';
  if (s === 'success') return '<span class="pill ok">成功</span>';
  return '<span class="pill bad">失败</span>';
}

function errBox(e) {
  return '<div class="card"><div class="empty">加载失败：' + esc(e.message) + '</div></div>';
}

/* ---------------- 证书列表 ---------------- */

async function renderCerts() {
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  let certs;
  try { certs = await api('/certs'); } catch (e) { $('#content').innerHTML = errBox(e); return; }
  state.certs = certs;
  $('#topbar-actions').innerHTML =
    '<button class="btn" onclick="checkNow()">立即检查续期</button>' +
    '<button class="btn primary" onclick="openCertForm()">+ 新建证书</button>';

  if (!certs.length) {
    $('#content').innerHTML =
      '<div class="card"><div class="empty"><div class="big">▤</div>' +
      '还没有证书<br><br><button class="btn primary" onclick="openCertForm()">申请第一张证书</button></div></div>';
    return;
  }

  let html = '<div class="table-wrap"><table><thead><tr>' +
    '<th>名称 / 域名</th><th>状态</th><th>到期</th><th>自动续订</th><th>验证方式</th><th>CA</th><th></th>' +
    '</tr></thead><tbody>';

  certs.forEach(c => {
    const st = STATUS[c.status] || ['未知', 'plain'];
    const dl = daysLeft(c.notAfter);
    let expiry = '<span class="sub">—</span>';
    if (dl !== null) {
      const cls = dl < 0 ? 'bad' : dl <= 14 ? 'warn' : 'ok';
      expiry = '<span class="pill ' + cls + '">' + dl + ' 天</span>' +
        '<div class="d2" style="font-size:11.5px;color:var(--faint)">' + fmtDate(c.notAfter) + '</div>';
    }
    html += '<tr>' +
      '<td><div class="domains"><div class="d1">' + esc(c.name || c.domains[0]) + '</div>' +
      '<div class="d2 mono">' + esc(c.domains.join(', ')) + '</div></div></td>' +
      '<td><span class="pill ' + st[1] + '">' + st[0] + '</span></td>' +
      '<td>' + expiry + '</td>' +
      '<td>' + autoRenewSwitch(c) + '</td>' +
      '<td><span class="tag">' + esc(CHALLENGE_LABEL[c.challenge] || c.challenge) + '</span></td>' +
      '<td class="mono">' + esc(c.ca) + '</td>' +
      '<td><div class="row-actions">' +
      '<button class="btn sm" onclick="openDetail(\'' + c.id + '\')">详情</button>' +
      '<button class="btn sm primary" onclick="issueCert(\'' + c.id + '\',\'' + (c.notAfter ? 'renew' : 'issue') + '\')">' +
      (c.notAfter ? '续期' : '签发') + '</button>' +
      '<button class="btn sm danger" onclick="deleteCert(\'' + c.id + '\',\'' + esc(c.name || c.domains[0]) + '\')">删除</button>' +
      '</div></td></tr>';
  });
  html += '</tbody></table></div>';
  $('#content').innerHTML = html;
}

/* ---------------- 证书路径 ---------------- */

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e2) { /* ignore */ }
    ta.remove();
  }
  toast((label || '内容') + ' 已复制', 'ok');
}

function pathRow(label, value, exists, copyLabel) {
  return '<div class="pathrow">' +
    '<span class="lbl">' + label + '</span>' +
    '<code class="pathbox">' + esc(value) + '</code>' +
    (exists ? '<span class="pill ok">存在</span>' : '<span class="pill bad">未生成</span>') +
    '<button class="btn sm" onclick="copyText(\'' + esc(value).replace(/'/g, "\\'") + '\',\'' + (copyLabel || label) + '\')">复制</button>' +
    '</div>';
}

async function renderPaths() {
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  let list;
  try { list = await api('/paths'); } catch (e) { $('#content').innerHTML = errBox(e); return; }
  $('#topbar-actions').innerHTML = '<button class="btn" onclick="renderPaths()">刷新</button>';

  if (!list.length) {
    $('#content').innerHTML = '<div class="card"><div class="empty">还没有证书<br><br>' +
      '<button class="btn primary" onclick="openCertForm()">去申请</button></div></div>';
    return;
  }

  let html = '<p class="hint" style="margin:0 0 16px">' +
    '把下面两行路径分别填到 3x-ui 的<b>面板设置 → 证书文件 / 私钥文件</b>，' +
    '或者入站的 <b>TLS 设置 → certificateFile / keyFile</b>。' +
    '证书续期后路径不变，3x-ui 会读到新文件。</p>';

  list.forEach(v => {
    const st = STATUS[v.status] || ['未知', 'plain'];
    html += '<div class="card" style="margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px">' +
      '<div><div style="font-weight:500">' + esc(v.name) + ' <span class="pill ' + st[1] + '" style="margin-left:6px">' + st[0] + '</span></div>' +
      '<div class="mono" style="font-size:11.5px;color:var(--faint);margin-top:3px">' + esc(v.domains.join(', ')) +
      (v.notAfter ? ' · 到期 ' + fmtDate(v.notAfter) : '') + '</div></div>' +
      '<div style="display:flex;gap:6px">' +
      '<button class="btn sm" onclick="copyText(\'' + esc(v.certPath) + '\\n' + esc(v.keyPath) + '\',\'两行路径\')">复制两行</button>' +
      '</div></div>';

    html += pathRow('证书文件', v.certPath, v.certExists, '证书路径');
    html += pathRow('私钥文件', v.keyPath, v.keyExists, '私钥路径');

    html += '<div class="pathrow" style="margin-top:4px">' +
      '<span class="lbl">3x-ui 命令</span>' +
      '<code class="pathbox">' + esc(v.xuiCommand) + '</code>' +
      '<button class="btn sm" onclick="copyText(\'' + esc(v.xuiCommand) + '\',\'命令\')">复制</button>' +
      '</div>';

    if (!v.isDeployed) {
      html += '<div class="pathrow" style="margin-top:6px">' +
        '<span class="lbl"></span>' +
        '<span class="sub" style="flex:1">还没设置部署路径，当前是内部存储路径（可用，但带随机 ID）。建议改成固定路径，续期后不会变。</span>' +
        '<button class="btn sm primary" onclick="setDeployPath(\'' + v.id + '\',\'' + esc(v.primary) + '\')">设为 /root/cert/...</button>' +
        '</div>';
    } else {
      html += '<div class="pathrow" style="margin-top:6px">' +
        '<span class="lbl"></span>' +
        '<span class="sub" style="flex:1">部署路径已配置，续期后会自动覆盖这两个文件。</span>' +
        '<button class="btn sm" onclick="redeploy(\'' + v.id + '\')">立即重新部署</button>' +
        '</div>';
    }
    html += '</div>';
  });

  $('#content').innerHTML = html;
}

async function setDeployPath(id, domain) {
  try {
    await api('/certs/' + id, {
      method: 'PUT',
      body: JSON.stringify({
        deployCertPath: '/root/cert/' + domain + '/fullchain.pem',
        deployKeyPath: '/root/cert/' + domain + '/privkey.pem',
      }),
    });
    await api('/certs/' + id + '/deploy', { method: 'POST' });
    toast('已设置并写入 /root/cert/' + domain + '/', 'ok');
    renderPaths();
  } catch (e) { toast(e.message, 'bad'); }
}

async function redeploy(id) {
  try {
    const r = await api('/certs/' + id + '/deploy', { method: 'POST' });
    toast('已写入 ' + (r.paths || []).length + ' 个文件', 'ok');
    renderPaths();
  } catch (e) { toast(e.message, 'bad'); }
}

/* ---------------- 环境 ---------------- */

async function renderCompat() {
  $('#content').innerHTML = '<div class="empty">探测中…</div>';
  let c;
  try { c = await api('/compat'); } catch (e) { $('#content').innerHTML = errBox(e); return; }
  state.compat = c;
  $('#topbar-actions').innerHTML = '<button class="btn" onclick="renderCompat()">重新探测</button>';

  let html = '<div class="grid c2">';
  html += '<div class="card"><h3>3x-ui</h3>';
  if (c.installed) {
    html += '<p><span class="pill ok">已安装</span> ' +
      (c.serviceActive ? '<span class="pill info">服务运行中</span>' : '<span class="pill plain">服务未运行</span>') + '</p>';
    html += '<dl class="kv">';
    c.evidence.forEach(e => { html += '<dt>证据</dt><dd class="mono">' + esc(e) + '</dd>'; });
    if (c.panelCert) {
      html += '<dt>面板证书</dt><dd class="mono">' + esc(c.panelCert) + '</dd>';
      html += '<dt>面板私钥</dt><dd class="mono">' + esc(c.panelKey) + '</dd>';
    }
    html += '</dl>';
  } else {
    html += '<p><span class="pill plain">未检测到</span></p>' +
      '<p class="sub">本程序与 3x-ui 无强依赖。3x-ui 可以在本程序之前或之后安装，' +
      '每 45 秒自动探测一次，识别后兼容选项立即生效。</p>';
  }
  html += '</div>';

  html += '<div class="card"><h3>端口占用</h3><dl class="kv">' +
    '<dt>80</dt><dd>' + portBadge(c.port80) + '</dd>' +
    '<dt>443</dt><dd>' + portBadge(c.port443) + '</dd>' +
    '<dt>探测时间</dt><dd class="mono">' + fmtDate(c.checkedAt) + '</dd>' +
    '</dl></div>';
  html += '</div>';

  html += '<div class="section-title">建议</div><div class="card"><ul class="advice">';
  (c.advice || []).forEach(a => { html += '<li>' + esc(a) + '</li>'; });
  html += '</ul></div>';

  html += '<div class="section-title">验证方式与端口</div><div class="table-wrap"><table>' +
    '<thead><tr><th>方式</th><th>需要的端口</th><th>与 3x-ui 共存</th></tr></thead><tbody>' +
    row3('DNS-01（自动）', '不占端口', 'ok', '推荐，永不冲突') +
    row3('DNS-01（手动）', '不占端口', 'ok', '通用兜底，人工加 TXT') +
    row3('HTTP-01 Webroot', '复用 80', 'ok', '需 80 上有 Web 服务') +
    row3('HTTP-01 独立监听', '独占 80', 'warn', '80 空闲时可用') +
    row3('TLS-ALPN-01', '独占 443', 'bad', '与 xray 冲突，不推荐') +
    '</tbody></table></div>';

  $('#content').innerHTML = html;
}

function row3(name, port, cls, note) {
  return '<tr><td>' + name + '</td><td class="mono">' + port + '</td>' +
    '<td><span class="pill ' + cls + '">' + note + '</span></td></tr>';
}

/* ---------------- 日志 ---------------- */

async function renderLogs() {
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  let ev;
  try { ev = await api('/events?limit=200'); } catch (e) { $('#content').innerHTML = errBox(e); return; }
  if (!ev.length) { $('#content').innerHTML = '<div class="card"><div class="empty">暂无日志</div></div>'; return; }
  let html = '<div class="table-wrap"><table><thead><tr><th>时间</th><th>级别</th><th>内容</th></tr></thead><tbody>';
  ev.forEach(e => {
    const cls = e.level === 'error' ? 'bad' : e.level === 'success' ? 'ok' : e.level === 'warn' ? 'warn' : 'plain';
    html += '<tr><td class="mono" style="white-space:nowrap">' + fmtDate(e.ts) + '</td>' +
      '<td><span class="pill ' + cls + '">' + esc(e.level) + '</span></td>' +
      '<td>' + esc(e.message) + '</td></tr>';
  });
  html += '</tbody></table></div>';
  $('#content').innerHTML = html;
}

/* ---------------- 设置 ---------------- */

async function renderSettings() {
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  try {
    if (!state.cas.length) state.cas = await api('/cas');
    state.settings = await api('/settings');
  } catch (e) { $('#content').innerHTML = errBox(e); return; }
  const s = state.settings;

  let html = '<div class="grid c2">';

  html += '<div class="card"><h3>ACME 账号</h3>' +
    field('联系邮箱', '<input type="email" id="set-email" value="' + esc(s.acmeEmail) + '" placeholder="you@example.com">') +
    '<p class="hint">邮箱用于向 CA 注册账号，Let\'s Encrypt 会在证书即将过期时发送提醒。</p>' +
    '</div>';

  html += '<div class="card"><h3>默认值</h3>' +
    field('默认 CA', '<select id="set-ca">' + state.cas.map(c =>
      '<option value="' + esc(c.id) + '"' + (c.id === s.defaultCa ? ' selected' : '') + '>' + esc(c.name) + '</option>').join('') + '</select>') +
    field('默认密钥类型', '<select id="set-key">' +
      opt('ec256', 'ECDSA P-256（推荐）', s.defaultKeyType) +
      opt('ec384', 'ECDSA P-384', s.defaultKeyType) +
      opt('rsa2048', 'RSA 2048（兼容性最好）', s.defaultKeyType) +
      opt('rsa4096', 'RSA 4096', s.defaultKeyType) + '</select>') +
    field('默认提前续期天数', '<input type="number" id="set-days" min="1" max="89" value="' + (s.defaultRenewDays || 30) + '">') +
    '</div>';

  html += '<div class="card"><h3>3x-ui 兼容</h3>' +
    field('模式', '<select id="set-compat">' +
      opt('auto', '自动（推荐）', s.compat3xui) +
      opt('on', '强制开启', s.compat3xui) +
      opt('off', '关闭', s.compat3xui) + '</select>') +
    field('证书目录前缀', '<input type="text" id="set-certdir" value="' + esc(s.compatCertDir || '/root/cert') + '">') +
    '<p class="hint">兼容模式不会修改 3x-ui 的任何文件。它只做三件事：探测端口占用、在签发前阻止冲突、' +
    '在部署时把证书写到 <b>/root/cert/&lt;域名&gt;/</b> 并执行你指定的重载命令。</p>' +
    '</div>';

  html += '<div class="card"><h3>通知</h3>' +
    field('Webhook 地址', '<input type="text" id="set-webhook" value="' + esc(s.webhookUrl) + '" placeholder="https://...">') +
    field('Telegram Bot Token', '<input type="password" id="set-tgtoken" placeholder="' + (s.hasTelegramToken ? '已设置，留空不修改' : '123456:ABC...') + '">') +
    field('Telegram Chat ID', '<input type="text" id="set-tgchat" value="' + esc(s.telegramChatId) + '">') +
    '<label class="switch"><input type="checkbox" id="set-n-renew"' + (s.notifyOnRenew ? ' checked' : '') + '>续期成功时通知</label>' +
    '<label class="switch" style="margin-top:8px"><input type="checkbox" id="set-n-err"' + (s.notifyOnError ? ' checked' : '') + '>失败时通知</label>' +
    '</div>';

  html += '</div>';

  html += '<div class="section-title">CA 外部账号绑定（EAB）</div><div class="card">' +
    '<p class="hint" style="margin-top:0">ZeroSSL 会尝试用上面的邮箱自动获取；Google Trust Services 必须手动填写。</p>';
  state.cas.filter(c => c.requiresEab).forEach(c => {
    const e = (s.eab && s.eab[c.id]) || {};
    html += '<div class="form-row" style="margin-top:14px"><div class="field"><span>' + esc(c.name) + ' · KID</span>' +
      '<input type="text" id="eab-kid-' + esc(c.id) + '" value="' + esc(e.kid || '') + '"></div>' +
      '<div class="field"><span>' + esc(c.name) + ' · HMAC</span>' +
      '<input type="password" id="eab-hmac-' + esc(c.id) + '" value="' + esc(e.hmac || '') + '"></div></div>';
  });
  html += '</div>';

  html += '<div class="section-title">网页终端</div><div class="card">' +
    '<p class="hint" style="margin-top:0">启用后可以直接在浏览器里操作这台服务器，不用另开 SSH 客户端。' +
    '注意：终端里是 <b>root shell</b>，进入时需要重新输入管理密码，会话空闲会自动断开。' +
    '默认关闭，建议只在需要时临时打开。</p>' +
    '<label class="switch"><input type="checkbox" id="set-term"' + (s.terminalEnabled ? ' checked' : '') + '>启用网页终端</label>' +
    '<div class="form-row" style="margin-top:12px">' +
    '<div class="field"><span>Shell 路径</span><input type="text" id="set-term-shell" value="' + esc(s.terminalShell || '/bin/bash') + '"></div>' +
    '<div class="field"><span>空闲断开（分钟）</span><input type="number" id="set-term-idle" min="1" max="720" value="' + (s.terminalIdleMinutes || 15) + '"></div>' +
    '</div></div>';

  html += '<div class="section-title">安全</div><div class="card">' +
    '<div class="form-row">' +
    '<div class="field"><span>原密码</span><input type="password" id="pw-old"></div>' +
    '<div class="field"><span>新密码</span><input type="password" id="pw-new" placeholder="至少 8 位"></div>' +
    '</div><button class="btn" onclick="changePassword()">修改密码</button></div>';

  html += '<div style="margin-top:20px;display:flex;gap:8px">' +
    '<button class="btn primary" onclick="saveSettings()">保存设置</button></div>';

  $('#content').innerHTML = html;
}

function field(label, inner) {
  return '<label class="field"><span>' + label + '</span>' + inner + '</label>';
}
function opt(v, label, cur) {
  return '<option value="' + v + '"' + (v === cur ? ' selected' : '') + '>' + label + '</option>';
}

async function saveSettings() {
  const eab = {};
  state.cas.filter(c => c.requiresEab).forEach(c => {
    const k = $('#eab-kid-' + c.id);
    const h = $('#eab-hmac-' + c.id);
    if (k && h && (k.value || h.value)) eab[c.id] = { kid: k.value.trim(), hmac: h.value.trim() };
  });
  const body = {
    acmeEmail: $('#set-email').value.trim(),
    defaultCa: $('#set-ca').value,
    defaultKeyType: $('#set-key').value,
    defaultRenewDays: parseInt($('#set-days').value, 10) || 30,
    compat3xui: $('#set-compat').value,
    compatCertDir: $('#set-certdir').value.trim(),
    webhookUrl: $('#set-webhook').value.trim(),
    telegramToken: $('#set-tgtoken').value,
    telegramChatId: $('#set-tgchat').value.trim(),
    notifyOnRenew: $('#set-n-renew').checked,
    notifyOnError: $('#set-n-err').checked,
    terminalEnabled: $('#set-term').checked,
    terminalShell: $('#set-term-shell').value.trim(),
    terminalIdleMinutes: parseInt($('#set-term-idle').value, 10) || 15,
    eab: eab,
  };
  try {
    await api('/settings', { method: 'PUT', body: JSON.stringify(body) });
    toast('设置已保存', 'ok');
  } catch (e) { toast(e.message, 'bad'); }
}

async function changePassword() {
  const oldPw = $('#pw-old').value;
  const newPw = $('#pw-new').value;
  if (newPw.length < 8) { toast('新密码至少 8 位', 'bad'); return; }
  try {
    await api('/password', { method: 'POST', body: JSON.stringify({ old: oldPw, new: newPw }) });
    $('#pw-old').value = ''; $('#pw-new').value = '';
    toast('密码已修改', 'ok');
  } catch (e) { toast(e.message, 'bad'); }
}

/* ---------------- 弹窗 ---------------- */

function openModal(title, bodyHTML, footHTML, wide) {
  closeModal();
  const mask = document.createElement('div');
  mask.className = 'modal-mask';
  mask.innerHTML =
    '<div class="modal' + (wide ? ' wide' : '') + '">' +
    '<div class="modal-head"><h3>' + esc(title) + '</h3><button class="x" onclick="closeModal()">×</button></div>' +
    '<div class="modal-body">' + bodyHTML + '</div>' +
    '<div class="modal-foot">' + (footHTML || '<button class="btn" onclick="closeModal()">关闭</button>') + '</div>' +
    '</div>';
  mask.addEventListener('click', ev => { if (ev.target === mask) closeModal(); });
  $('#modal-root').appendChild(mask);
  return mask;
}

function confirmDialog(title, message, okLabel, onOk) {
  openModal(title, '<p class="sub" style="margin:0;line-height:1.8;white-space:pre-line">' + esc(message) + '</p>',
    '<button class="btn" onclick="closeModal()">取消</button>' +
    '<button class="btn danger" id="confirm-ok">' + okLabel + '</button>');
  const btn = $('#confirm-ok');
  if (btn) btn.onclick = () => { closeModal(); onOk(); };
}

function deleteCert(id, name) {
  confirmDialog('删除证书',
    '将从列表中移除「' + name + '」，并删除本程序保存的证书文件。\n\n' +
    '已经部署到 /root/cert/ 等位置的副本不会被删除，线上服务不受影响。\n此操作不可恢复。',
    '确认删除', async () => {
      try {
        await api('/certs/' + id, { method: 'DELETE' });
        toast('已删除', 'ok');
        render();
      } catch (e) { toast(e.message, 'bad'); }
    });
}

function closeModal() {
  if (state.jobTimer) { clearInterval(state.jobTimer); state.jobTimer = null; }
  $('#modal-root').innerHTML = '';
}

/* ---------------- 新建证书 ---------------- */

async function openCertForm() {
  try {
    if (!state.cas.length) state.cas = await api('/cas');
    if (!state.providers.length) state.providers = await api('/dnsproviders');
    if (!state.settings) state.settings = await api('/settings');
  } catch (e) { toast(e.message, 'bad'); return; }

  const s = state.settings;
  const body =
    field('备注名（可选）', '<input type="text" id="f-name" placeholder="例如：主站、节点 A">') +
    field('域名', '<textarea id="f-domains" placeholder="example.com&#10;www.example.com&#10;*.example.com"></textarea>' +
      '<small>一行一个，或用逗号分隔。第一个作为主域名。通配符 * 只能配合 DNS-01 使用。</small>') +
    '<div class="form-row">' +
    field('证书颁发机构', '<select id="f-ca">' + state.cas.map(c =>
      '<option value="' + esc(c.id) + '"' + (c.id === s.defaultCa ? ' selected' : '') + '>' + esc(c.name) + '</option>').join('') + '</select>') +
    field('密钥类型', '<select id="f-key">' +
      opt('ec256', 'ECDSA P-256', s.defaultKeyType) +
      opt('ec384', 'ECDSA P-384', s.defaultKeyType) +
      opt('rsa2048', 'RSA 2048', s.defaultKeyType) +
      opt('rsa4096', 'RSA 4096', s.defaultKeyType) + '</select>') +
    '</div>' +
    field('验证方式', '<select id="f-challenge" onchange="onChallengeChange()">' +
      '<option value="dns-01">DNS-01 自动（推荐，不占端口）</option>' +
      '<option value="dns-01-manual">DNS-01 手动（人工加 TXT）</option>' +
      '<option value="http-01-webroot">HTTP-01 Webroot（复用 80）</option>' +
      '<option value="http-01-standalone">HTTP-01 独立监听（独占 80）</option>' +
      '<option value="tls-alpn-01">TLS-ALPN-01（独占 443，不推荐）</option>' +
      '</select>') +
    '<div id="f-extra"></div>' +
    '<div class="form-row">' +
    field('提前续期天数', '<input type="number" id="f-days" min="1" max="89" value="' + (s.defaultRenewDays || 30) + '">') +
    '<div class="field"><span>自动续期</span><label class="switch" style="margin-top:7px">' +
      '<input type="checkbox" id="f-auto" checked>启用</label></div>' +
    '</div>' +
    '<div class="section-title">部署（可选）</div>' +
    '<p class="hint">签发成功后会把证书写到目标路径并执行重载命令。可用 <b>{domain}</b> 占位符。' +
    '填 <b>/root/cert/{domain}/fullchain.pem</b> 可对接 3x-ui。</p>' +
    field('证书路径', '<input type="text" id="f-dcert" placeholder="/root/cert/{domain}/fullchain.pem">') +
    field('私钥路径', '<input type="text" id="f-dkey" placeholder="/root/cert/{domain}/privkey.pem">') +
    field('重载命令', '<input type="text" id="f-dcmd" placeholder="x-ui restart">') +
    '<button class="btn sm" type="button" onclick="fill3xui()">填入 3x-ui 预设</button>' +
    '<div style="margin-top:16px"><label class="switch"><input type="checkbox" id="f-issue" checked>创建后立即签发</label></div>';

  openModal('新建证书', body,
    '<button class="btn" onclick="closeModal()">取消</button>' +
    '<button class="btn primary" onclick="submitCert()">创建</button>', true);

  onChallengeChange();
}

function onChallengeChange() {
  const v = $('#f-challenge').value;
  const box = $('#f-extra');
  if (v === 'dns-01') {
    box.innerHTML = field('DNS 服务商', '<select id="f-dns" onchange="onDNSChange()">' +
      state.providers.map(p => '<option value="' + esc(p.id) + '">' + esc(p.name) + '</option>').join('') +
      '</select>') + '<div id="f-dnscreds"></div>';
    onDNSChange();
  } else if (v === 'dns-01-manual') {
    box.innerHTML = '<p class="hint">签发时会列出需要添加的 TXT 记录，你去 DNS 服务商手动添加后，程序会自动轮询等待生效（最长 20 分钟）。适用于任何 DNS 服务商。</p>';
  } else if (v === 'http-01-webroot') {
    box.innerHTML = field('站点根目录', '<input type="text" id="f-webroot" placeholder="/var/www/html">') +
      '<p class="hint">必须与 80 端口上的 Web 服务指向同一目录，例如 Nginx 的 root。程序只会写入 <b>.well-known/acme-challenge/</b>。</p>';
  } else if (v === 'http-01-standalone') {
    box.innerHTML = field('监听端口', '<input type="number" id="f-port" value="80" min="1" max="65535">') +
      '<p class="hint">签发时临时占用该端口几秒。如果 80 已被 nginx/xray 占用，请改用 Webroot 或 DNS-01。</p>';
  } else {
    box.innerHTML = '<p class="hint" style="border-color:var(--danger)">TLS-ALPN-01 必须独占 443。如果 443 上跑着 xray，验证一定失败——请改用 DNS-01。</p>';
  }
}

function onDNSChange() {
  const id = $('#f-dns').value;
  const p = state.providers.find(x => x.id === id);
  const box = $('#f-dnscreds');
  if (!p) { box.innerHTML = ''; return; }
  box.innerHTML = p.fields.map(f =>
    field(f.label + (f.required ? '' : '（可选）'),
      '<input type="' + (f.secret ? 'password' : 'text') + '" data-cred="' + esc(f.key) + '" ' +
      'placeholder="' + esc(f.placeholder || '') + '" value="' + esc(f.default || '') + '">')
  ).join('') + '<p class="hint">' + esc(p.help) + '</p>';
}

function fill3xui() {
  $('#f-dcert').value = '/root/cert/{domain}/fullchain.pem';
  $('#f-dkey').value = '/root/cert/{domain}/privkey.pem';
  $('#f-dcmd').value = 'x-ui restart';
}

async function submitCert() {
  const domains = $('#f-domains').value.trim();
  if (!domains) { toast('请填写域名', 'bad'); return; }

  const challenge = $('#f-challenge').value;
  const body = {
    name: $('#f-name').value.trim(),
    domains: [domains],
    ca: $('#f-ca').value,
    keyType: $('#f-key').value,
    challenge: challenge,
    renewBeforeDays: parseInt($('#f-days').value, 10) || 30,
    autoRenew: $('#f-auto').checked,
    deployCertPath: $('#f-dcert').value.trim(),
    deployKeyPath: $('#f-dkey').value.trim(),
    deployCmd: $('#f-dcmd').value.trim(),
    issueNow: $('#f-issue').checked,
  };

  if (challenge === 'http-01-webroot') body.webroot = $('#f-webroot').value.trim();
  if (challenge === 'http-01-standalone') body.challengePort = parseInt($('#f-port').value, 10) || 80;
  if (challenge === 'dns-01') {
    body.dnsProvider = $('#f-dns').value;
    const creds = {};
    $$('[data-cred]').forEach(i => { if (i.value) creds[i.dataset.cred] = i.value; });
    body.dnsCredentials = creds;
  }

  try {
    const res = await api('/certs', { method: 'POST', body: JSON.stringify(body) });
    closeModal();
    toast('已创建', 'ok');
    if (res.jobId) openJob(res.jobId);
    render();
  } catch (e) { toast(e.message, 'bad'); }
}

/* ---------------- 签发 / 续期 ---------------- */

async function issueCert(id, action) {
  try {
    const res = await api('/certs/' + id + '/' + action, { method: 'POST' });
    openJob(res.jobId);
  } catch (e) { toast(e.message, 'bad'); }
}

async function checkNow() {
  try {
    const r = await api('/check', { method: 'POST' });
    toast(r.triggered ? ('已触发 ' + r.triggered + ' 张证书续期') : '没有需要续期的证书', 'ok');
    render();
  } catch (e) { toast(e.message, 'bad'); }
}

/* ---------------- 任务进度 ---------------- */

function openJob(jobId) {
  openModal('任务进度',
    '<div id="job-status" class="sub" style="margin-bottom:12px">准备中…</div>' +
    '<div id="job-txt"></div>' +
    '<div class="log-box" id="job-log">…</div>',
    '<button class="btn" onclick="closeModal();render()">关闭</button>');

  const poll = async () => {
    let j;
    try { j = await api('/jobs/' + jobId); } catch (e) { return; }
    const st = $('#job-status');
    if (!st) { clearInterval(state.jobTimer); return; }
    if (j.status === 'running') {
      st.innerHTML = '<span class="pill info">进行中</span> ' + esc(j.message || '');
    } else if (j.status === 'success') {
      st.innerHTML = '<span class="pill ok">成功</span> ' + esc(j.message || '');
    } else {
      st.innerHTML = '<span class="pill bad">失败</span> ' + esc(j.message || '');
    }
    $('#job-log').textContent = (j.logs || []).join('\n');
    $('#job-log').scrollTop = $('#job-log').scrollHeight;

    if (j.txt && j.txt.length) {
      $('#job-txt').innerHTML = '<p class="hint" style="margin-top:0">请把下面的 TXT 记录添加到 DNS 解析商，程序会自动检测生效：</p>' +
        j.txt.map(t =>
          '<div class="txt-rec"><div class="fq">' + esc(t.fqdn) + '</div>' +
          '<div class="val">' + esc(t.value) + '</div></div>').join('');
    } else {
      $('#job-txt').innerHTML = '';
    }

    if (j.status !== 'running') {
      clearInterval(state.jobTimer);
      state.jobTimer = null;
      if (j.status === 'success') toast('任务完成', 'ok');
    }
  };
  poll();
  state.jobTimer = setInterval(poll, 1200);
}

/* ---------------- 证书详情 ---------------- */

async function openDetail(id) {
  let c, info = null;
  try {
    c = await api('/certs/' + id);
    try { info = await api('/certs/' + id + '/inspect'); } catch (e) { info = null; }
  } catch (e) { toast(e.message, 'bad'); return; }

  const st = STATUS[c.status] || ['未知', 'plain'];
  let body = '<dl class="kv">' +
    '<dt>状态</dt><dd><span class="pill ' + st[1] + '">' + st[0] + '</span></dd>' +
    '<dt>域名</dt><dd class="mono">' + esc(c.domains.join('<br>')) + '</dd>' +
    '<dt>CA</dt><dd class="mono">' + esc(c.ca) + '</dd>' +
    '<dt>验证方式</dt><dd>' + esc(CHALLENGE_LABEL[c.challenge] || c.challenge) + '</dd>' +
    '<dt>密钥类型</dt><dd class="mono">' + esc(c.keyType) + '</dd>' +
    '<dt>自动续订</dt><dd>' + autoRenewSwitch(c) +
    '<span class="sub" style="margin-left:8px">' + (c.autoRenew ? ('提前 ' + c.renewBeforeDays + ' 天') : '已关闭') + '</span></dd>' +
    '<dt>到期时间</dt><dd>' + fmtDate(c.notAfter) + (c.notAfter ? '（剩余 ' + daysLeft(c.notAfter) + ' 天）' : '') + '</dd>';
  if (c.lastError) body += '<dt>最近错误</dt><dd style="color:var(--danger)">' + esc(c.lastError) + '</dd>';
  body += '</dl>';

  if (info) {
    body += '<div class="section-title">证书内容</div><dl class="kv">' +
      '<dt>颁发者</dt><dd class="mono">' + esc(info.issuer) + '</dd>' +
      '<dt>序列号</dt><dd class="mono">' + esc(info.serial) + '</dd>' +
      '<dt>生效时间</dt><dd>' + fmtDate(info.notBefore) + '</dd>' +
      '<dt>覆盖域名</dt><dd class="mono">' + esc((info.dnsNames || []).join(', ')) + '</dd>' +
      '</dl>';
    if (info.chain && info.chain.length) {
      body += '<div class="section-title">证书链</div>';
      info.chain.forEach((ch, i) => {
        body += '<div class="txt-rec"><div class="fq">' + esc(ch.subject) + '</div>' +
          '<div class="val">由 ' + esc(ch.issuer) + ' 签发，有效期至 ' + fmtDate(ch.notAfter) + '</div></div>';
      });
    }
  }

  body += '<div class="section-title">部署</div><dl class="kv">' +
    '<dt>证书路径</dt><dd class="mono">' + esc(c.deployCertPath || '未设置') + '</dd>' +
    '<dt>私钥路径</dt><dd class="mono">' + esc(c.deployKeyPath || '未设置') + '</dd>' +
    '<dt>重载命令</dt><dd class="mono">' + esc(c.deployCmd || '未设置') + '</dd>' +
    '</dl>';

  if (c.notAfter) {
    body += '<div class="section-title">下载</div><div style="display:flex;gap:8px;flex-wrap:wrap">' +
      dlBtn(id, 'fullchain', 'fullchain.pem') +
      dlBtn(id, 'privkey', 'privkey.pem') +
      dlBtn(id, 'cert', 'cert.pem') +
      dlBtn(id, 'chain', 'chain.pem') + '</div>';
  }

  const foot = '<button class="btn danger" onclick="deleteCert(\'' + id + '\',\'' + esc(c.name || c.domains[0]) + '\')">删除</button>' +
    '<button class="btn" onclick="revokeCert(\'' + id + '\')">吊销</button>' +
    '<button class="btn" onclick="openCertEdit(\'' + id + '\')">编辑</button>' +
    '<button class="btn primary" onclick="issueCert(\'' + id + '\',\'' + (c.notAfter ? 'renew' : 'issue') + '\')">' +
    (c.notAfter ? '立即续期' : '立即签发') + '</button>';

  openModal(c.name || c.domains[0], body, foot, true);
}

function dlBtn(id, file, label) {
  return '<a class="btn sm" href="/api/certs/' + id + '/download?file=' + file + '">' + label + '</a>';
}

async function revokeCert(id) {
  if (!confirm('确定要吊销这张证书吗？吊销后该证书立即失效，无法恢复。')) return;
  try {
    const r = await api('/certs/' + id + '/revoke', { method: 'POST' });
    closeModal();
    openJob(r.jobId);
  } catch (e) { toast(e.message, 'bad'); }
}

async function openCertEdit(id) {
  let c;
  try { c = await api('/certs/' + id); } catch (e) { toast(e.message, 'bad'); return; }
  const body =
    field('备注名', '<input type="text" id="e-name" value="' + esc(c.name) + '">') +
    field('域名', '<textarea id="e-domains">' + esc(c.domains.join('\n')) + '</textarea>') +
    '<div class="form-row">' +
    field('提前续期天数', '<input type="number" id="e-days" value="' + c.renewBeforeDays + '">') +
    '<div class="field"><span>自动续期</span><label class="switch" style="margin-top:7px">' +
    '<input type="checkbox" id="e-auto"' + (c.autoRenew ? ' checked' : '') + '>启用</label></div>' +
    '</div>' +
    field('证书路径', '<input type="text" id="e-dcert" value="' + esc(c.deployCertPath) + '">') +
    field('私钥路径', '<input type="text" id="e-dkey" value="' + esc(c.deployKeyPath) + '">') +
    field('重载命令', '<input type="text" id="e-dcmd" value="' + esc(c.deployCmd) + '">') +
    '<p class="hint">修改验证方式或 CA 需要重新签发；这里只改元数据与部署配置。</p>';

  openModal('编辑证书', body,
    '<button class="btn" onclick="closeModal()">取消</button>' +
    '<button class="btn primary" onclick="saveCert(\'' + id + '\')">保存</button>');
}

async function saveCert(id) {
  const body = {
    name: $('#e-name').value.trim(),
    domains: [$('#e-domains').value],
    renewBeforeDays: parseInt($('#e-days').value, 10) || 30,
    autoRenew: $('#e-auto').checked,
    deployCertPath: $('#e-dcert').value.trim(),
    deployKeyPath: $('#e-dkey').value.trim(),
    deployCmd: $('#e-dcmd').value.trim(),
  };
  try {
    await api('/certs/' + id, { method: 'PUT', body: JSON.stringify(body) });
    closeModal();
    toast('已保存', 'ok');
    render();
  } catch (e) { toast(e.message, 'bad'); }
}

/* ---------------- 3x-ui ---------------- */

function xuiRandPass() {
  const cs = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  const buf = new Uint32Array(16);
  (window.crypto || window.msCrypto).getRandomValues(buf);
  for (let i = 0; i < 16; i++) s += cs[buf[i] % cs.length];
  return s;
}

function xuiPill(status) {
  const map = {
    running: ['安装中', 'info'],
    success: ['完成', 'ok'],
    error: ['失败', 'bad'],
  };
  const m = map[status] || [status, 'plain'];
  return '<span class="pill ' + m[1] + '">' + m[0] + '</span>';
}

function xuiStateCard(d) {
  const s = d.state || {};
  const c = d.compat || {};
  let h = '<div class="grid c3">';
  if (s.installed) {
    h += '<div class="card stat"><div class="k">3x-ui</div><div class="v">已安装</div>' +
      '<div class="d">' + esc(s.version || '版本未知') + '</div></div>';
    h += '<div class="card stat ' + (s.serviceActive ? 'ok' : 'bad') + '"><div class="k">服务</div>' +
      '<div class="v">' + (s.serviceActive ? '运行中' : '未运行') + '</div><div class="d">systemd · x-ui</div></div>';
    h += '<div class="card stat"><div class="k">面板端口</div><div class="v">' + (s.panelPort || '—') +
      '</div><div class="d">' + esc(s.basePath ? '/' + s.basePath : '无路径前缀') + '</div></div>';
  } else {
    h += '<div class="card stat"><div class="k">3x-ui</div><div class="v">未安装</div>' +
      '<div class="d">可以直接在下面一键安装</div></div>';
    h += '<div class="card stat"><div class="k">80 端口</div><div class="v">' +
      (c.port80 && c.port80.inUse ? '被占用' : '空闲') + '</div><div class="d">' +
      esc((c.port80 && c.port80.owner) || '—') + '</div></div>';
    h += '<div class="card stat"><div class="k">443 端口</div><div class="v">' +
      (c.port443 && c.port443.inUse ? '被占用' : '空闲') + '</div><div class="d">' +
      esc((c.port443 && c.port443.owner) || '—') + '</div></div>';
  }
  h += '</div>';

  if (s.installed) {
    h += '<div class="card" style="margin-top:14px"><h3>当前状态</h3><dl class="kv">' +
      '<dt>可执行文件</dt><dd class="mono">' + esc(s.binaryPath || '—') + '</dd>' +
      '<dt>数据目录</dt><dd class="mono">' + esc(s.dataDir || '/etc/x-ui') + '</dd>' +
      '<dt>面板证书</dt><dd class="mono">' + esc(s.panelCert || '未设置（面板走 HTTP）') + '</dd>' +
      '</dl></div>';
  }
  return h;
}

function xuiFormHTML(d) {
  const s = d.state || {};
  const def = d.defaults || {};
  const installed = !!s.installed;
  let h = '<div class="section-title">' + (installed ? '重新安装 / 升级' : '安装配置') + '</div><div class="card">';
  h += '<p class="hint" style="margin-top:0">' +
    (installed
      ? '重新安装会复用 3x-ui 官方安装脚本，已有的数据库与入站配置会保留，面板端口与账号按下面填写的内容覆盖。'
      : '调用 3x-ui 官方安装脚本的非交互模式安装，全程日志实时回传。SSL 建议先选「暂不配置」，装完后由 CertPilot 签发证书并部署，' +
        '避免两套 ACME 客户端抢同一个 80 端口。') +
    '</p>';

  h += '<div class="form-row">' +
    '<label class="field"><span>版本</span><input type="text" id="xui-version" placeholder="留空 = 最新稳定版"></label>' +
    '<label class="field"><span>面板端口</span><input type="number" id="xui-port" min="1" max="65535" value="' +
    (s.panelPort || def.port || 2053) + '"></label>' +
    '</div>';

  h += '<div class="form-row">' +
    '<label class="field"><span>用户名</span><input type="text" id="xui-user" value="' + esc(def.username || 'admin') + '"></label>' +
    '<label class="field"><span>密码</span><div class="input-row">' +
    '<input type="text" id="xui-pass" value="' + xuiRandPass() + '">' +
    '<button class="btn sm" type="button" onclick="document.getElementById(\'xui-pass\').value=xuiRandPass()">换一个</button>' +
    '</div></label>' +
    '</div>';

  h += '<label class="field"><span>面板路径前缀（可选）</span>' +
    '<input type="text" id="xui-basepath" placeholder="例如 panel；留空由官方脚本随机生成"></label>';

  h += '<label class="field"><span>SSL 证书</span><select id="xui-ssl" onchange="onXuiSslChange()">' +
    '<option value="none">暂不配置（推荐，装完由 CertPilot 签发）</option>' +
    '<option value="ip">官方脚本为本机 IP 签证书（6 天，需 80 空闲）</option>' +
    '<option value="domain">官方脚本为域名签证书（需域名已解析到本机）</option>' +
    '</select></label>';

  h += '<label class="field" id="xui-domain-field" hidden><span>域名</span>' +
    '<input type="text" id="xui-domain" placeholder="panel.example.com"></label>';
  h += '<label class="field" id="xui-email-field" hidden><span>ACME 邮箱</span>' +
    '<input type="email" id="xui-email" placeholder="you@example.com"></label>';

  if (installed) {
    h += '<label class="switch" style="margin:14px 0 0"><input type="checkbox" id="xui-force" checked>覆盖安装（保留数据库）</label>';
  }

  h += '<div style="margin-top:16px;display:flex;gap:10px;align-items:center">' +
    '<button class="btn primary" onclick="submitXuiInstall()"' + (d.supported === false ? ' disabled' : '') + '>' +
    (installed ? '开始重装' : '一键安装 3x-ui') + '</button>' +
    '<span class="form-hint" id="xui-form-hint"></span></div>';
  h += '</div>';
  return h;
}

function onXuiSslChange() {
  const v = $('#xui-ssl').value;
  $('#xui-domain-field').hidden = v !== 'domain';
  $('#xui-email-field').hidden = v === 'none';
}

function xuiProgressHTML(t) {
  const running = t.status === 'running';
  let h = '<div class="section-title">安装进度</div><div class="card" id="xui-progress">';
  h += '<div class="task-head">' + xuiPill(t.status) +
    '<span class="task-msg">' + esc(t.message || '') + '</span>' +
    (running ? '<span class="spin"></span>' : '') + '</div>';

  h += '<ul class="steps">';
  (t.steps || []).forEach(s => {
    const icon = s.status === 'done' ? '✓' : s.status === 'error' ? '✕' :
      s.status === 'running' ? '◌' : s.status === 'skip' ? '–' : '·';
    h += '<li class="step ' + s.status + '"><span class="step-i">' + icon + '</span>' +
      '<span class="step-n">' + esc(s.name) + '</span>' +
      (s.detail ? '<span class="step-d">' + esc(s.detail) + '</span>' : '') + '</li>';
  });
  h += '</ul>';

  if (t.result && t.result.url) {
    const r = t.result;
    h += '<div class="result-box"><div class="result-t">面板已就绪</div>' +
      '<dl class="kv">' +
      '<dt>地址</dt><dd class="mono">' + esc(r.url) + ' <button class="btn sm" onclick="copyText(\'' + esc(r.url).replace(/'/g, "\\'") + '\',\'面板地址\')">复制</button></dd>' +
      '<dt>用户名</dt><dd class="mono">' + esc(r.username) + '</dd>' +
      '<dt>密码</dt><dd class="mono">' + esc(r.password) + ' <button class="btn sm" onclick="copyText(\'' + esc(r.password).replace(/'/g, "\\'") + '\',\'密码\')">复制</button></dd>' +
      '<dt>版本</dt><dd class="mono">' + esc(r.version || '—') + '</dd>' +
      '</dl>' +
      '<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">' +
      '<button class="btn" onclick="switchView(\'certs\')">去签发证书</button>' +
      '<button class="btn" onclick="renderXui()">重新检查状态</button>' +
      '<button class="btn" onclick="switchView(\'terminal\')">打开终端</button>' +
      '</div></div>';
  }

  h += '<div class="log-head">执行日志' + (running ? '（实时）' : '') + '</div>';
  h += '<pre class="log-box" id="xui-log">' + esc((t.logs || []).join('\n')) + '</pre>';
  h += '</div>';
  return h;
}

function xuiPaint(d, task) {
  let html = xuiStateCard(d);
  if (!d.supported) {
    html += '<div class="card warn-card" style="margin-top:14px"><h3>当前环境不支持安装</h3>' +
      '<p class="hint" style="margin:0">3x-ui 安装只能在 Linux 上执行。当前进程运行在其它系统上，下面的表单仅作预览。</p></div>';
  }
  if (task) html += xuiProgressHTML(task);
  else if (d.installing && d.currentTask) html += xuiProgressHTML(d.currentTask);
  else html += xuiFormHTML(d);
  $('#content').innerHTML = html;
  const box = $('#xui-log');
  if (box) box.scrollTop = box.scrollHeight;
}

async function renderXui() {
  if (state.xuiTimer) { clearTimeout(state.xuiTimer); state.xuiTimer = null; }
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  let d;
  try { d = await api('/xui/state'); } catch (e) { $('#content').innerHTML = errBox(e); return; }
  state.xui = d;
  xuiPaint(d, null);
  if (d.installing && d.currentTask) xuiPoll(d.currentTask.id);
}

function xuiPoll(id) {
  if (state.view !== 'xui') return;
  state.xuiTimer = setTimeout(async () => {
    let t;
    try { t = await api('/xui/tasks/' + id); } catch (e) {
      state.xuiTimer = setTimeout(() => xuiPoll(id), 1500);
      return;
    }
    xuiPaint(state.xui || {}, t);
    if (t.status === 'running') {
      xuiPoll(id);
    } else {
      state.xuiTimer = null;
      try {
        state.xui = await api('/xui/state');
        xuiPaint(state.xui, t);
        if (t.status === 'success') toast('3x-ui 安装完成', 'ok');
        else toast(t.message || '安装失败', 'bad');
      } catch (e) { /* 忽略刷新失败 */ }
    }
  }, 900);
}

async function submitXuiInstall() {
  const hint = $('#xui-form-hint');
  const body = {
    version: $('#xui-version').value.trim(),
    port: parseInt($('#xui-port').value, 10) || 0,
    username: $('#xui-user').value.trim(),
    password: $('#xui-pass').value,
    basePath: $('#xui-basepath').value.trim(),
    sslMode: $('#xui-ssl').value,
    domain: $('#xui-domain') ? $('#xui-domain').value.trim() : '',
    email: $('#xui-email') ? $('#xui-email').value.trim() : '',
    force: $('#xui-force') ? $('#xui-force').checked : false,
  };
  if (hint) hint.textContent = '正在提交…';
  try {
    const r = await api('/xui/install', { method: 'POST', body: JSON.stringify(body) });
    toast('安装已开始', 'ok');
    state.xui = await api('/xui/state');
    xuiPaint(state.xui, null);
    xuiPoll(r.taskId);
  } catch (e) {
    if (hint) hint.textContent = '';
    toast(e.message, 'bad');
  }
}

/* ---------------- 终端 ---------------- */

function termDispose() {
  if (state.termResize) {
    window.removeEventListener('resize', state.termResize);
    state.termResize = null;
  }
  if (state.termWS) {
    try { state.termWS.close(); } catch (e) { /* ignore */ }
    state.termWS = null;
  }
  if (state.term) {
    try { state.term.dispose(); } catch (e) { /* ignore */ }
    state.term = null;
  }
  state.termFit = null;
}

async function renderTerminal() {
  termDispose();
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  let d;
  try { d = await api('/terminal'); } catch (e) { $('#content').innerHTML = errBox(e); return; }

  if (!d.supported) {
    $('#content').innerHTML = '<div class="card"><h3>当前平台不支持</h3>' +
      '<p class="hint" style="margin:0">网页终端依赖 Linux PTY，只能在 Linux 服务器上使用。</p></div>';
    return;
  }
  if (!d.enabled) {
    $('#content').innerHTML = '<div class="card"><h3>网页终端未启用</h3>' +
      '<p class="hint">这是一个高危功能：启用后，任何拿到面板密码的人都能以 <b>root</b> 身份在这台服务器上执行任意命令。' +
      '默认关闭，需要你在设置里主动打开。</p>' +
      '<button class="btn primary" onclick="switchView(\'settings\')">去设置里开启</button></div>';
    return;
  }

  const busy = (d.sessions || []).length > 0;
  let h = '<div class="card warn-card"><h3>⚠ 这是 root shell</h3>' +
    '<p class="hint" style="margin:0">CertPilot 以 root 运行，终端里输入的命令直接以 root 执行，没有二次确认。' +
    '会话空闲 ' + (d.idleMinutes || 15) + ' 分钟后自动断开；同时只允许一个会话；' +
    '本程序只记录会话的开始与结束，<b>不记录你输入的内容</b>。</p></div>';

  if (busy) {
    h += '<div class="card" style="margin-top:14px"><h3>已有会话在运行</h3>' +
      '<p class="hint" style="margin:0">为避免两个人抢同一个 shell，需要先在原会话里退出，或者等待空闲超时。</p></div>';
    $('#content').innerHTML = h;
    return;
  }

  h += '<div class="card" style="margin-top:14px"><h3>身份确认</h3>' +
    '<p class="hint" style="margin-top:0">进入终端需要重新输入一次管理密码 —— 会话 cookie 单独不足以打开 root shell。</p>' +
    '<div class="form-row"><label class="field"><span>管理密码</span>' +
    '<input type="password" id="term-pass" autocomplete="current-password" placeholder="请输入管理密码"></label>' +
    '<div style="display:flex;align-items:flex-end"><button class="btn primary" onclick="openTerminal()">打开终端</button></div>' +
    '</div><div class="err" id="term-err"></div></div>';

  $('#content').innerHTML = h;
  setTimeout(() => { const el = $('#term-pass'); if (el) el.focus(); }, 50);
  const inp = $('#term-pass');
  if (inp) inp.addEventListener('keydown', ev => { if (ev.key === 'Enter') openTerminal(); });
}

async function openTerminal() {
  const el = $('#term-pass');
  const errEl = $('#term-err');
  if (errEl) errEl.textContent = '';
  if (!el || !el.value) return;
  try {
    const r = await api('/terminal/ticket', { method: 'POST', body: JSON.stringify({ password: el.value }) });
    mountTerminal(r.ticket);
  } catch (e) {
    if (errEl) errEl.textContent = e.message;
    else toast(e.message, 'bad');
  }
}

function mountTerminal(ticket) {
  $('#content').innerHTML =
    '<div class="term-wrap">' +
    '<div class="term-bar">' +
    '<span class="term-dot"></span><span class="term-title">root@' + esc(location.hostname) + '</span>' +
    '<span class="term-status" id="term-status">连接中…</span>' +
    '<button class="btn sm ghost" onclick="termFitWin()">适应窗口</button>' +
    '<button class="btn sm danger" onclick="closeTerminal()">断开</button>' +
    '</div>' +
    '<div id="term" class="term-body"></div>' +
    '</div>';

  const term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    lineHeight: 1.25,
    fontFamily: '"JetBrains Mono", "Cascadia Code", Menlo, Consolas, "Courier New", monospace',
    scrollback: 8000,
    theme: {
      background: '#0d1117', foreground: '#e6edf3', cursor: '#2dd4bf',
      selectionBackground: '#264f78',
      black: '#484f58', red: '#ff7b72', green: '#3fb950', yellow: '#d29922',
      blue: '#58a6ff', magenta: '#bc8cff', cyan: '#39c5cf', white: '#b1bac4',
      brightBlack: '#6e7681', brightRed: '#ffa198', brightGreen: '#56d364',
      brightYellow: '#e3b341', brightBlue: '#79c0ff', brightMagenta: '#d2a8ff',
      brightCyan: '#56d4dd', brightWhite: '#f0f6fc',
    },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($('#term'));
  state.term = term;
  state.termFit = fit;

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/api/terminal/ws?ticket=' + encodeURIComponent(ticket));
  ws.binaryType = 'arraybuffer';
  state.termWS = ws;

  const setStatus = (txt, cls) => {
    const el2 = $('#term-status');
    if (el2) { el2.textContent = txt; el2.className = 'term-status ' + (cls || ''); }
  };

  ws.onopen = () => {
    setStatus('已连接', 'ok');
    termFitWin();
    term.focus();
  };
  ws.onmessage = ev => {
    if (typeof ev.data === 'string') term.write(ev.data);
    else term.write(new Uint8Array(ev.data));
  };
  ws.onclose = ev => {
    setStatus('已断开', 'bad');
    term.write('\r\n\x1b[33m── 连接已关闭' + (ev.reason ? '：' + ev.reason : '') + ' ──\x1b[0m\r\n');
  };
  ws.onerror = () => {
    setStatus('连接出错', 'bad');
    term.write('\r\n\x1b[31m── 连接出错，请刷新页面重试 ──\x1b[0m\r\n');
  };

  term.onData(d => { if (ws.readyState === 1) ws.send(d); });
  term.onResize(({ cols, rows }) => {
    if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'resize', cols, rows }));
  });

  state.termResize = () => { try { fit.fit(); } catch (e) { /* ignore */ } };
  window.addEventListener('resize', state.termResize);
}

function termFitWin() {
  if (!state.termFit) return;
  try { state.termFit.fit(); } catch (e) { /* ignore */ }
  if (state.term) state.term.focus();
}

function closeTerminal() {
  termDispose();
  renderTerminal();
}

/* ---------------- 启动 ---------------- */

async function boot() {
  $('#boot').hidden = true;
  try {
    const s = await api('/session');
    if (s.needSetup) { showLogin(true); return; }
    if (!s.authed) { showLogin(false); return; }
    $('#ver').textContent = 'v' + s.version;
    $('#login').hidden = true;
    $('#app').hidden = false;
    switchView('overview');
  } catch (e) {
    showLogin(false);
  }
}

boot();
