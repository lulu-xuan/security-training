# Day2 - 用户登录管理平台 (漏洞修复版)

> **项目说明**: 基于 Flask 的用户登录管理平台，从 Day1 的"故意有漏洞"版本修复了 11 项安全漏洞，构建了一个具备基本安全防护能力的 Web 应用。

---

## 项目结构

```
security-training/
├── app/                               # Flask 应用主目录
│   ├── app.py                        # 主应用入口（已修复）
│   ├── requirements.txt              # Python 依赖清单
│   ├── .env.example                  # 环境变量模板
│   ├── templates/
│   │   ├── base.html                 # 基础模板（导航栏）
│   │   ├── index.html                # 首页 / 用户信息页
│   │   ├── login.html                # 登录页面
│   │   └── register.html             # 注册页面
│   └── static/
│       └── css/
│           └── style.css             # 全局样式
├── report/
│   └── vulnerability_fix_report.md   # 漏洞修复报告（供 AI 评分）
└── README.md                         # 本文件
```

## 快速启动

```bash
# 1. 安装依赖
pip install -r app/requirements.txt

# 2. 配置环境变量（可选，不配置会自动生成安全密钥）
cp app/.env.example app/.env
# 编辑 .env 填入 SECRET_KEY

# 3. 启动应用
cd app && python3 app.py
```

访问: **http://localhost:5000**

### Windows 获取方式

```bash
# 通过 GitHub 克隆到桌面
cd %USERPROFILE%\Desktop
git clone git@github.com:lulu-xuan/security-training.git

# 安装依赖
cd security-training
pip install -r app\requirements.txt

# 启动
cd app && python app.py
```

## 预置账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

## 漏洞修复清单

| 编号 | 漏洞名称 | 严重程度 | 修复方式 |
|------|---------|---------|---------|
| V-01 | 密码明文存储 | 🔴 高危 | 改用 Werkzeug 哈希加密 (PBKDF2-SHA256) |
| V-02 | 密码明文展示 | 🔴 高危 | 用户信息中彻底移除密码字段 |
| V-03 | HTML 注释泄露账号 | 🔴 高危 | 删除登录页调试注释 |
| V-04 | 弱 Secret Key | 🔴 高危 | 环境变量 + secrets 自动生成 64 位十六进制密钥 |
| V-05 | Debug 模式暴露 | 🔴 高危 | 环境变量控制，生产环境默认关闭 |
| V-06 | 无 CSRF 防护 | 🔴 高危 | Flask-WTF CSRFProtect 全局保护 |
| V-07 | 无速率限制 | 🟠 中危 | flask-limiter 限制登录接口 5次/分钟 |
| V-08 | Session 无过期 | 🟠 中危 | PERMANENT_SESSION_LIFETIME = 30 分钟 |
| V-09 | 无安全响应头 | 🟠 中危 | 添加 CSP、HSTS、X-Frame-Options 等 6 项安全头 |
| V-10 | 输入未校验 | 🟠 中危 | 长度限制、空值检查、模板自动转义 |
| V-11 | 密码无强度要求 | 🟢 低危 | 注册时校验大小写字母+数字+最小长度 |

## 安全特性一览

- ✅ 密码哈希存储 (PBKDF2-SHA256)
- ✅ CSRF 全局防护
- ✅ 登录频率限制 (5次/分钟)
- ✅ Session 30 分钟自动过期
- ✅ 安全响应头 (CSP, HSTS, X-Frame-Options 等)
- ✅ 用户输入长度校验
- ✅ 密码强度校验
- ✅ 环境变量分离配置
- ✅ HttpOnly + SameSite Cookie

## 课程信息

- **课程**: 网络安全漏洞修复实训
- **Day**: 2 - 用户登录平台漏洞修复
