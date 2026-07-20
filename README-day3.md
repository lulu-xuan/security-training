# Day3 - SQL注入漏洞分析与修复

> **Day3 任务**: 在 Flask 登录管理平台中引入 SQL 注入漏洞（注册/搜索/登录全使用 f-string 字符串拼接 SQL）→ POC 测试验证 → 参数化查询修复

---

## 项目结构

```
day3-sql-injection/
├── app/                                    # 应用目录
│   ├── app.py                             # ⚠️ 漏洞版 (字符串拼接SQL，data/users.db)
│   ├── app_fixed.py                       # ✅ 修复版 (参数化查询)
│   ├── data/                              # 数据库目录
│   │   └── users.db                       # SQLite 数据库文件
│   ├── requirements.txt                   # 依赖
│   ├── templates/
│   │   ├── base.html                      # 基础模板（含注册链接）
│   │   ├── login.html                     # 登录页
│   │   ├── register.html                  # 注册页
│   │   ├── index.html                     # 首页（含搜索功能）
│   │   ├── login_fixed.html               # 修复版登录页
│   │   ├── register_fixed.html            # 修复版注册页
│   │   ├── index_fixed.html               # 修复版首页
│   │   └── search_fixed.html              # 修复版独立搜索页
│   └── static/css/style.css              # 样式
├── report/
│   └── sql_injection_report.md            # 📄 详细漏洞分析修复报告
└── README.md                              # 本文件
```

## 漏洞详情

| 漏洞 | 位置 | SQL 示例 |
|------|------|---------|
| **登录 SQL 注入** | `/login` POST | `f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"` |
| **搜索 SQL 注入** | `/?keyword=` | `f"SELECT ... WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"` |
| **注册 SQL 注入** | `/register` POST | `f"INSERT INTO users ... VALUES ('{username}', '{password}', '{email}', '{phone}')"` |

### POC 测试命令

```bash
# 登录获取 session
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/c.txt

# POC 1: UNION 注入
curl "http://127.0.0.1:5000/?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" -b /tmp/c.txt

# POC 2: OR 万能条件
curl "http://127.0.0.1:5000/?keyword=%27%20OR%20%271%27%3D%271" -b /tmp/c.txt

# POC 3: 注册注入
curl http://127.0.0.1:5000/register -d "username=hacker', 'pass', 'h@x.com', '123')--&password=x"
curl http://127.0.0.1:5000/login -d "username=hacker&password=pass"
```

## 快速启动

### 漏洞版（教学用）
```bash
cd app && python3 app.py
# ⚠️ 此版本包含 SQL 注入漏洞 - 仅供教学使用
```

### 修复版（生产安全）
```bash
cd app && python3 app_fixed.py
# ✅ 此版本已修复所有 SQL 注入漏洞
```

## 课程信息

- **课程**: 网络安全漏洞修复实训
- **Day**: 3 — SQL注入漏洞分析与修复
- **仓库**: https://github.com/lulu-xuan/day3-sql-injection
