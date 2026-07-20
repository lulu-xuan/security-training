# 网络安全漏洞修复实训项目

> **项目说明**: 安全漏洞修复实训系列项目，每天一个安全主题，在 Flask 平台上进行漏洞引入 → POC 测试验证 → 系统性修复的完整流程。

---

## 项目导航

| Day | 主题 | 目录 | 状态 |
|:---:|------|------|:----:|
| Day2 | 用户登录平台漏洞修复（11项安全漏洞） | [`app/`](./app/) · [`report/`](./report/) | ✅ 已完成 |
| Day3 | SQL注入漏洞分析与修复 | [`day3-app/`](./day3-app/) · [`day3-report/`](./day3-report/) | ✅ 已完成 |

---

## Day2 - 用户登录管理平台漏洞修复

**主题**: 修复密码明文存储、CSRF缺失、弱密钥、Debug模式、Session过期等11项漏洞

- 代码: [`app/`](./app/)
- 报告: [`report/vulnerability_fix_report.md`](./report/vulnerability_fix_report.md)
- [完整说明 →](./README-day2.md)

## Day3 - SQL注入漏洞分析与修复

**主题**: 引入SQL注入漏洞（f-string拼接）→ POC测试 → 参数化查询修复

- 漏洞版: [`day3-app/app.py`](./day3-app/app.py)
- 修复版: [`day3-app/app_fixed.py`](./day3-app/app_fixed.py)
- 报告: [`day3-report/sql_injection_report.md`](./day3-report/sql_injection_report.md)
- [完整说明 →](./README-day3.md)

---

## 快速启动

```bash
# 安装依赖
pip install -r app/requirements.txt

# Day2 - 启动修复版
cd app && python3 app.py

# Day3 - 启动漏洞版（SQL注入演示）
cd day3-app && rm -f data/users.db && python3 app.py

# Day3 - 启动修复版（参数化查询）
cd day3-app && rm -f data/users.db && python3 app_fixed.py
```

## 预置账号

| 用户名 | 密码 | Day2 | Day3 |
|--------|------|:----:|:----:|
| admin | admin123 | ✅ | ✅ |
| alice | alice2025 | ✅ | ✅ |

## 课程信息

- **课程**: 网络安全漏洞修复实训
- **仓库**: [github.com/lulu-xuan/security-training](https://github.com/lulu-xuan/security-training)
- **结构**: 每天新增一个 `dayX-` 前缀目录，保留所有历史项目
