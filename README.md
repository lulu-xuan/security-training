# 安全漏洞分析与修复 — Web 应用安全工程

> 基于 Flask 平台，每日一个安全主题，按照「引入漏洞 → POC 攻击验证 → 安全修复验证」的三步法进行 Web 应用安全审计与加固。

---

## 项目导航

| Day | 主题 | 目录 | 状态 |
|:---:|------|------|:----:|
| Day2 | 用户登录平台漏洞修复（11项安全漏洞） | [`app/`](./app/) · [`report/`](./report/) | ✅ 已完成 |
| Day3 | SQL注入漏洞分析与修复 | [`day3-app/`](./day3-app/) · [`day3-report/`](./day3-report/) | ✅ 已完成 |
| Day4 | 文件上传漏洞分析与修复 | [`day4-app/`](./day4-app/) · [`day4-report/`](./day4-report/) | ✅ 已完成 |
| Day5 | 业务逻辑漏洞（越权与充值欺诈） | [`day5-app/`](./day5-app/) · [`day5-report/`](./day5-report/) | ✅ 已完成 |
| Day6 | 文件包含漏洞（5种攻击场景） | [`day6-app/`](./day6-app/) · [`day6-report/`](./day6-report/) | ✅ 已完成 |
| Day7 | CSRF跨站请求伪造漏洞（3种场景） | [`day7-app/`](./day7-app/) · [`day7-report/`](./day7-report/) | ✅ 已完成 |

---

## Day2 - 用户登录管理平台漏洞修复

**主题**: 修复密码明文存储、CSRF缺失、弱密钥、Debug模式、Session过期等11项漏洞

- 代码: [`app/`](./app/)
- 报告: [`report/vulnerability_fix_report.md`](./report/vulnerability_fix_report.md)

## Day3 - SQL注入漏洞分析与修复

**主题**: 引入SQL注入漏洞（f-string拼接）→ POC测试 → 参数化查询修复

- 漏洞版: [`day3-app/app.py`](./day3-app/app.py)
- 修复版: [`day3-app/app_fixed.py`](./day3-app/app_fixed.py)
- 报告: [`day3-report/sql_injection_report.md`](./day3-report/sql_injection_report.md)

## Day4 - 文件上传漏洞分析与修复

**主题**: 10 类文件上传绕过场景 + 文件魔数/白名单/重命名修复

- 漏洞版: [`day4-app/app_upload_labs.py`](./day4-app/app_upload_labs.py)
- 修复版: [`day4-app/app_fixed.py`](./day4-app/app_fixed.py)
- 报告: [`day4-report/upload_vulnerability_report.md`](./day4-report/upload_vulnerability_report.md)

## Day5 - 业务逻辑漏洞（越权与充值欺诈）

**主题**: IDOR 水平越权 + 负数充值 + 垂直越权 → session 归属校验 + 参数化

- 漏洞版: [`day5-app/app.py`](./day5-app/app.py)
- 修复版: [`day5-app/app_fixed.py`](./day5-app/app_fixed.py)
- 报告: [`day5-report/business_logic_vulnerability_report.md`](./day5-report/business_logic_vulnerability_report.md)

---

## Day6 - 文件包含漏洞（5种攻击场景）

**主题**: 基本文件包含 + 路径遍历 + RFI + data://封装协议 + 日志注入 → 5项安全加固

- 漏洞版: [`day6-app/app.py`](./day6-app/app.py)
- 修复版: [`day6-app/app_fixed.py`](./day6-app/app_fixed.py)
- 报告: [`day6-report/path_traversal_report.md`](./day6-report/path_traversal_report.md)
---

## Day7 - CSRF跨站请求伪造漏洞

**主题**: 完全无防御CSRF + GET请求绕过Token + Token存在性绕过 → 4项安全加固

- 漏洞版: [`day7-app/app.py`](./day7-app/app.py)
- 修复版: [`day7-app/app_fixed.py`](./day7-app/app_fixed.py)
- 报告: [`day7-report/csrf_vulnerability_report.md`](./day7-report/csrf_vulnerability_report.md)

---

## 快速启动

```bash
git clone git@github.com:lulu-xuan/security-training.git
cd security-training

# Day2 - 启动修复版
cd app && python3 app.py

# Day3 - 漏洞版 / 修复版
cd day3-app && rm -f data/users.db && python3 app.py
cd day3-app && rm -f data/users.db && python3 app_fixed.py

# Day4 - 漏洞版 / 修复版
cd day4-app && rm -rf static/uploads && python3 app_upload_labs.py
cd day4-app && rm -rf static/uploads && python3 app_fixed.py

# Day5 - 漏洞版 / 修复版
cd day5-app && rm -f data/users.db && python3 app.py
cd day5-app && rm -f data/users.db && python3 app_fixed.py

# Day6 - 漏洞版（5种文件包含攻击场景）/ 修复版
cd day6-app && rm -rf data/ logs/ && python3 app.py
cd day6-app && rm -rf data/ logs/ && python3 app_fixed.py

# Day7 - 漏洞版（3种CSRF攻击场景）/ 修复版
cd day7-app && rm -rf data/ logs/ && python3 app.py
cd day7-app && rm -rf data/ logs/ && python3 app_fixed.py
```
## 预置账号

| 用户名 | 密码 | Day2 | Day3 | Day4 | Day5 | Day6 | Day7 |
|--------|------|:----:|:----:|:----:|:----:|:----:|:----:|
| admin | admin123 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| alice | alice2025 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 项目信息

- **仓库**: [github.com/lulu-xuan/security-training](https://github.com/lulu-xuan/security-training)
- **结构**: 每日递增 `dayX-` 目录，独立可运行
