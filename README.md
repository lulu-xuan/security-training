# 网络安全漏洞修复实训项目

> **项目说明**: 安全漏洞修复实训系列项目，每天一个安全主题，在 Flask 平台上进行漏洞引入 → POC 测试验证 → 系统性修复的完整流程。

---

## 项目导航

| Day | 主题 | 目录 | 状态 |
|:---:|------|------|:----:|
| Day2 | 用户登录平台漏洞修复（11项安全漏洞） | [`app/`](./app/) · [`report/`](./report/) | ✅ 已完成 |
| Day3 | SQL注入漏洞分析与修复 | [`day3-app/`](./day3-app/) · [`day3-report/`](./day3-report/) | ✅ 已完成 |
| **Day4** | **文件上传漏洞分析与修复** | **[`day4-app/`](./day4-app/) · [`day4-report/`](./day4-report/)** | **✅ 已完成** |
| **Day5** | **业务逻辑漏洞（越权+充值欺诈）** | **[`day5-app/`](./day5-app/) · [`day5-report/`](./day5-report/)** | **✅ 已完成** |

---

## Day2 - 用户登录管理平台漏洞修复

**主题**: 修复密码明文存储、CSRF缺失、弱密钥、Debug模式、Session过期等11项漏洞

- 代码: [`app/`](./app/)
- 报告: [`report/vulnerability_fix_report.md`](./report/vulnerability_fix_report.md)
- [完整说明 →](./README-day2.md)

## Day4 - 文件上传漏洞分析与修复

**主题**: 实现 upload-labs 10关闯关 + 文件上传漏洞系统修复（白名单+魔数+重命名）

- 漏洞版: [`day4-app/app_upload_labs.py`](./day4-app/app_upload_labs.py) （10关闯关）
- 修复版: [`day4-app/app_fixed.py`](./day4-app/app_fixed.py) （6项安全加固）
- 报告: [`day4-report/upload_vulnerability_report.md`](./day4-report/upload_vulnerability_report.md)

---

## Day5 - 业务逻辑漏洞（越权与充值欺诈）

**主题**: IDOR越权 + 负数充值 + 垂直越权 → session加固 + 参数校验 + 归属验证

- 漏洞版: [`day5-app/app.py`](./day5-app/app.py)
- 修复版: [`day5-app/app_fixed.py`](./day5-app/app_fixed.py)
- 报告: [`day5-report/business_logic_vulnerability_report.md`](./day5-report/business_logic_vulnerability_report.md)

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

# Day4 - 启动漏洞版（upload-labs 10关闯关）— 端口5000
cd day4-app && rm -rf static/uploads && python3 app_upload_labs.py

# Day4 - 启动修复版（安全上传）— 端口5001
cd day4-app && rm -rf static/uploads && python3 app_fixed.py
```

## 预置账号

| 用户名 | 密码 | Day2 | Day3 | Day4 |
|--------|------|:----:|:----:|:----:|
| admin | admin123 | ✅ | ✅ | ✅ |
| alice | alice2025 | ✅ | ✅ | ✅ |

## 课程信息

- **课程**: 网络安全漏洞修复实训
- **仓库**: [github.com/lulu-xuan/security-training](https://github.com/lulu-xuan/security-training)
- **结构**: 每天新增一个 `dayX-` 前缀目录，保留所有历史项目
