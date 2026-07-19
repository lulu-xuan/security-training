"""
Day2 - 用户登录管理平台 (已修复漏洞版本)
=======================================
修复内容:
  V-01 密码明文存储 → 哈希存储
  V-02 密码明文展示 → 移除密码字段
  V-04 Secret Key硬编码 → 环境变量 + secrets 自动生成
  V-05 Debug模式 → 环境变量控制
  V-06 CSRF防护 → Flask-WTF CSRFProtect
  V-07 无速率限制 → flask_limiter
  V-08 Session无过期 → permanent_session_lifetime
  V-09 无安全响应头 → after_request 钩子
  V-10 输入未校验 → 长度限制 + 模板自动转义
  V-11 密码无强度要求 → 注册时校验复杂度
"""

import os
import secrets
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, url_for, flash,
    jsonify, abort, after_this_request
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf

# ------------------------------------------------------------
# 应用初始化
# ------------------------------------------------------------
app = Flask(__name__)

# V-04 修复: 从环境变量读取密钥，无环境变量时自动生成强密钥
_SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.secret_key = _SECRET_KEY

# V-05 修复: debug 模式由环境变量控制，默认 False
DEBUG = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

# V-08 修复: Session 过期时间设为 30 分钟
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# V-06 修复: CSRF 保护
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # CSRF token 有效期 1 小时
csrf = CSRFProtect(app)

# V-07 修复: 速率限制
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

# ------------------------------------------------------------
# V-01 修复: 密码用哈希存储 (generate_password_hash)
# ------------------------------------------------------------
USERS = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# 用户信息中不返回密码的字段列表 (V-02 修复)
_SAFE_FIELDS = {"username", "role", "email", "phone", "balance"}


def _safe_user_info(username):
    """返回用户信息，过滤掉密码字段 (V-02 修复)"""
    if username not in USERS:
        return None
    user = USERS[username]
    return {
        "username": username,
        "role": user.get("role", ""),
        "email": user.get("email", ""),
        "phone": user.get("phone", ""),
        "balance": user.get("balance", ""),
    }


def _validate_password_strength(password):
    """V-11 修复: 密码强度校验"""
    if len(password) < 6:
        return "密码长度不能少于6位"
    if not any(c.isupper() for c in password):
        return "密码必须包含至少一个大写字母"
    if not any(c.islower() for c in password):
        return "密码必须包含至少一个小写字母"
    if not any(c.isdigit() for c in password):
        return "密码必须包含至少一个数字"
    return None


# ------------------------------------------------------------
# V-09 修复: 安全响应头
# ------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    """为所有响应添加安全相关的 HTTP 头"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = \
        "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = \
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ------------------------------------------------------------
# 路由: 首页
# ------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = _safe_user_info(username)
    return render_template("index.html", username=username, user=user_info)


# ------------------------------------------------------------
# 路由: 登录 (V-07 修复: 添加速率限制)
# ------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # 每分钟最多 5 次登录尝试
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # V-10 修复: 输入长度校验
        if len(username) > 50:
            error = "用户名过长"
        elif len(password) > 128:
            error = "密码过长"
        elif not username or not password:
            error = "用户名和密码不能为空"
        elif username in USERS and check_password_hash(
            USERS[username]["password"], password
        ):
            # V-08 修复: 标记 session 为永久（受 lifetime 限制）
            session.permanent = True
            session["username"] = username
            user_info = _safe_user_info(username)
            return render_template(
                "index.html", username=username, user=user_info
            )
        else:
            error = "用户名或密码错误"

    return render_template("login.html", error=error)


# ------------------------------------------------------------
# 路由: 注册新用户
# ------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()

        # V-10 修复: 输入校验
        if len(username) > 50:
            error = "用户名过长"
        elif not username:
            error = "用户名不能为空"
        elif username in USERS:
            error = "用户名已存在"
        elif password != confirm_password:
            error = "两次密码输入不一致"
        else:
            # V-11 修复: 密码强度校验
            strength_error = _validate_password_strength(password)
            if strength_error:
                error = strength_error
            else:
                USERS[username] = {
                    "password": generate_password_hash(password),
                    "role": "user",
                    "email": email or "",
                    "phone": "",
                    "balance": 0,
                }
                success = f"用户 {username} 注册成功，请登录"

    return render_template("register.html", error=error, success=success)


# ------------------------------------------------------------
# 路由: 登出
# ------------------------------------------------------------
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


# ------------------------------------------------------------
# 路由: 获取 CSRF Token (前端 AJAX 使用)
# ------------------------------------------------------------
@app.route("/csrf-token")
def get_csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


# ------------------------------------------------------------
# 启动
# ------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 55)
    print("  用户登录管理平台 (漏洞已修复)")
    print("=" * 55)
    print(f"  Debug模式: {'开启' if DEBUG else '关闭'}")
    print(f"  CSRF防护:  已启用")
    print(f"  速率限制:  已启用 (5次/分钟)")
    print(f"  Session过期: 30分钟")
    print(f"  密码存储:  哈希加密")
    print("=" * 55)
    print(f"  访问地址: http://0.0.0.0:5000")
    print("=" * 55)

    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
