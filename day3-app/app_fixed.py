"""
Day3 - 用户登录管理平台 (SQL注入漏洞修复版)
=========================================
✅ 修复内容:
  V-01 字符串拼接SQL → 参数化查询
  V-02 无输入过滤 → 输入长度和白名单校验
  V-03 搜索结果有回显 → 仅安全数据回显 + 移除SQL调试信息
  V-04 密码明文存储 → PBKDF2-SHA256 哈希存储

对比漏洞版本:
  漏洞版所有SQL使用 f-string 拼接 → 攻击者可注入任意SQL
  修复版使用参数化查询(?) → 用户输入始终作为数据,永不作为代码
"""

import os
import re
import secrets
import sqlite3
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, url_for, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# Secret Key
_SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.secret_key = _SECRET_KEY

# Session 配置
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# CSRF 保护
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
csrf = CSRFProtect(app)

# 速率限制
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

# Debug
DEBUG = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

# 数据库路径
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database_fixed.db")


# ============================================================
# 安全响应头
# ============================================================
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = \
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    return response


# ============================================================
# 输入校验 (V-02 修复)
# ============================================================
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,50}$')
EMAIL_PATTERN = re.compile(r'^.{0,100}$')
PHONE_PATTERN = re.compile(r'^[0-9\-+() ]{0,20}$')
PASSWORD_MAX_LEN = 128


def validate_username(username):
    """只允许字母、数字、下划线"""
    if not username or len(username) > 50:
        return False, "用户名长度必须在1-50个字符之间"
    if not USERNAME_PATTERN.match(username):
        return False, "用户名只能包含字母、数字和下划线，不允许特殊字符"
    return True, ""


def validate_password(password):
    if len(password) > PASSWORD_MAX_LEN:
        return False, "密码过长"
    return True, ""


def validate_email(email):
    if len(email) > 100:
        return False, "邮箱过长"
    return True, ""


def validate_phone(phone):
    if len(phone) > 20:
        return False, "手机号过长"
    return True, ""


def validate_search_keyword(keyword):
    """搜索关键词校验：仅允许中文、英文、数字、空格、@、.、_、-"""
    if not keyword or len(keyword) > 100:
        return False, "搜索关键词长度必须在1-100个字符之间"
    # 防御纵深: 即使参数化查询已防止注入，仍做字符白名单校验
    if not re.match(r'^[a-zA-Z0-9一-鿿 @._\-]+$', keyword):
        return False, "搜索关键词包含不允许的特殊字符"
    return True, ""


# ============================================================
# 数据库操作 (V-01 修复: 全部使用参数化查询)
# ============================================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT ''
        )
    """)

    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    if count == 0:
        # ✅ V-04 修复: 密码使用 PBKDF2-SHA256 哈希存储
        cursor.execute("INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                       ("admin", generate_password_hash("admin123"),
                        "admin@example.com", "13800138000"))
        cursor.execute("INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                       ("alice", generate_password_hash("alice2025"),
                        "alice@example.com", "13900139001"))

    db.commit()
    db.close()


# ============================================================
# 首页
# ============================================================
@app.route("/")
def index():
    username = session.get("username")
    return render_template("index_fixed.html", username=username)


# ============================================================
# ✅ 登录 (修复: 参数化查询 + 哈希密码验证)
# ============================================================
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # V-02 修复: 白名单输入校验
        valid, msg = validate_username(username)
        if not valid:
            error = msg
        elif not password:
            error = "密码不能为空"
        else:
            db = get_db()
            # ✅ V-01 修复: 参数化查询 — 用 ? 占位符，用户输入永不作为 SQL 代码执行
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if user and check_password_hash(user["password"], password):
                session.permanent = True
                session["username"] = user["username"]

                # 查询安全信息(4列，不含密码)
                user_info = db.execute(
                    "SELECT id, username, email, phone FROM users WHERE username = ?",
                    (username,)
                ).fetchone()
                return render_template("index_fixed.html",
                                       username=session["username"],
                                       user=dict(user_info) if user_info else None)
            else:
                error = "用户名或密码错误"

    return render_template("login_fixed.html", error=error)


# ============================================================
# ✅ 搜索 (修复: 参数化查询 + 输入白名单 + 移除SQL调试)
# ============================================================
@app.route("/search")
@limiter.limit("20 per minute")
def search():
    if "username" not in session:
        return redirect(url_for("login"))

    keyword = request.args.get("keyword", "").strip()

    if not keyword:
        return render_template("search_fixed.html", results=None, keyword="")

    # V-02 修复: 校验搜索关键词
    valid, msg = validate_search_keyword(keyword)
    if not valid:
        return render_template("search_fixed.html", results=None,
                               keyword=keyword, error=msg)

    db = get_db()
    # ✅ V-01 修复: 参数化查询
    # LIKE 中的 % 通配符在参数中拼接，但 keyword 已经过白名单校验
    like_pattern = f"%{keyword}%"
    results = db.execute(
        "SELECT id, username, email, phone FROM users "
        "WHERE username LIKE ? OR email LIKE ?",
        (like_pattern, like_pattern)
    ).fetchall()

    # V-03 修复: 不显示 SQL 语句，不暴露数据库错误细节
    return render_template("search_fixed.html",
                           results=results,
                           keyword=keyword)


# ============================================================
# ✅ 注册 (修复: 参数化查询 + 输入校验 + 哈希密码)
# ============================================================
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # V-02 修复: 输入校验
        valid, msg = validate_username(username)
        if not valid:
            error = msg
        elif not password:
            error = "密码不能为空"
        elif not validate_password(password)[0]:
            error = validate_password(password)[1]
        elif not validate_email(email)[0]:
            error = validate_email(email)[1]
        elif not validate_phone(phone)[0]:
            error = validate_phone(phone)[1]
        else:
            db = get_db()
            try:
                # ✅ V-01 修复: 参数化查询
                # ✅ V-04 修复: 密码哈希存储
                db.execute(
                    "INSERT INTO users (username, password, email, phone) "
                    "VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), email, phone)
                )
                db.commit()
                success = f"用户 {username} 注册成功！请登录。"
            except sqlite3.IntegrityError:
                error = "用户名已存在"
            except Exception as e:
                error = "注册失败，请稍后重试"

    return render_template("register_fixed.html", error=error, success=success)


# ============================================================
# 登出
# ============================================================
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print("  Day3 - 用户登录管理平台 (SQL注入修复版)")
    print("=" * 55)
    print(f"  ✅ SQL注入: 已修复 (参数化查询)")
    print(f"  ✅ 输入过滤: 白名单校验")
    print(f"  ✅ 密码存储: PBKDF2-SHA256 哈希")
    print(f"  ✅ CSRF防护: 已启用")
    print(f"  ✅ 速率限制: 已启用")
    print(f"  Debug模式: {'开启' if DEBUG else '关闭'}")
    print("=" * 55)
    print(f"  访问地址: http://0.0.0.0:5000")
    print("=" * 55)

    with app.app_context():
        init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
