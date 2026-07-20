"""
Day3 - 用户登录管理平台 (SQL注入漏洞版本)
=========================================
⚠️ 警告: 此版本故意包含 SQL 注入漏洞，仅供安全教学使用！

漏洞:
  漏洞1: 字符串拼接 SQL 查询 (登录/注册/搜索全使用 f-string 拼接)
  漏洞2: 无任何输入过滤 (用户输入直传 SQL)
  漏洞3: 搜索结果有回显 (攻击者可通过 UNION 注入获取数据)
"""

import os
import sqlite3
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, url_for, g
)

app = Flask(__name__)

# Secret Key
_SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-day3-vuln")
app.secret_key = _SECRET_KEY

# Session 配置 (保留基本session安全,但SQL注入方面全是漏洞)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Debug 由环境变量控制
DEBUG = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

# 数据库路径 — data/users.db
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "data", "users.db")


# ============================================================
# 数据库操作 (全部使用字符串拼接 — 存在SQL注入漏洞)
# ============================================================

def get_db():
    """获取数据库连接"""
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
    """初始化数据库和预置用户 — 使用 INSERT OR IGNORE 防止重复插入"""
    # 确保 data 目录存在
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT ''
        )
    """)

    # INSERT OR IGNORE 防止重复插入
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')
    """)

    db.commit()
    db.close()


# ============================================================
# 漏洞路由: 首页
# ============================================================
@app.route("/")
def index():
    username = session.get("username")
    return render_template("index.html", username=username)


# ============================================================
# ⚠️ 漏洞路由: 搜索 (支持 GET，字符串拼接 SQL)
# ============================================================
@app.route("/search")
def search():
    if "username" not in session:
        return redirect(url_for("login"))

    keyword = request.args.get("keyword", "")
    results = None

    if keyword:
        db = get_db()

        # ⚠️ 漏洞: SELECT * —— 返回所有5列（id, username, password, email, phone）
        # ⚠️ 漏洞: 字符串拼接 SQL，无任何过滤
        query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"

        # 将 SQL 语句打印到控制台，方便观察注入效果
        print("=" * 55)
        print(f"  [SQL] {query}")
        print("=" * 55)

        try:
            results = db.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            print(f"  [SQL ERROR] {e}")
            results = []

    return render_template("index.html", username=session["username"],
                           results=results, keyword=keyword)


# ============================================================
# ⚠️ 漏洞路由: 登录 (字符串拼接 SQL — 存在 SQL 注入)
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    # 从 URL 参数获取注册成功提示
    registered = request.args.get("registered")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ⚠️ 漏洞: 字符串拼接 SQL 查询，无任何过滤
        db = get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        try:
            result = db.execute(query).fetchone()
        except sqlite3.OperationalError as e:
            error = f"数据库错误: {e}"
            return render_template("login.html", error=error)

        if result:
            session.permanent = True
            session["username"] = result["username"]
            # 查询用户完整信息
            info_query = f"SELECT id, username, email, phone FROM users WHERE username='{result['username']}'"
            user_info = db.execute(info_query).fetchone()
            return render_template("index.html", username=session["username"],
                                   user=dict(user_info) if user_info else None)
        else:
            error = "用户名或密码错误"

    return render_template("login.html", error=error, registered=registered)


# ============================================================
# ⚠️ 漏洞路由: 注册 (字符串拼接 SQL — 存在 SQL 注入)
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # ⚠️ 漏洞: 字符串拼接 SQL，无任何过滤
        db = get_db()
        query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

        try:
            db.execute(query)
            db.commit()
            # 注册成功后跳转到登录页并提示"注册成功，请登录"
            return redirect(url_for("login", registered="true"))
        except sqlite3.OperationalError as e:
            error = f"注册失败: {e}"
        except sqlite3.IntegrityError:
            error = "用户名已存在，请选择其他用户名"

    return render_template("register.html", error=error)


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
    print("  Day3 - 用户登录管理平台 (SQL注入漏洞版)")
    print("=" * 55)
    print(f"  ⚠️  SQL注入漏洞: 已引入")
    print(f"  ⚠️  字符串拼接: 登录/注册/搜索")
    print(f"  ⚠️  无输入过滤: 已确认")
    print(f"  ⚠️  搜索结果: 直接回显在首页")
    print(f"  Debug模式: {'开启' if DEBUG else '关闭'}")
    print(f"  数据库: {DATABASE}")
    print("=" * 55)
    print(f"  访问地址: http://0.0.0.0:5000")
    print("=" * 55)

    with app.app_context():
        init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
