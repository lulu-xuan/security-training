"""
Day4 - 用户登录管理平台 (文件上传漏洞版本)
=========================================
⚠️ 警告: 此版本故意包含文件上传漏洞，仅供安全教学使用！

新增漏洞:
  漏洞4: 无文件类型检查 (任意文件可上传)
  漏洞5: 使用原始文件名 (路径遍历/覆盖风险)
  漏洞6: 文件保存到可访问的静态目录
"""

import os
import sqlite3
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, url_for, g,
    send_from_directory
)
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Secret Key
_SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-day4-vuln")
app.secret_key = _SECRET_KEY

# Session 配置
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True

# ⚠️ 漏洞: 设置 MAX_CONTENT_LENGTH = 16MB，但不上传时的文件类型检查
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Debug 由环境变量控制
DEBUG = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

# 数据库路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "data", "users.db")

# ⚠️ 漏洞: 上传目录设为 static/uploads/，文件可直接通过 URL 访问
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")


# ============================================================
# 数据库操作
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
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
# 首页
# ============================================================
@app.route("/")
def index():
    username = session.get("username")
    return render_template("index.html", username=username)


# ============================================================
# 搜索
# ============================================================
@app.route("/search")
def search():
    if "username" not in session:
        return redirect(url_for("login"))

    keyword = request.args.get("keyword", "")
    results = None

    if keyword:
        db = get_db()
        query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
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
# 登录
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    registered = request.args.get("registered")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

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
            info_query = f"SELECT id, username, email, phone FROM users WHERE username='{result['username']}'"
            user_info = db.execute(info_query).fetchone()
            return render_template("index.html", username=session["username"],
                                   user=dict(user_info) if user_info else None)
        else:
            error = "用户名或密码错误"

    return render_template("login.html", error=error, registered=registered)


# ============================================================
# 注册
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        db = get_db()
        query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

        try:
            db.execute(query)
            db.commit()
            return redirect(url_for("login", registered="true"))
        except sqlite3.OperationalError as e:
            error = f"注册失败: {e}"
        except sqlite3.IntegrityError:
            error = "用户名已存在，请选择其他用户名"

    return render_template("register.html", error=error)


# ============================================================
# ⚠️ 漏洞路由: 文件上传 (无文件类型检查，使用原始文件名)
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    """文件上传 — 存在漏洞：无类型检查、原始文件名、直接可访问"""
    if "username" not in session:
        return redirect(url_for("login"))

    error = None
    uploaded_file_url = None
    uploaded_filename = None

    if request.method == "POST":
        # ⚠️ 漏洞: 不检查是否有文件
        file = request.files.get("file")

        if file and file.filename:
            # ⚠️ 漏洞: 使用用户提供的原始文件名（不重命名）
            # ⚠️ 漏洞: 不检查文件后缀名
            # ⚠️ 漏洞: 不检查 MIME 类型
            # ⚠️ 漏洞: 不检查文件内容
            filename = file.filename

            # 保存文件到 static/uploads/ 目录
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)

            # 返回文件访问 URL
            uploaded_file_url = url_for("static", filename=f"uploads/{filename}")
            uploaded_filename = filename
        else:
            error = "请选择一个文件"

    return render_template("upload.html",
                           error=error,
                           uploaded_file_url=uploaded_file_url,
                           uploaded_filename=uploaded_filename)


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
    print("  Day4 - 用户登录管理平台 (文件上传漏洞版)")
    print("=" * 55)
    print(f"  ⚠️  文件上传漏洞: 已引入")
    print(f"  ⚠️  无文件类型检查: 已确认")
    print(f"  ⚠️  使用原始文件名: 已确认")
    print(f"  ⚠️  上传目录: static/uploads/")
    print(f"  Debug模式: {'开启' if DEBUG else '关闭'}")
    print("=" * 55)
    print(f"  访问地址: http://0.0.0.0:5000")
    print("=" * 55)

    with app.app_context():
        init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
