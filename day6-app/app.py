"""
Day6 - 用户登录管理平台 (文件包含漏洞完整版)
==============================================
⚠️ 警告: 此版本故意包含多种文件包含漏洞，仅供安全教学使用！

漏洞场景:
  1 · 基本文件包含 — os.path.join 拼接读取 pages/ 下文件
  2 · 路径遍历 — 使用 ../ 突破目录限制读取任意文件
  3 · 远程文件包含(RFI) — name 参数支持 http:// 远程地址
  4 · 封装协议(data://) — name 参数支持 data://base64 编码
  5 · 日志注入 — User-Agent 写入日志后包含日志文件
  6 · 综合利用 — 多种技术组合突破安全检查
"""

import os
import re
import base64
import sqlite3
import urllib.request
from datetime import timedelta
from functools import wraps
from urllib.parse import unquote

from flask import (
    Flask, render_template, request, redirect, session, url_for, g
)

app = Flask(__name__)

app.secret_key = "dev-key-day6-vuln"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

DEBUG = False
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "data", "users.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
PAGES_DIR = os.path.join(BASE_DIR, "pages")
LOG_DIR = os.path.join(BASE_DIR, "logs")
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None: db.close()

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, email TEXT DEFAULT '', phone TEXT DEFAULT '',
        balance INTEGER DEFAULT 0)""")
    db.execute("""INSERT OR IGNORE INTO users (username,password,email,phone,balance)
        VALUES ('admin','admin123','admin@example.com','13800138000',0)""")
    db.execute("""INSERT OR IGNORE INTO users (username,password,email,phone,balance)
        VALUES ('alice','alice2025','alice@example.com','13900139001',0)""")
    db.commit(); db.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session: return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ⚠️ 漏洞: 日志注入 — 每次请求记录 User-Agent 到日志文件
@app.before_request
def log_user_agent():
    """记录用户请求头到日志文件（用于日志注入攻击）"""
    try:
        ua = request.headers.get("User-Agent", "Unknown")
        ip = request.remote_addr or "0.0.0.0"
        path = request.path
        with open(ACCESS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{ip} - {path} - {ua}\n")
    except:
        pass


# ========== 用户功能 ==========
@app.route("/")
def index():
    return render_template("index.html", username=session.get("username"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None; registered = request.args.get("registered")
    if request.method == "POST":
        u = request.form.get("username",""); p = request.form.get("password","")
        db = get_db()
        r = db.execute(f"SELECT * FROM users WHERE username='{u}' AND password='{p}'").fetchone()
        if r:
            session.permanent = True; session["username"] = r["username"]
            return redirect(url_for("index"))
        else: error = "用户名或密码错误"
    return render_template("login.html", error=error, registered=registered)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        u=request.form.get("username",""); p=request.form.get("password","")
        e=request.form.get("email",""); ph=request.form.get("phone","")
        db = get_db()
        try:
            db.execute(f"INSERT INTO users (username,password,email,phone) VALUES ('{u}','{p}','{e}','{ph}')")
            db.commit(); return redirect(url_for("login", registered="true"))
        except: error="注册失败"
    return render_template("register.html", error=error)

@app.route("/search")
def search():
    if "username" not in session: return redirect(url_for("login"))
    keyword = request.args.get("keyword",""); results = None
    if keyword:
        db = get_db()
        query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        try: results = db.execute(query).fetchall()
        except: results = []
    return render_template("index.html", username=session["username"], results=results, keyword=keyword)

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    e=None; url=None; fn=None
    if request.method=="POST":
        f=request.files.get("file")
        if f and f.filename:
            fn=f.filename
            f.save(os.path.join(UPLOAD_FOLDER,fn))
            url=url_for("static", filename=f"uploads/{fn}")
        else: e="请选择一个文件"
    return render_template("upload.html", error=e, uploaded_file_url=url, uploaded_filename=fn)

# ============================================================
# ⚠️ 核心漏洞路由: 文件包含 (支持6种攻击场景)
# ============================================================
@app.route("/page")
def dynamic_page():
    """文件包含漏洞入口 — 支持基本包含/路径遍历/RFI/data封装/日志包含"""
    name = request.args.get("name", "")
    page_content = None
    source = ""

    # ================================================================
    # 场景3: 远程文件包含 (RFI) — name 以 http 开头
    # ================================================================
    if name.startswith("http://") or name.startswith("https://"):
        try:
            # ⚠️ 漏洞: 从远程 URL 获取内容，可能加载恶意代码
            # ⚠️ 漏洞: 不验证远程服务器是否可信
            # ⚠️ 漏洞: 不检查返回内容类型
            resp = urllib.request.urlopen(name, timeout=5)
            page_content = resp.read().decode("utf-8", errors="replace")
            source = "🌐 远程文件包含 (RFI)"
            return render_template("index.html",
                                   username=session.get("username"),
                                   page_content=page_content,
                                   file_source=source)
        except Exception as err:
            page_content = f"<p>远程文件读取失败: {str(err)}</p>"
            return render_template("index.html",
                                   username=session.get("username"),
                                   page_content=page_content,
                                   file_source=source)

    # ================================================================
    # 场景4: 封装协议 data:// — base64 解码内容
    # ================================================================
    if name.startswith("data://"):
        try:
            # ⚠️ 漏洞: data://text/plain;base64,<base64编码内容>
            # 执行解码后在页面中渲染，可被用于构造任意内容
            data_part = name[len("data://"):]
            if ";base64," in data_part:
                _, b64_data = data_part.split(";base64,", 1)
                decoded = base64.b64decode(b64_data).decode("utf-8", errors="replace")
                page_content = f"<pre>{decoded}</pre>"
                source = "📦 封装协议 data:// (base64解码)"
            else:
                page_content = f"<p>data 内容: {data_part[:200]}</p>"
                source = "📦 封装协议 data://"
            return render_template("index.html",
                                   username=session.get("username"),
                                   page_content=page_content,
                                   file_source=source)
        except Exception as err:
            page_content = f"<p>data 解码失败: {str(err)}</p>"

    # ⚠️ 漏洞: 直接拼接用户输入的 name 到路径中
    # ⚠️ 漏洞: 不检查路径中是否包含 ../
    # ⚠️ 漏洞: 不使用 os.path.abspath/os.path.realpath 规范化
    page_path = os.path.join(PAGES_DIR, name)

    if os.path.exists(page_path) and os.path.isfile(page_path):
        try:
            with open(page_path, "r", encoding="utf-8", errors="replace") as f:
                page_content = f.read()
            source = "📄 基本文件包含" if "../" not in name else "🔀 路径遍历"
        except:
            page_content = "<p>读取文件失败</p>"
    else:
        page_path_html = page_path + ".html"
        if os.path.exists(page_path_html) and os.path.isfile(page_path_html):
            try:
                with open(page_path_html, "r", encoding="utf-8", errors="replace") as f:
                    page_content = f.read()
                source = "📄 基本文件包含 (.html自动补全)"
            except:
                page_content = "<p>读取文件失败</p>"
        else:
            page_content = "<p>页面不存在</p>"

    return render_template("index.html",
                           username=session.get("username"),
                           page_content=page_content,
                           file_source=source)


# ========== 登出 ==========
@app.route("/logout")
def logout():
    session.pop("username", None); return redirect(url_for("index"))


if __name__ == "__main__":
    print("=" * 60)
    print("  Day6 - 文件包含漏洞通关平台 (6种攻击场景)")
    print("=" * 60)
    print("  1 · 基本文件包含:     /page?name=help")
    print("  2 · 路径遍历:        /page?name=../app.py")
    print("  3 · 远程文件包含(RFI): /page?name=http://...")
    print("  4 · 封装协议(data):   /page?name=data://text/plain;base64,...")
    print("  5 · 日志注入:        User-Agent 写入 → /page?name=../logs/access.log")
    print("  6 · 综合利用:        多种技术组合")
    print("=" * 60)
    print(f"  访问地址: http://0.0.0.0:5000")
    print("=" * 60)
    with app.app_context(): init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
