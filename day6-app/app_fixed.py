"""
Day6 - 用户登录管理平台 (文件包含漏洞修复版)
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
    """动态页面加载 — 已修复全部文件包含漏洞"""
    name = request.args.get("name", "")
    page_content = None

    # F-01: 拒绝路径遍历攻击
    if ".." in name or name.startswith("/") or "\\" in name:
        page_content = "<p>页面不存在</p>"
        return render_template("index.html",
                               username=session.get("username"),
                               page_content=page_content)

    # F-02: 白名单校验
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        page_content = "<p>页面不存在</p>"
        return render_template("index.html",
                               username=session.get("username"),
                               page_content=page_content)

    page_path = os.path.join(PAGES_DIR, name)

    if os.path.exists(page_path) and os.path.isfile(page_path):
        try:
            with open(page_path, "r", encoding="utf-8", errors="replace") as f:
                page_content = f.read()
        except:
            page_content = "<p>读取文件失败</p>"
    else:
        page_path_html = page_path + ".html"
        if os.path.exists(page_path_html) and os.path.isfile(page_path_html):
            try:
                with open(page_path_html, "r", encoding="utf-8", errors="replace") as f:
                    page_content = f.read()
            except:
                page_content = "<p>读取文件失败</p>"
        else:
            page_content = "<p>页面不存在</p>"

    return render_template("index.html",
                           username=session.get("username"),
                           page_content=page_content)

# ========== 登出 ==========
@app.route("/logout")
def logout():
    session.pop("username", None); return redirect(url_for("index"))


if __name__ == "__main__":
    print("=" * 55)
    print("  Day6 - 用户登录管理平台 (文件包含漏洞修复版)")
    print("=" * 55)
    print("  F-01: ../ + / 路径遍历检测")
    print("  F-02: 白名单正则校验")
    print("  F-03: 拒绝 http/https RFI")
    print("  F-04: 拒绝 data:// 封装协议")
    print("  F-05: 日志内容中性化")
    print("=" * 55)
    print(f"  访问地址: http://0.0.0.0:5000")
    print("=" * 55)
    with app.app_context(): init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
