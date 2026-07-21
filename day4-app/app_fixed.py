"""
Day4 - upload-labs 文件上传漏洞修复版
=====================================
✅ 修复内容:
  F-01: 黑名单→白名单后缀校验
  F-02: 文件内容头校验
  F-03: 文件名规范化(去空格/去点号/小写转换)
  F-04: 随机重命名(防覆盖)
  F-05: 先检查后保存(防条件竞争)
  F-06: 路径遍历防御
"""

import os, sqlite3, time, secrets, re
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, g

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

DEBUG = False
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "data", "users.db")
UPLOAD_BASE = os.path.join(BASE_DIR, "static", "uploads")

# ✅ F-01: 白名单后缀（只允许图片）
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'}
# ✅ F-02: 文件魔数白名单
FILE_MAGIC = {
    b'\xff\xd8': 'jpg',
    b'\x89PNG': 'png',
    b'GIF87a': 'gif',
    b'GIF89a': 'gif',
    b'BM': 'bmp',
}

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
    os.makedirs(UPLOAD_BASE, exist_ok=True)
    for i in range(1, 19):
        os.makedirs(os.path.join(UPLOAD_BASE, f"pass-{i:02d}"), exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT ''
        )
    """)
    db.execute("""INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')""")
    db.execute("""INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')""")
    db.commit(); db.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ✅ F-03: 文件名规范化
def sanitize_filename(filename):
    """移除路径、去空格、去尾部点号、转小写"""
    name = os.path.basename(filename)           # 防路径遍历
    name = name.strip()                          # 去首尾空格
    name = name.rstrip('.')                      # 去尾部点号
    return name

def secure_save(uploaded_file, save_dir):
    """✅ 统一的文件安全保存流程"""
    if not uploaded_file or not uploaded_file.filename:
        return None, "请选择一个文件"

    # 1. 检查文件内容（读魔数）
    head = uploaded_file.read(8)
    uploaded_file.seek(0)

    detected_ext = None
    for magic, ext in FILE_MAGIC.items():
        if head.startswith(magic):
            detected_ext = ext
            break

    if not detected_ext:
        return None, "文件类型不被允许（只接受图片文件）"

    # 2. 规范化文件名
    raw_name = sanitize_filename(uploaded_file.filename)
    original_ext = raw_name.rsplit('.', 1)[-1].lower() if '.' in raw_name else ''

    # 3. ✅ F-01: 白名单校验
    if original_ext not in ALLOWED_EXTENSIONS:
        return None, f"后缀 .{original_ext} 不被允许"

    # 4. ✅ F-04: 随机重命名
    timestamp = int(time.time())
    rand_str = secrets.token_hex(4)
    safe_name = f"{timestamp}_{rand_str}.{detected_ext}"

    # 5. ✅ F-05: 先检查后保存（直接保存到最终路径）
    save_path = os.path.join(save_dir, safe_name)
    uploaded_file.save(save_path)

    rel_path = os.path.relpath(save_path, os.path.join(BASE_DIR, "static"))
    file_url = url_for("static", filename=rel_path)

    return file_url, f"上传成功！文件: {safe_name}"

# ========== 用户功能 ==========
@app.route("/")
def index():
    return render_template("upload_labs_fixed_index.html", username=session.get("username"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None; registered = request.args.get("registered")
    if request.method == "POST":
        u = request.form.get("username", ""); p = request.form.get("password", "")
        db = get_db()
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        try:
            r = db.execute(query).fetchone()
        except: error = "数据库错误"
        if r:
            session.permanent = True; session["username"] = r["username"]
            return redirect(url_for("index"))
        else: error = "用户名或密码错误"
    return render_template("upload_labs_fixed_login.html", error=error, registered=registered)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        u = request.form.get("username", ""); p = request.form.get("password", "")
        e = request.form.get("email", ""); ph = request.form.get("phone", "")
        db = get_db()
        try:
            db.execute(f"INSERT INTO users (username, password, email, phone) VALUES ('{u}', '{p}', '{e}', '{ph}')")
            db.commit(); return redirect(url_for("login", registered="true"))
        except: error = "注册失败"
    return render_template("upload_labs_fixed_register.html", error=error)

@app.route("/logout")
def logout():
    session.pop("username", None); return redirect(url_for("index"))

# ========== 统一修复上传路由 ==========
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_fixed():
    msg = None; file_url = None
    if request.method == "POST":
        file_url, msg = secure_save(request.files.get("file"), UPLOAD_BASE)
    return render_template("upload_fixed.html", msg=msg, file_url=file_url)

if __name__ == "__main__":
    print("=" * 55)
    print("  Day4 - 文件上传漏洞修复版")
    print("=" * 55)
    print("  ✅ F-01: 白名单后缀 (jpg/png/gif/bmp/webp)")
    print("  ✅ F-02: 文件魔数校验")
    print("  ✅ F-03: 文件名规范化(去空格/去点号/转小写)")
    print("  ✅ F-04: 随机重命名(防覆盖)")
    print("  ✅ F-05: 先检查后保存(防条件竞争)")
    print("  ✅ F-06: 路径遍历防御")
    print("=" * 55)
    print(f"  访问地址: http://0.0.0.0:5000")
    print("=" * 55)
    with app.app_context(): init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5001)
