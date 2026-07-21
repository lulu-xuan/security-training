"""
Day4 - upload-labs 文件上传漏洞分析平台
========================================
基于 Flask 实现了 upload-labs Pass-01 ~ Pass-18 的各类文件上传漏洞

漏洞场景列表:
  Pass-01: 前端JS校验 → 禁用JS/直接发包绕过
  Pass-02: MIME类型校验 → 改Content-Type绕过
  Pass-03: 黑名单后缀 → .phtml 替代后缀绕过
  Pass-06: 大小写绕过 → .Php 绕过
  Pass-07: 空格绕过 → .php[空格] 绕过
  Pass-08: 点号绕过 → .php. 绕过
  Pass-11: 双写绕过 → .pphphp 绕过
  Pass-12: GET %00截断 → save_path=%00截断
  Pass-14: 文件头2字节 → 图片马绕过
  Pass-18: 条件竞争 → 先保存后检查，并发绕过
"""

import os
import re
import sqlite3
import time
import threading
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, session, url_for, g
)

app = Flask(__name__)

app.secret_key = "dev-key-day4-upload-labs"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

DEBUG = False
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "data", "users.db")
UPLOAD_BASE = os.path.join(BASE_DIR, "static", "uploads")


# ============================================================
# 数据库 & 登录（复用原平台功能）
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
    os.makedirs(UPLOAD_BASE, exist_ok=True)
    # 创建各场景子目录
    for i in [1, 2, 3, 6, 7, 8, 11, 12, 14, 18]:
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
    db.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')
    """)
    db.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')
    """)
    db.commit()
    db.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ============================================================
# 辅助函数
# ============================================================

def get_pass_dir(pass_num):
    """获取场景上传目录"""
    path = os.path.join(UPLOAD_BASE, f"pass-{pass_num:02d}")
    os.makedirs(path, exist_ok=True)
    return path


BLACKLIST_EXT = [
    'php', 'asp', 'aspx', 'jsp', 'exe', 'bat', 'sh', 'py', 'pl', 'cgi'
]


def get_ext(filename):
    """获取文件后缀（小写）"""
    if '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[-1].lower()


# ============================================================
# 用户功能路由（登录/注册/首页）
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    return render_template("upload_labs_index.html", username=username)


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
            return render_template("upload_labs_login.html", error=error)
        if result:
            session.permanent = True
            session["username"] = result["username"]
            return redirect(url_for("index"))
        else:
            error = "用户名或密码错误"
    return render_template("upload_labs_login.html", error=error, registered=registered)


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
            error = "用户名已存在"
    return render_template("upload_labs_register.html", error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


# ============================================================
# ══════════════════════════════════════════════════════════════
#  Pass-01: 前端 JS 校验 — 禁用JS / 直接发包绕过
# ══════════════════════════════════════════════════════════════
#  防御: 前端 JS 检查后缀是否为 .jpg/.png/.gif
#  绕过: ①禁用JS ②Burp直接发包 ③Console改accept
#  后端: 无检查
# ============================================================
ALLOWED_EXT_JS = {'jpg', 'jpeg', 'png', 'gif'}

@app.route("/upload/pass-01", methods=["GET", "POST"])
@login_required
def upload_pass_01():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            filename = f.filename
            save_path = os.path.join(get_pass_dir(1), filename)
            f.save(save_path)
            file_url = url_for("static", filename=f"uploads/pass-01/{filename}")
            msg = f"上传成功！文件: {filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=1,
                           pass_title="前端JS校验", msg=msg, file_url=file_url,
                           desc="防御：前端JS检查后缀（.jpg/.png/.gif）",
                           bypass="绕过：禁用JS 或 Burp直接发包（后端无检查）",
                           check_js=True)


# ============================================================
#  Pass-02: MIME 类型校验 — 改 Content-Type 绕过
# ============================================================
ALLOWED_MIME = {'image/jpeg', 'image/png', 'image/gif'}

@app.route("/upload/pass-02", methods=["GET", "POST"])
@login_required
def upload_pass_02():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # ⚠️ 防御: 检查 Content-Type
            content_type = f.content_type or ''
            if content_type not in ALLOWED_MIME:
                msg = f"禁止上传该类型文件！(Content-Type: {content_type})"
            else:
                filename = f.filename
                f.save(os.path.join(get_pass_dir(2), filename))
                file_url = url_for("static", filename=f"uploads/pass-02/{filename}")
                msg = f"上传成功！文件: {filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=2,
                           pass_title="MIME类型校验", msg=msg, file_url=file_url,
                           desc="防御：检查 Content-Type 是否为 image/jpeg|png|gif",
                           bypass="绕过：Burp截获请求，改 Content-Type: image/jpeg")


# ============================================================
#  Pass-03: 黑名单后缀 — 替代后缀绕过 (.phtml / .php5)
# ============================================================
PASS03_BLACKLIST = {'asp', 'aspx', 'php', 'jsp'}

@app.route("/upload/pass-03", methods=["GET", "POST"])
@login_required
def upload_pass_03():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            ext = get_ext(f.filename)
            if ext in PASS03_BLACKLIST:
                msg = f"禁止上传 {ext} 后缀文件！(黑名单: asp/aspx/php/jsp)"
            else:
                filename = f.filename
                f.save(os.path.join(get_pass_dir(3), filename))
                file_url = url_for("static", filename=f"uploads/pass-03/{filename}")
                msg = f"上传成功！文件: {filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=3,
                           pass_title="黑名单后缀", msg=msg, file_url=file_url,
                           desc="防御：黑名单仅禁止 asp/aspx/php/jsp",
                           bypass="绕过：用 .phtml / .php5 / .php3 替代 .php")


# ============================================================
#  Pass-06: 大小写绕过 — .Php 绕过（黑名单全小写，无strtolower）
# ============================================================
PASS06_BLACKLIST = {'php', 'asp', 'aspx', 'jsp', 'exe', 'bat'}

@app.route("/upload/pass-06", methods=["GET", "POST"])
@login_required
def upload_pass_06():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # ⚠️ 漏洞: 直接取原始后缀，不做小写转换
            orig_ext = f.filename.rsplit('.', 1)[-1] if '.' in f.filename else ''
            # 黑名单中全是小写
            if orig_ext in PASS06_BLACKLIST:
                msg = f"禁止上传 {orig_ext} 后缀文件！"
            else:
                filename = f.filename
                f.save(os.path.join(get_pass_dir(6), filename))
                file_url = url_for("static", filename=f"uploads/pass-06/{filename}")
                msg = f"上传成功！文件: {filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=6,
                           pass_title="大小写绕过", msg=msg, file_url=file_url,
                           desc="防御：黑名单全小写，但未转小写比较",
                           bypass="绕过：将 .php 改为 .Php / .PHP / .pHp")


# ============================================================
#  Pass-07: 空格绕过 — .php[空格] 绕过（无trim）
# ============================================================
PASS07_BLACKLIST = {'php', 'asp', 'aspx', 'jsp', 'phtml', 'php5'}

@app.route("/upload/pass-07", methods=["GET", "POST"])
@login_required
def upload_pass_07():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # ⚠️ 漏洞: 直接取后缀，不做 trim()
            ext = get_ext(f.filename)
            if ext in PASS07_BLACKLIST:
                msg = f"禁止上传 {ext} 后缀文件！"
            else:
                filename = f.filename
                f.save(os.path.join(get_pass_dir(7), filename))
                file_url = url_for("static", filename=f"uploads/pass-07/{filename}")
                msg = f"上传成功！文件: {filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=7,
                           pass_title="空格绕过", msg=msg, file_url=file_url,
                           desc="防御：黑名单检查后缀，但未 trim() 去空格",
                           bypass="绕过：Burp截获，文件名改为 shell.php[空格]")


# ============================================================
#  Pass-08: 点号绕过 — .php. 绕过（无deldot）
# ============================================================
PASS08_BLACKLIST = {'php', 'asp', 'aspx', 'jsp', 'phtml', 'php5', 'php '}

@app.route("/upload/pass-08", methods=["GET", "POST"])
@login_required
def upload_pass_08():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # ⚠️ 漏洞: 不做 deldot()，尾部点号保留
            ext = get_ext(f.filename)
            if ext in PASS08_BLACKLIST:
                msg = f"禁止上传 {ext} 后缀文件！"
            else:
                filename = f.filename
                f.save(os.path.join(get_pass_dir(8), filename))
                file_url = url_for("static", filename=f"uploads/pass-08/{filename}")
                msg = f"上传成功！文件: {filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=8,
                           pass_title="点号绕过", msg=msg, file_url=file_url,
                           desc="防御：黑名单检查，但未删除尾部点号",
                           bypass="绕过：Burp截获，文件名改为 shell.php.")


# ============================================================
#  Pass-11: 双写绕过 — .pphphp 绕过（str_ireplace只替换一次）
# ============================================================
PASS11_BLACKLIST = ['php', 'asp', 'aspx', 'jsp', 'phtml', 'php5']

@app.route("/upload/pass-11", methods=["GET", "POST"])
@login_required
def upload_pass_11():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            orig_filename = f.filename
            # ⚠️ 漏洞: 只替换第一次出现的黑名单词（应全部替换但代码只做一次）
            filename = orig_filename
            for bad_ext in PASS11_BLACKLIST:
                filename = filename.replace(bad_ext, "", 1)  # 仅替换一次！
            ext = get_ext(filename)
            # 保存原始文件（含双写），但用处理后的ext做检查
            if ext in PASS11_BLACKLIST:
                msg = "禁止上传该类型文件！"
            else:
                # 注意：这里保存的是原始文件（含双写），但重命名后的filename去掉了黑名单词
                # 实际upload-labs保存的是原始文件名，但rename时用处理过的
                # 我们这里模拟：保存原始文件，但校验的是处理后的
                orig_name = f.filename
                f.save(os.path.join(get_pass_dir(11), orig_name))
                file_url = url_for("static", filename=f"uploads/pass-11/{orig_name}")
                msg = f"上传成功！文件: {orig_name}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=11,
                           pass_title="双写绕过", msg=msg, file_url=file_url,
                           desc="防御：str_ireplace 过滤黑名单词，但仅替换一次",
                           bypass="绕过：shell.php → shell.pphphp，删除中间php后变成shell.php")


# ============================================================
#  Pass-12: GET %00 截断 — save_path=%00 截断路径
# ============================================================
PASS12_ALLOWED_EXT = {'jpg', 'jpeg', 'png', 'gif'}

@app.route("/upload/pass-12", methods=["GET", "POST"])
@login_required
def upload_pass_12():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            ext = get_ext(f.filename)
            # 白名单：只允许图片后缀
            if ext not in PASS12_ALLOWED_EXT:
                msg = f"只允许上传 {','.join(PASS12_ALLOWED_EXT)} 文件！"
            else:
                # ⚠️ 从 GET 参数获取 save_path，存在 %00 截断漏洞
                save_path = request.args.get("save_path", "")
                if save_path:
                    # ⚠️ %00 截断：PHP < 5.3.4 中 %00 会截断字符串
                    # 在 Python 中模拟：如果 path 包含 %00 或 \x00，取截断前部分
                    null_pos = save_path.find('\x00')
                    if null_pos != -1:
                        save_path = save_path[:null_pos]
                    save_dir = os.path.join(UPLOAD_BASE, "pass-12", save_path)
                    os.makedirs(os.path.dirname(save_dir), exist_ok=True)
                    final_path = save_dir if '.' in os.path.basename(save_dir) else \
                        os.path.join(save_dir, f.filename)
                else:
                    final_path = os.path.join(get_pass_dir(12), f.filename)

                os.makedirs(os.path.dirname(final_path), exist_ok=True)
                f.save(final_path)

                rel_path = os.path.relpath(final_path, os.path.join(BASE_DIR, "static"))
                file_url = url_for("static", filename=rel_path)
                msg = f"上传成功！文件保存到: {os.path.basename(final_path)}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=12,
                           pass_title="GET %00截断", msg=msg, file_url=file_url,
                           desc="防御：白名单只允许图片后缀 + save_path参数拼接路径",
                           bypass="绕过：上传.jpg文件，URL加 ?save_path=shell.php%00")


# ============================================================
#  Pass-14: 文件头2字节检查 → 图片马绕过
# ============================================================
FILE_HEADERS = {
    (0xFF, 0xD8): 'jpg',
    (0x89, 0x50): 'png',
    (0x47, 0x49): 'gif',
}

@app.route("/upload/pass-14", methods=["GET", "POST"])
@login_required
def upload_pass_14():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # ⚠️ 防御: 读取文件前2字节检查文件头
            head = f.read(2)
            f.seek(0)  # 回到文件开头
            detected_type = FILE_HEADERS.get((head[0], head[1])) if len(head) >= 2 else None

            if detected_type is None:
                msg = f"文件类型不被允许！(前2字节: {head.hex() if len(head)>=2 else '不足'})"
            else:
                filename = f.filename
                f.save(os.path.join(get_pass_dir(14), filename))
                file_url = url_for("static", filename=f"uploads/pass-14/{filename}")
                msg = f"上传成功！检测到 {detected_type.upper()} 格式，文件: {filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=14,
                           pass_title="文件头检查", msg=msg, file_url=file_url,
                           desc="防御：读取前2字节检查文件头(FFD8/8950/4749)",
                           bypass="绕过：制作图片马(copy /b 图片.jpg+shell.php=webshell.jpg)")


# ============================================================
#  Pass-18: 条件竞争 — 先保存后检查，并发绕过
# ============================================================
PASS18_BLACKLIST = {'php', 'asp', 'aspx', 'jsp', 'phtml', 'php5'}

# 用于条件竞争的临时文件目录
RACE_DIR = os.path.join(UPLOAD_BASE, "pass-18", "race_tmp")
os.makedirs(RACE_DIR, exist_ok=True)

@app.route("/upload/pass-18", methods=["GET", "POST"])
@login_required
def upload_pass_18():
    msg = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            ext = get_ext(f.filename)
            # ⚠️ 漏洞: 先保存到临时目录
            temp_name = f"temp_{int(time.time())}_{f.filename}"
            temp_path = os.path.join(RACE_DIR, temp_name)
            f.save(temp_path)

            # 然后再检查后缀
            if ext in PASS18_BLACKLIST:
                # 检查不合格 → 删除
                try:
                    os.remove(temp_path)
                except:
                    pass
                msg = f"禁止上传 {ext} 后缀文件！(已删除)"
            else:
                # 合法 → 移动到正式目录
                final_path = os.path.join(get_pass_dir(18), f.filename)
                os.rename(temp_path, final_path)
                file_url = url_for("static", filename=f"uploads/pass-18/{f.filename}")
                msg = f"上传成功！文件: {f.filename}"
        else:
            msg = "请选择一个文件"
    return render_template("upload_pass.html", pass_num=18,
                           pass_title="条件竞争", msg=msg, file_url=file_url,
                           desc="防御：先保存到临时目录→检查后缀→合法则保留/非法则删除",
                           bypass="绕过：在「保存」和「删除」的时间窗口内并发访问临时文件")


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  Day4 - upload-labs 文件上传漏洞分析平台")
    print("=" * 60)
    print("  漏洞场景列表:")
    print("    Pass-01: 前端JS校验")
    print("    Pass-02: MIME类型校验")
    print("    Pass-03: 黑名单后缀")
    print("    Pass-06: 大小写绕过")
    print("    Pass-07: 空格绕过")
    print("    Pass-08: 点号绕过")
    print("    Pass-11: 双写绕过")
    print("    Pass-12: GET %00截断")
    print("    Pass-14: 文件头检查")
    print("    Pass-18: 条件竞争")
    print("=" * 60)
    print("  访问地址: http://0.0.0.0:5000")
    print("=" * 60)
    with app.app_context():
        init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
