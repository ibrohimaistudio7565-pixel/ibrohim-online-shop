import os, sqlite3, secrets, hmac, hashlib, time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = APP_DIR / "shop.db"
ALLOWED = {"png", "jpg", "jpeg", "webp", "gif"}

app = Flask(__name__)
app.secret_key = os.environ.get("SHOP_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=5 * 1024 * 1024)
ADMIN_PIN_HASH = generate_password_hash(os.environ.get("SHOP_ADMIN_PIN", "7565"))
COMMISSION_RATE = 0.01
LANGS = {
    "uz": {"home":"Bosh sahifa","login":"Kirish","register":"Ro‘yxatdan o‘tish","products":"Mahsulotlar","sell":"Sotuvchi bo‘lish","logout":"Chiqish","add":"Mahsulot qo‘shish","buy":"Sotib olish","price":"Narx","review":"Fikr bildirish","admin":"Admin panel"},
    "en": {"home":"Home","login":"Login","register":"Register","products":"Products","sell":"Become a seller","logout":"Logout","add":"Add product","buy":"Buy","price":"Price","review":"Review","admin":"Admin panel"},
    "ru": {"home":"Главная","login":"Войти","register":"Регистрация","products":"Товары","sell":"Стать продавцом","logout":"Выйти","add":"Добавить товар","buy":"Купить","price":"Цена","review":"Отзыв","admin":"Панель администратора"},
    "zh": {"home":"首页","login":"登录","register":"注册","products":"商品","sell":"成为卖цом","logout":"退出","add":"添加商品","buy":"购买","price":"价格","review":"评价","admin":"管理面板"},
    "ko": {"home":"홈","login":"로그인","register":"가입","products":"상품","sell":"판매자 되기","logout":"로그아웃","add":"상품 추가","buy":"구매","price":"가격","review":"리뷰","admin":"관리자 패널"},
    "ar": {"home":"الرئيسية","login":"دخول","register":"تسجيل","products":"المنتجات","sell":"كن بائعاً","logout":"خروج","add":"إضافة منتج","buy":"شراء","price":"السعر","review":"تقييم","admin":"لوحة الإدارة"}
}

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'buyer',
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS subscriptions(
          id INTEGER PRIMARY KEY, seller_id INTEGER NOT NULL, plan TEXT NOT NULL,
          price REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          starts_at TEXT, ends_at TEXT, FOREIGN KEY(seller_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS products(
          id INTEGER PRIMARY KEY, seller_id INTEGER NOT NULL, title TEXT NOT NULL,
          description TEXT, price REAL NOT NULL CHECK(price >= 0), image TEXT,
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
          FOREIGN KEY(seller_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS orders(
          id INTEGER PRIMARY KEY, buyer_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
          seller_id INTEGER NOT NULL, amount REAL NOT NULL, commission REAL NOT NULL,
          created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'completed',
          FOREIGN KEY(buyer_id) REFERENCES users(id),
          FOREIGN KEY(product_id) REFERENCES products(id));
        CREATE TABLE IF NOT EXISTS reviews(
          id INTEGER PRIMARY KEY, order_id INTEGER UNIQUE NOT NULL, product_id INTEGER NOT NULL,
          buyer_id INTEGER NOT NULL, stars INTEGER NOT NULL CHECK(stars BETWEEN 1 AND 5),
          comment TEXT, created_at TEXT NOT NULL,
          FOREIGN KEY(order_id) REFERENCES orders(id));
        CREATE TABLE IF NOT EXISTS expenses(
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, amount REAL NOT NULL CHECK(amount >= 0),
          created_at TEXT NOT NULL);
        """)
init_db()

def csrf_token():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def protect_post():
    if request.method == "POST":
        token = request.form.get("_csrf", "")
        if not token or not hmac.compare_digest(token, session.get("_csrf", "")):
            abort(400, "CSRF tekshiruvidan o‘tmadi.")

def current_user():
    if session.get("uid"):
        with db() as c: return c.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    return None

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            flash("Avval tizimga kiring.")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper

def seller_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        u = current_user()
        if u["role"] != "seller": abort(403)
        with db() as c:
            sub = c.execute("SELECT * FROM subscriptions WHERE seller_id=? AND status='active' AND ends_at>?",
                            (u["id"], datetime.utcnow().isoformat())).fetchone()
        if not sub:
            flash("Mahsulot sotish uchun faol obuna kerak. Oylik $1 yoki yillik $10.")
            return redirect(url_for("plans"))
        return fn(*a, **kw)
    return wrapper

BASE = """
<!doctype html><html lang="{{lang}}" dir="{{'rtl' if lang=='ar' else 'ltr'}}"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IBROHIM ONLINE SHOP</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f4f6fb;color:#172033;font:16px Arial}
header{background:#111d3b;color:white;padding:18px max(4%,calc((100% - 1100px)/2));display:flex;gap:18px;align-items:center;justify-content:space-between;flex-wrap:wrap}
a{color:#315bd6;text-decoration:none}header a{color:white}.brand{font-weight:800;font-size:20px}
nav{display:flex;gap:14px;flex-wrap:wrap}main{max-width:1100px;margin:28px auto;padding:0 16px}
.card{background:white;padding:20px;border-radius:15px;box-shadow:0 5px 22px #1720330d;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
input,textarea,select{width:100%;padding:12px;border:1px solid #d6dbea;border-radius:9px;margin:7px 0 14px}
button,.btn{display:inline-block;border:0;border-radius:9px;background:#315bd6;color:white;padding:11px 16px;cursor:pointer}
img.product{width:100%;height:170px;object-fit:cover;border-radius:10px;background:#edf0f7}
small,.muted{color:#68738a}.flash{background:#fff1c9;padding:12px;border-radius:8px;margin:10px 0}
table{width:100%;border-collapse:collapse;background:white}td,th{padding:10px;border-bottom:1px solid #e6e9f0;text-align:left}
.stat{font-size:25px;font-weight:bold;color:#244bc1}.danger{background:#a92d3b}
</style>
<header><a class="brand" href="/">IBROHIM ONLINE SHOP</a><nav>
<a href="/">{{t.home}}</a><a href="/">{{t.products}}</a>
{% if user %}<a href="/sell">{{t.add}}</a><a href="/logout">{{t.logout}}</a>
{% else %}<a href="/login">{{t.login}}</a><a href="/register">{{t.register}}</a>{% endif %}
<a href="/plans">Tariflar</a><a href="/ai">AI</a>
<form method="post" action="/language" style="margin:0"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
<select name="lang" onchange="this.form.submit()" style="margin:0;padding:6px">
{% for code,label in [('uz','O‘zbek'),('en','English'),('ru','Русский'),('zh','中文'),('ko','한국어'),('ar','العربية')] %}
<option value="{{code}}" {{'selected' if lang==code else ''}}>{{label}}</option>{% endfor %}
</select></form></nav></header><main>
{% for m in get_flashed_messages() %}<div class="flash">{{m}}</div>{% endfor %}
{{body|safe}}
<footer class="muted" style="padding:25px 0">© {{year}} IBROHIM ONLINE SHOP · Demo MVP</footer></main></html>
"""
def page(body, **kwargs):
    lang = session.get("lang","uz")
    return render_template_string(BASE, body=render_template_string(body, **kwargs),
        user=current_user(), lang=lang, t=LANGS[lang], year=datetime.now().year)

@app.get("/")
def home():
    with db() as c:
        products = c.execute("""SELECT p.*,u.name seller,
          (SELECT ROUND(AVG(stars),1) FROM reviews r WHERE r.product_id=p.id) rating
          FROM products p JOIN users u ON u.id=p.seller_id WHERE p.active=1 ORDER BY p.id DESC""").fetchall()
    body = """<h1>IBROHIM ONLINE SHOP</h1><p class="muted">Bir joyda xarid qiling, soting va rivojlaning.</p>
    <div class="grid">{% for p in products %}<div class="card">
    {% if p.image %}<img class="product" src="/uploads/{{p.image}}">{% else %}<div class="product"></div>{% endif %}
    <h3>{{p.title}}</h3><p>{{p.description or ''}}</p><b>{{'%.2f'|format(p.price)}} USD</b>
    <p class="muted">Sotuvchi: {{p.seller}} · ⭐ {{p.rating or '—'}}</p>
    <a class="btn" href="/product/{{p.id}}">Ko‘rish / Buyurtma</a></div>{% else %}
    <div class="card">Hozircha mahsulot yo‘q. Birinchi sotuvchi bo‘ling!</div>{% endfor %}</div>"""
    return page(body, products=products)

@app.post("/language")
def language():
    lang=request.form.get("lang","uz")
    session["lang"] = lang if lang in LANGS else "uz"
    return redirect(request.referrer or "/")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower()
        pw=request.form.get("password","")
        if len(name)<2 or "@" not in email or len(pw)<10:
            flash("Ism, to‘g‘ri email va kamida 10 belgili parol kiriting.")
        else:
            try:
                with db() as c:
                    c.execute("INSERT INTO users(name,email,password,created_at) VALUES(?,?,?,?)",
                              (name,email,generate_password_hash(pw),datetime.utcnow().isoformat()))
                flash("Hisob yaratildi. Endi tizimga kiring."); return redirect("/login")
            except sqlite3.IntegrityError: flash("Bu email avval ro‘yxatdan o‘tgan.")
    return page("""<div class="card" style="max-width:480px;margin:auto"><h2>Ro‘yxatdan o‘tish</h2>
    <form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
    Ism<input name="name" required> Email<input name="email" type="email" required>
    Parol (kamida 10 belgi)<input name="password" type="password" minlength="10" required>
    <button>Hisob yaratish</button></form></div>""")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        with db() as c: u=c.execute("SELECT * FROM users WHERE email=?",(request.form.get("email","").lower(),)).fetchone()
        if u and check_password_hash(u["password"],request.form.get("password","")):
            session.clear(); session["uid"]=u["id"]; session["_csrf"]=secrets.token_urlsafe(24)
            return redirect("/")
        flash("Email yoki parol noto‘g‘ri.")
    return page("""<div class="card" style="max-width:480px;margin:auto"><h2>Kirish</h2><form method="post">
    <input type="hidden" name="_csrf" value="{{csrf_token()}}">Email<input name="email" type="email" required>
    Parol<input name="password" type="password" required><button>Kirish</button></form></div>""")

@app.get("/logout")
def logout(): session.clear(); return redirect("/")

@app.route("/plans", methods=["GET","POST"])
@login_required
def plans():
    u=current_user()
    if request.method=="POST":
        plan=request.form.get("plan")
        if plan not in ("monthly","yearly"): abort(400)
        price=1 if plan=="monthly" else 10
        with db() as c:
            c.execute("UPDATE users SET role='seller' WHERE id=?",(u["id"],))
            c.execute("INSERT INTO subscriptions(seller_id,plan,price,status) VALUES(?,?,?,'pending')",
                      (u["id"],plan,price))
        flash("Obuna so‘rovi yaratildi. To‘lov integratsiyasi ulanmaguncha admin obunani qo‘lda faollashtiradi.")
        return redirect("/")
    return page("""<div class="card"><h2>Sotuvchi tariflari</h2><p>Ro‘yxatdan o‘tish bepul. Savdo qilish uchun obuna kerak.</p>
    <form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
    <button name="plan" value="monthly">Oyiga $1</button> <button name="plan" value="yearly">Yiliga $10</button></form>
    <p>Har bir yakunlangan sotuvdan 1% komissiya olinadi.</p></div>""")

@app.route("/sell", methods=["GET","POST"])
@seller_required
def sell():
    if request.method=="POST":
        title=request.form.get("title","").strip(); desc=request.form.get("description","").strip()
        try: price=float(request.form.get("price","0"))
        except ValueError: price=-1
        f=request.files.get("image"); filename=None
        if f and f.filename:
            safe=secure_filename(f.filename); ext=safe.rsplit(".",1)[-1].lower() if "." in safe else ""
            if ext not in ALLOWED: flash("Rasm formati png, jpg, jpeg, webp yoki gif bo‘lishi kerak."); return redirect("/sell")
            filename=secrets.token_hex(12)+"."+ext; f.save(UPLOAD_DIR/filename)
        if not title or price<0: flash("Mahsulot nomi va to‘g‘ri narx kiriting.")
        else:
            with db() as c:
                c.execute("INSERT INTO products(seller_id,title,description,price,image,created_at) VALUES(?,?,?,?,?,?)",
                          (current_user()["id"],title,desc,price,filename,datetime.utcnow().isoformat()))
            flash("Mahsulot joylandi."); return redirect("/")
    return page("""<div class="card"><h2>Mahsulot joylash</h2><form method="post" enctype="multipart/form-data">
    <input type="hidden" name="_csrf" value="{{csrf_token()}}">Nomi<input name="title" required>
    Tavsif<textarea name="description"></textarea>Narxi (USD)<input name="price" type="number" min="0" step=".01" required>
    Rasm<input name="image" type="file" accept="image/*"><button>Joylash</button></form></div>""")

@app.get("/product/<int:pid>")
def product(pid):
    with db() as c:
        p=c.execute("SELECT p.*,u.name seller FROM products p JOIN users u ON u.id=p.seller_id WHERE p.id=? AND p.active=1",(pid,)).fetchone()
        reviews=c.execute("SELECT r.*,u.name FROM reviews r JOIN users u ON u.id=r.buyer_id WHERE product_id=? ORDER BY r.id DESC",(pid,)).fetchall()
    if not p: abort(404)
    return page("""<div class="card">{% if p.image %}<img class="product" style="max-width:420px" src="/uploads/{{p.image}}">{% endif %}
    <h2>{{p.title}}</h2><p>{{p.description}}</p><h3>{{'%.2f'|format(p.price)}} USD</h3><p>Sotuvchi: {{p.seller}}</p>
    {% if user %}<form method="post" action="/buy/{{p.id}}"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><button>Sotib olish</button></form>{% else %}<a href="/login">Xarid qilish uchun kiring</a>{% endif %}</div>
    <div class="card"><h3>Baholar va fikrlar</h3>{% for r in reviews %}<p>{{'⭐'*r.stars}} — {{r.comment}} <small>({{r.name}})</small></p>{% else %}<p>Hali fikr yo‘q.</p>{% endfor %}</div>""",p=p,reviews=reviews)

@app.post("/buy/<int:pid>")
@login_required
def buy(pid):
    with db() as c:
        p=c.execute("SELECT * FROM products WHERE id=? AND active=1",(pid,)).fetchone()
        if not p: abort(404)
        if p["seller_id"]==current_user()["id"]: flash("O‘zingizning mahsulotingizni sotib ololmaysiz."); return redirect("/")
        commission=round(p["price"]*COMMISSION_RATE,2)
        cur=c.execute("INSERT INTO orders(buyer_id,product_id,seller_id,amount,commission,created_at) VALUES(?,?,?,?,?,?)",
          (current_user()["id"],pid,p["seller_id"],p["price"],commission,datetime.utcnow().isoformat()))
        oid=cur.lastrowid
    flash(f"Buyurtma #{oid} demo rejimida yaratildi. Haqiqiy to‘lov hali ulanmagan.")
    return redirect(f"/review/{oid}")

@app.route("/review/<int:oid>",methods=["GET","POST"])
@login_required
def review(oid):
    with db() as c:
        order=c.execute("SELECT * FROM orders WHERE id=? AND buyer_id=?",(oid,current_user()["id"])).fetchone()
        if not order: abort(404)
        if request.method=="POST":
            try: stars=int(request.form.get("stars","5"))
            except ValueError: stars=0
            if not 1<=stars<=5: abort(400)
            try:
                c.execute("INSERT INTO reviews(order_id,product_id,buyer_id,stars,comment,created_at) VALUES(?,?,?,?,?,?)",
                    (oid,order["product_id"],current_user()["id"],stars,request.form.get("comment","")[:1000],datetime.utcnow().isoformat()))
                flash("Fikringiz saqlandi.")
            except sqlite3.IntegrityError: flash("Bu buyurtmaga allaqachon baho bergansiz.")
            return redirect("/")
    return page("""<div class="card"><h2>Xaridni baholash</h2><form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
    Yulduz (1–5)<select name="stars">{% for n in range(5,0,-1) %}<option value="{{n}}">{{n}} ⭐</option>{% endfor %}</select>
    Fikringiz<textarea name="comment" maxlength="1000"></textarea><button>Yuborish</button></form></div>""")

@app.get("/ai")
def ai():
    return page("""<div class="card"><h2>IBROHIM AI yordamchisi</h2><p>Hozircha internet va AI API kalitisiz ishlaydigan demo yordamchi.</p>
    <form method="get"><input name="q" placeholder="Masalan: mahsulotni qanday sotaman?"><button>So‘rash</button></form>
    {% if q %}<p><b>AI:</b> {{answer}}</p>{% endif %}</div>""",
    q=request.args.get("q",""), answer=(
      "Mahsulot sotish uchun hisob yarating, Sotuvchi tariflari bo‘limidan obuna tanlang va admin tasdiqlagach mahsulot rasmini, narxini va tavsifini joylang."
      if request.args.get("q") else ""))

@app.route("/admin",methods=["GET","POST"])
def admin():
    if not session.get("is_admin"):
        if request.method=="POST":
            pin=request.form.get("pin","")
            if check_password_hash(ADMIN_PIN_HASH,pin):
                session.clear(); session["is_admin"]=True; session["_csrf"]=secrets.token_urlsafe(24)
                return redirect("/admin")
            flash("Admin kodi noto‘g‘ri.")
        return page("""<div class="card" style="max-width:420px;margin:auto"><h2>Yopiq admin panel</h2>
        <form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
        Admin kodi<input type="password" name="pin" required><button>Kirish</button></form></div>""")
    with db() as c:
        totals=c.execute("SELECT COUNT(*) orders,COALESCE(SUM(amount),0) gross,COALESCE(SUM(commission),0) commission FROM orders").fetchone()
        users=c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
        sellers=c.execute("SELECT COUNT(*) n FROM users WHERE role='seller'").fetchone()["n"]
        expenses=c.execute("SELECT COALESCE(SUM(amount),0) n FROM expenses").fetchone()["n"]
        subscription_income=c.execute("SELECT COALESCE(SUM(price),0) n FROM subscriptions WHERE status='active'").fetchone()["n"]
        pending=c.execute("""SELECT s.*,u.name,u.email FROM subscriptions s JOIN users u ON u.id=s.seller_id WHERE s.status='pending' ORDER BY s.id DESC""").fetchall()
        sales=c.execute("""SELECT o.*,p.title,b.name buyer,s.name seller FROM orders o JOIN products p ON p.id=o.product_id
          JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id ORDER BY o.id DESC""").fetchall()
        exp=c.execute("SELECT * FROM expenses ORDER BY id DESC").fetchall()
    net=round(totals["commission"]+subscription_income-expenses,2)
    return page("""<h1>Admin panel</h1><div class="grid">
    <div class="card">Umumiy savdo<div class="stat">${{'%.2f'|format(totals.gross)}}</div></div>
    <div class="card">Komissiya daromadi<div class="stat">${{'%.2f'|format(totals.commission)}}</div></div>
    <div class="card">Obuna daromadi<div class="stat">${{'%.2f'|format(subscription_income)}}</div></div>
    <div class="card">Chiqimlar<div class="stat">${{'%.2f'|format(expenses)}}</div></div>
    <div class="card">Sof foyda<div class="stat">${{'%.2f'|format(net)}}</div></div>
    <div class="card">Foydalanuvchilar<div class="stat">{{users}}</div></div>
    <div class="card">Sotuvchilar<div class="stat">{{sellers}}</div></div></div>
    <div class="card"><h2>Kutilayotgan obunalar</h2>{% for s in pending %}<p>{{s.name}} · {{s.email}} · {{s.plan}} · ${{s.price}}
    <form method="post" action="/admin/activate/{{s.id}}" style="display:inline"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><button>Faollashtirish</button></form></p>{% else %}Yo‘q{% endfor %}</div>
    <div class="card"><h2>Sotuvlar / kim nima sotib oldi</h2><table><tr><th>Mahsulot</th><th>Sotuvchi</th><th>Xaridor</th><th>Narx</th><th>1% komissiya</th></tr>
    {% for o in sales %}<tr><td>{{o.title}}</td><td>{{o.seller}}</td><td>{{o.buyer}}</td><td>${{o.amount}}</td><td>${{o.commission}}</td></tr>{% endfor %}</table></div>
    <div class="card"><h2>Chiqim kiritish</h2><form method="post" action="/admin/expense"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
    Nomi<input name="title" required> Summa (USD)<input name="amount" type="number" min="0" step=".01" required><button>Saqlash</button></form>
    {% for e in exp %}<p>{{e.title}} — ${{e.amount}}</p>{% endfor %}</div>
    <form method="post" action="/admin/logout"><input type="hidden" name="_csrf" value="{{csrf_token()}}"><button class="danger">Admin paneldan chiqish</button></form>""",
    totals=totals,users=users,sellers=sellers,expenses=expenses,subscription_income=subscription_income,net=net,pending=pending,sales=sales,exp=exp)

@app.post("/admin/activate/<int:sid>")
def activate(sid):
    if not session.get("is_admin"): abort(403)
    with db() as c:
        s=c.execute("SELECT * FROM subscriptions WHERE id=?",(sid,)).fetchone()
        if not s: abort(404)
        now=datetime.utcnow(); days=30 if s["plan"]=="monthly" else 365
        c.execute("UPDATE subscriptions SET status='expired' WHERE seller_id=? AND status='active'",(s["seller_id"],))
        c.execute("UPDATE subscriptions SET status='active',starts_at=?,ends_at=? WHERE id=?",
          (now.isoformat(),(now+timedelta(days=days)).isoformat(),sid))
    return redirect("/admin")

@app.post("/admin/expense")
def add_expense():
    if not session.get("is_admin"): abort(403)
    try: amount=float(request.form.get("amount","-1"))
    except ValueError: amount=-1
    if amount<0: abort(400)
    with db() as c: c.execute("INSERT INTO expenses(title,amount,created_at) VALUES(?,?,?)",
        (request.form.get("title","Chiqim")[:120],amount,datetime.utcnow().isoformat()))
    return redirect("/admin")

@app.post("/admin/logout")
def admin_logout():
    if not session.get("is_admin"): abort(403)
    session.clear(); return redirect("/")

@app.get("/uploads/<path:filename>")
def uploaded(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.errorhandler(400)
def bad(e): return page("<div class='card'><h2>So‘rov rad etildi</h2><p>{{msg}}</p></div>",msg=str(e)),400
@app.errorhandler(403)
def forbidden(e): return page("<div class='card'><h2>Ruxsat yo‘q</h2></div>"),403
@app.errorhandler(404)
def missing(e): return page("<div class='card'><h2>Sahifa topilmadi</h2></div>"),404

if __name__ == "__main__":
    # For local testing only. For public deployment use HTTPS + production WSGI server.
    app.run(host="127.0.0.1", port=5000, debug=False)
