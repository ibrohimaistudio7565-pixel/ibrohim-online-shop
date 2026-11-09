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
          created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new',
          buyer_name TEXT, buyer_phone TEXT, delivery_address TEXT,
          payment_method TEXT NOT NULL DEFAULT 'cash_on_delivery',
          FOREIGN KEY(buyer_id) REFERENCES users(id),
          FOREIGN KEY(product_id) REFERENCES products(id));
        CREATE TABLE IF NOT EXISTS reviews(
          id INTEGER PRIMARY KEY, order_id INTEGER UNIQUE NOT NULL, product_id INTEGER NOT NULL,
          buyer_id INTEGER NOT NULL, stars INTEGER NOT NULL CHECK(stars BETWEEN 1 AND 5),
          comment TEXT, created_at TEXT NOT NULL,
          FOREIGN KEY(order_id) REFERENCES orders(id));
        CREATE TABLE IF NOT EXISTS conversations(
          id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL, buyer_id INTEGER NOT NULL,
          seller_id INTEGER NOT NULL, created_at TEXT NOT NULL,
          UNIQUE(product_id,buyer_id,seller_id),
          FOREIGN KEY(product_id) REFERENCES products(id),
          FOREIGN KEY(buyer_id) REFERENCES users(id),
          FOREIGN KEY(seller_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL, sender_id INTEGER NOT NULL,
          body TEXT NOT NULL, image TEXT, read_at TEXT, created_at TEXT NOT NULL,
          FOREIGN KEY(conversation_id) REFERENCES conversations(id),
          FOREIGN KEY(sender_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS expenses(
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, amount REAL NOT NULL CHECK(amount >= 0),
          created_at TEXT NOT NULL);
        """)
        # Upgrade databases created by older demo versions without deleting data.
        cols = {row[1] for row in c.execute("PRAGMA table_info(orders)").fetchall()}
        for name, declaration in [
            ("buyer_name", "TEXT"), ("buyer_phone", "TEXT"),
            ("delivery_address", "TEXT"),
            ("payment_method", "TEXT NOT NULL DEFAULT 'cash_on_delivery'")
        ]:
            if name not in cols:
                c.execute(f"ALTER TABLE orders ADD COLUMN {name} {declaration}")
        c.execute("UPDATE orders SET status='new' WHERE status='completed'")
        message_cols = {row[1] for row in c.execute("PRAGMA table_info(messages)").fetchall()}
        if "image" not in message_cols:
            c.execute("ALTER TABLE messages ADD COLUMN image TEXT")
        if "read_at" not in message_cols:
            c.execute("ALTER TABLE messages ADD COLUMN read_at TEXT")
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
*{box-sizing:border-box}
:root{--purple:#7000c8;--purple-dark:#4b008c;--yellow:#ffdc00;--ink:#242033;--muted:#747184}
body{margin:0;background:#f7f5fa;color:var(--ink);font:16px Arial,sans-serif}
header{background:var(--purple);color:white;padding:12px max(4%,calc((100% - 1180px)/2));display:flex;gap:18px;align-items:center;justify-content:space-between;flex-wrap:wrap;box-shadow:0 3px 14px #3d006b22}
a{color:var(--purple);text-decoration:none}
header a{color:white}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:19px;white-space:nowrap}
.brand img{width:48px;height:48px;object-fit:contain;border-radius:10px;background:white;padding:3px}
nav{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
nav>a{padding:9px 11px;border-radius:9px;font-weight:600}
nav>a:hover{background:#ffffff24}
main{max-width:1180px;margin:26px auto;padding:0 16px;min-height:65vh}
.card{background:white;padding:20px;border:1px solid #eee9f4;border-radius:16px;box-shadow:0 5px 22px #28133b0b;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
input,textarea,select{width:100%;padding:12px;border:1px solid #ded8e8;border-radius:10px;margin:7px 0 14px;background:white;color:var(--ink)}
input:focus,textarea:focus,select:focus{outline:2px solid #d9b7f5;border-color:var(--purple)}
button,.btn{display:inline-block;border:0;border-radius:10px;background:var(--purple);color:white;padding:11px 17px;cursor:pointer;font-weight:700}
button:hover,.btn:hover{background:var(--purple-dark)}
nav select{max-width:135px}
img.product{width:100%;height:190px;object-fit:cover;border-radius:12px;background:#f0edf4}
small,.muted{color:var(--muted)}
.flash{background:#fff5c2;border:1px solid #ffe36b;padding:12px;border-radius:10px;margin:10px 0}
table{width:100%;border-collapse:collapse;background:white;overflow-x:auto}
td,th{padding:10px;border-bottom:1px solid #eee9f4;text-align:left}
.stat{font-size:25px;font-weight:bold;color:var(--purple)}.danger{background:#b42335}
h1,h2,h3{color:#292039}
footer{color:var(--muted);text-align:center}
@media(max-width:700px){
 header{padding:12px 14px;gap:10px}
 .brand{font-size:16px}
 .brand img{width:42px;height:42px}
 nav{width:100%;gap:5px}
 nav>a{padding:8px;font-size:14px}
 main{margin:16px auto;padding:0 12px}
 .card{padding:16px}
 .grid{grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:10px}
 img.product{height:145px}
}
</style>
<header>
<a class="brand" href="/">
<img src="{{ url_for('static', filename='logo.png') }}" alt="IBROHIM ONLINE SHOP logotipi">
<span>IBROHIM ONLINE SHOP</span>
</a>
<nav>
<a href="/">{{t.home}}</a><a href="/#products">{{t.products}}</a>
{% if user %}
    {% if user.role == 'seller' %}<a href="/sell">{{t.add}}</a>
    {% else %}<a href="/plans">{{t.sell}}</a>{% endif %}
    <a href="/logout">{{t.logout}}</a>
{% else %}<a href="/login">{{t.login}}</a><a href="/register">{{t.register}}</a>{% endif %}
{% if user %}<a href="/orders">Buyurtmalarim</a><a href="/chats">Xabarlar{% if unread_count %} <span style="background:#e53935;color:white;border-radius:20px;padding:2px 7px">{{unread_count}}</span>{% endif %}</a><a href="/notifications">Bildirishnomalar</a>{% endif %}<a href="/plans">Tariflar</a><a href="/ai">AI</a>
<form method="post" action="/language" style="margin:0"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
<select name="lang" onchange="this.form.submit()" style="margin:0;padding:6px">
{% for code,label in [('uz','O‘zbek'),('en','English'),('ru','Русский'),('zh','中文'),('ko','한국어'),('ar','العربية')] %}
<option value="{{code}}" {{'selected' if lang==code else ''}}>{{label}}</option>{% endfor %}
</select></form></nav></header><main>
{% for m in get_flashed_messages() %}<div class="flash">{{m}}</div>{% endfor %}
{{body|safe}}
<footer class="muted" style="padding:25px 0">© {{year}} IBROHIM ONLINE SHOP</footer></main></html>
"""
def page(body, **kwargs):
    lang = session.get("lang","uz")
    u = current_user()
    unread_count = 0
    if u:
        with db() as c:
            unread_count = c.execute("""SELECT COUNT(*) FROM messages m
                JOIN conversations cv ON cv.id=m.conversation_id
                WHERE m.sender_id<>? AND m.read_at IS NULL
                AND (cv.buyer_id=? OR cv.seller_id=?)""",
                (u["id"],u["id"],u["id"])).fetchone()[0]
    return render_template_string(BASE, body=render_template_string(body, **kwargs),
        user=u, unread_count=unread_count, lang=lang, t=LANGS[lang], year=datetime.now().year)

@app.get("/")
def home():
    with db() as c:
        products = c.execute("""SELECT p.*,u.name seller,
          (SELECT ROUND(AVG(stars),1) FROM reviews r WHERE r.product_id=p.id) rating
          FROM products p JOIN users u ON u.id=p.seller_id WHERE p.active=1 ORDER BY p.id DESC""").fetchall()
    body = """<h1>IBROHIM ONLINE SHOP</h1><p class="muted">Bir joyda xarid qiling, soting va rivojlaning.</p>
    <div class="grid" id="products">{% for p in products %}<div class="card">
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
    {% if user %}<a class="btn" href="/checkout/{{p.id}}">Buyurtma berish</a>
    {% if user.id != p.seller_id %}<a class="btn" href="/chat/start/{{p.id}}">Sotuvchiga yozish</a>{% endif %}
    {% else %}<a href="/login">Xarid qilish uchun kiring</a>{% endif %}</div>
    <div class="card"><h3>Baholar va fikrlar</h3>{% for r in reviews %}<p>{{'⭐'*r.stars}} — {{r.comment}} <small>({{r.name}})</small></p>{% else %}<p>Hali fikr yo‘q.</p>{% endfor %}</div>""",p=p,reviews=reviews)


@app.get("/chats")
@login_required
def chats():
    u=current_user()
    with db() as c:
        rows=c.execute("""SELECT cv.id,cv.product_id,p.title,
            CASE WHEN cv.buyer_id=? THEN seller.name ELSE buyer.name END AS other_name,
            (SELECT body FROM messages m WHERE m.conversation_id=cv.id ORDER BY m.id DESC LIMIT 1) last_message,
            (SELECT created_at FROM messages m WHERE m.conversation_id=cv.id ORDER BY m.id DESC LIMIT 1) last_time
            FROM conversations cv JOIN products p ON p.id=cv.product_id
            JOIN users buyer ON buyer.id=cv.buyer_id JOIN users seller ON seller.id=cv.seller_id
            WHERE cv.buyer_id=? OR cv.seller_id=? ORDER BY cv.id DESC""",
            (u["id"],u["id"],u["id"])).fetchall()
    return page("""<div class="card"><h2>Xabarlar</h2>
    {% for x in rows %}<div style="padding:12px;border-bottom:1px solid #eee">
    <b>{{x.other_name}}</b> · {{x.title}}<p>{{x.last_message or 'Suhbat boshlandi'}}</p>
    <a class="btn" href="/chat/{{x.id}}">Chatni ochish</a></div>
    {% else %}<p>Hozircha suhbatlar yo‘q. Mahsulot sahifasidan sotuvchiga yozishingiz mumkin.</p>{% endfor %}</div>""",rows=rows)

@app.get("/chat/start/<int:pid>")
@login_required
def chat_start(pid):
    u=current_user()
    with db() as c:
        product=c.execute("SELECT * FROM products WHERE id=? AND active=1",(pid,)).fetchone()
        if not product: abort(404)
        if product["seller_id"]==u["id"]:
            flash("O‘z mahsulotingizga xaridor sifatida yozisha olmaysiz.")
            return redirect(url_for("product",pid=pid))
        if u["role"] not in ("buyer","seller"): abort(403)
        cur=c.execute("""INSERT OR IGNORE INTO conversations
            (product_id,buyer_id,seller_id,created_at) VALUES(?,?,?,?)""",
            (pid,u["id"],product["seller_id"],datetime.utcnow().isoformat()))
        conv=c.execute("""SELECT id FROM conversations WHERE product_id=? AND buyer_id=? AND seller_id=?""",
            (pid,u["id"],product["seller_id"])).fetchone()
    return redirect(url_for("chat_thread",cid=conv["id"]))

@app.route("/chat/<int:cid>",methods=["GET","POST"])
@login_required
def chat_thread(cid):
    u=current_user()
    with db() as c:
        conv=c.execute("""SELECT cv.*,p.title, buyer.name buyer_name,seller.name seller_name
            FROM conversations cv JOIN products p ON p.id=cv.product_id
            JOIN users buyer ON buyer.id=cv.buyer_id JOIN users seller ON seller.id=cv.seller_id
            WHERE cv.id=? AND (cv.buyer_id=? OR cv.seller_id=?)""",
            (cid,u["id"],u["id"])).fetchone()
        if not conv: abort(404)
        if request.method=="POST":
            body=request.form.get("body","").strip()
            image_file=request.files.get("image")
            saved_image=None
            if image_file and image_file.filename:
                ext=image_file.filename.rsplit(".",1)[-1].lower() if "." in image_file.filename else ""
                if ext not in ALLOWED:
                    flash("Rasm formati PNG, JPG, WEBP yoki GIF bo‘lishi kerak.")
                    return redirect(url_for("chat_thread",cid=cid))
                saved_image=secrets.token_hex(16)+"."+ext
                image_file.save(UPLOAD_DIR/saved_image)
            if not body and not saved_image:
                flash("Xabar yozing yoki rasm tanlang.")
            elif len(body)>2000:
                if saved_image: (UPLOAD_DIR/saved_image).unlink(missing_ok=True)
                flash("Xabar 2000 belgidan oshmasin.")
            else:
                c.execute("""INSERT INTO messages(conversation_id,sender_id,body,image,created_at)
                    VALUES(?,?,?,?,?)""",
                    (cid,u["id"],body,saved_image,datetime.utcnow().isoformat()))
                return redirect(url_for("chat_thread",cid=cid))
        c.execute("""UPDATE messages SET read_at=?
            WHERE conversation_id=? AND sender_id<>? AND read_at IS NULL""",
            (datetime.utcnow().isoformat(),cid,u["id"]))
        msgs=c.execute("""SELECT m.*,u.name sender_name,m.sender_id=? mine
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.conversation_id=? ORDER BY m.id ASC""",(u["id"],cid)).fetchall()
    return page("""<div class="card"><h2>{{conv.title}}</h2>
    <p>Suhbat: {{conv.buyer_name}} ↔ {{conv.seller_name}}</p>
    <div style="max-height:55vh;overflow:auto;padding:8px;background:#faf8fc;border-radius:12px">
    {% for m in msgs %}<div style="margin:10px 0;text-align:{{'right' if m.mine else 'left'}}">
    <div style="display:inline-block;max-width:85%;padding:10px 14px;border-radius:12px;background:{{'#ead7ff' if m.mine else '#fff'}}">
    <b>{{m.sender_name}}</b>
    {% if m.body %}<p style="white-space:pre-wrap;margin:6px 0">{{m.body}}</p>{% endif %}
    {% if m.image %}<a href="/uploads/{{m.image}}" target="_blank"><img src="/uploads/{{m.image}}" alt="Xabar rasmi" style="display:block;max-width:240px;max-height:240px;border-radius:10px;margin:8px 0"></a>{% endif %}
    <small>{{m.created_at[:16].replace('T',' ')}}</small></div></div>
    {% else %}<p>Hali xabar yo‘q. Birinchi xabarni yuboring.</p>{% endfor %}</div>
    <form method="post" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
    <textarea name="body" rows="3" maxlength="2000" placeholder="Xabaringiz..."></textarea>
    <label style="display:block;margin:10px 0">Rasm biriktirish: <input type="file" name="image" accept="image/png,image/jpeg,image/webp,image/gif"></label>
    <button type="submit">Yuborish</button> <a class="btn" href="/chats">Xabarlar</a></form></div>
    <script>setInterval(()=>{const box=document.querySelector('textarea');if(box && document.activeElement!==box && !box.value) location.reload();},20000);</script>""",conv=conv,msgs=msgs)

@app.get("/notifications")
@login_required
def notifications():
    u=current_user()
    with db() as c:
        rows=c.execute("""SELECT m.id,m.body,m.image,m.created_at,cv.id conversation_id,
            p.title,other.name sender_name
            FROM messages m JOIN conversations cv ON cv.id=m.conversation_id
            JOIN products p ON p.id=cv.product_id JOIN users other ON other.id=m.sender_id
            WHERE m.sender_id<>? AND (cv.buyer_id=? OR cv.seller_id=?)
            ORDER BY m.id DESC LIMIT 100""",(u["id"],u["id"],u["id"])).fetchall()
        unread=c.execute("""SELECT COUNT(*) FROM messages m JOIN conversations cv ON cv.id=m.conversation_id
            WHERE m.sender_id<>? AND m.read_at IS NULL AND (cv.buyer_id=? OR cv.seller_id=?)""",
            (u["id"],u["id"],u["id"])).fetchone()[0]
    return page("""<div class="card"><h2>Bildirishnomalar</h2>
    <p>O‘qilmagan xabarlar: <b>{{unread}}</b></p>
    {% for n in rows %}<div style="padding:12px;border-bottom:1px solid #eee">
    <b>{{n.sender_name}}</b> · {{n.title}} {% if not n.body %}<p>Rasm yubordi</p>{% else %}<p>{{n.body}}</p>{% endif %}
    <small>{{n.created_at[:16].replace('T',' ')}}</small><br>
    <a class="btn" href="/chat/{{n.conversation_id}}">Javob berish</a></div>
    {% else %}<p>Hozircha bildirishnoma yo‘q.</p>{% endfor %}</div>""",rows=rows,unread=unread)

@app.route("/checkout/<int:pid>", methods=["GET", "POST"])
@login_required
def checkout(pid):
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
        if not p: abort(404)
        if p["seller_id"] == current_user()["id"]:
            flash("O‘zingizning mahsulotingizga buyurtma bera olmaysiz.")
            return redirect(url_for("product", pid=pid))
        if request.method == "POST":
            name = request.form.get("buyer_name", "").strip()
            phone = request.form.get("buyer_phone", "").strip()
            address = request.form.get("delivery_address", "").strip()
            if len(name) < 2 or len(phone) < 7 or len(address) < 8:
                flash("Ism, telefon raqami va to‘liq manzilni to‘g‘ri kiriting.")
            else:
                commission = round(p["price"] * COMMISSION_RATE, 2)
                cur = c.execute("""INSERT INTO orders
                    (buyer_id,product_id,seller_id,amount,commission,created_at,status,
                     buyer_name,buyer_phone,delivery_address,payment_method)
                    VALUES(?,?,?,?,?,?,'new',?,?,?,'cash_on_delivery')""",
                    (current_user()["id"], pid, p["seller_id"], p["price"], commission,
                     datetime.utcnow().isoformat(), name, phone, address))
                oid = cur.lastrowid
                flash(f"Buyurtmangiz #{oid} qabul qilindi. Sotuvchi tasdiqlashini kuting.")
                return redirect(url_for("orders"))
    return page("""<div class="card" style="max-width:620px;margin:auto"><h2>Buyurtmani rasmiylashtirish</h2>
    <p><b>{{p.title}}</b> — {{'%.2f'|format(p.price)}} USD</p>
    <form method="post"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
    Ism-familiya<input name="buyer_name" value="{{user.name}}" minlength="2" required>
    Telefon raqami<input name="buyer_phone" type="tel" placeholder="+998 90 123 45 67" minlength="7" required>
    Yetkazib berish manzili<textarea name="delivery_address" minlength="8" required placeholder="Viloyat, tuman, ko‘cha, uy, mo‘ljal"></textarea>
    <p><b>To‘lov:</b> mahsulot yetkazilganda naqd pulda</p><button>Buyurtmani tasdiqlash</button></form></div>""", p=p)

@app.get("/orders")
@login_required
def orders():
    u = current_user()
    with db() as c:
        rows = c.execute("""SELECT o.*,p.title,p.image,b.name buyer,s.name seller
            FROM orders o JOIN products p ON p.id=o.product_id
            JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id
            WHERE o.buyer_id=? OR o.seller_id=? ORDER BY o.id DESC""",
            (u["id"], u["id"])).fetchall()
    return page("""<h1>Buyurtmalar</h1>{% for o in rows %}<div class="card">
    <h3>Buyurtma #{{o.id}} — {{o.title}}</h3><p>Narxi: {{'%.2f'|format(o.amount)}} USD</p>
    <p>Holati: <b>{{o.status}}</b> · To‘lov: yetkazilganda naqd</p>
    {% if o.buyer_id == user.id %}<p>Sotuvchi: {{o.seller}}</p>{% else %}<p>Xaridor: {{o.buyer_name}} · {{o.buyer_phone}}</p><p>Manzil: {{o.delivery_address}}</p>
      {% if o.status in ['new','confirmed','shipped'] %}<form method="post" action="/orders/{{o.id}}/status"><input type="hidden" name="_csrf" value="{{csrf_token()}}">
      <select name="status">{% for st,label in [('confirmed','Tasdiqlandi'),('shipped','Yo‘lda'),('delivered','Yetkazildi'),('cancelled','Bekor qilindi')] %}<option value="{{st}}" {% if st==o.status %}selected{% endif %}>{{label}}</option>{% endfor %}</select><button>Holatni yangilash</button></form>{% endif %}{% endif %}
    <small>{{o.created_at}}</small></div>{% else %}<div class="card">Hozircha buyurtmalar yo‘q.</div>{% endfor %}""", rows=rows)

@app.post("/orders/<int:oid>/status")
@login_required
def update_order_status(oid):
    allowed = {"new": {"confirmed", "cancelled"}, "confirmed": {"shipped", "cancelled"}, "shipped": {"delivered"}}
    new_status = request.form.get("status", "")
    with db() as c:
        o = c.execute("SELECT * FROM orders WHERE id=? AND seller_id=?", (oid, current_user()["id"])).fetchone()
        if not o: abort(404)
        if new_status not in allowed.get(o["status"], set()): abort(400, "Buyurtma holati ketma-ketligini buzib bo‘lmaydi.")
        c.execute("UPDATE orders SET status=? WHERE id=?", (new_status, oid))
    flash("Buyurtma holati yangilandi.")
    return redirect(url_for("orders"))

@app.route("/review/<int:oid>",methods=["GET","POST"])
@login_required
def review(oid):
    with db() as c:
        order=c.execute("SELECT * FROM orders WHERE id=? AND buyer_id=?",(oid,current_user()["id"])).fetchone()
        if not order: abort(404)
        if order["status"] != "delivered":
            flash("Buyurtmani baholash uchun mahsulot yetkazilgan bo‘lishi kerak.")
            return redirect(url_for("orders"))
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
    <div class="card"><h2>Buyurtmalar</h2><table><tr><th>Mahsulot</th><th>Sotuvchi</th><th>Xaridor</th><th>Telefon</th><th>Manzil</th><th>Holat</th><th>Narx</th></tr>
    {% for o in sales %}<tr><td>{{o.title}}</td><td>{{o.seller}}</td><td>{{o.buyer_name or o.buyer}}</td><td>{{o.buyer_phone or '—'}}</td><td>{{o.delivery_address or '—'}}</td><td>{{o.status}}</td><td>${{o.amount}}</td></tr>{% endfor %}</table></div>
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
