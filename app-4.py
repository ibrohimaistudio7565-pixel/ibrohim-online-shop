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
          (SELECT ROUND(AVG(stars),1) FROM reviews r WHERE r.product_id=p.id) rating,
          (SELECT COUNT(*) FROM reviews r WHERE r.product_id=p.id) review_count
          FROM products p JOIN users u ON u.id=p.seller_id WHERE p.active=1 ORDER BY p.id DESC""").fetchall()

    # Namoyish mahsulotlari: ma'lumotlar bazasiga yozilmaydi va buyurtma qilinmaydi.
    demo_products = [
      {"title":"Type-C tezkor zaryadlash kabeli","price":"9 900","old":"29 900","discount":"67%","rating":"4.5","reviews":"88","image":"https://images.unsplash.com/photo-1583863788434-e58a36330cf0?auto=format&fit=crop&w=700&q=85","tag":"ARZON NARX KAFOLATI"},
      {"title":"Power Bank 20 000 mAh","price":"119 900","old":"199 900","discount":"40%","rating":"4.7","reviews":"924","image":"https://images.unsplash.com/photo-1609091839311-d5365f9ff1c5?auto=format&fit=crop&w=700&q=85","tag":"TOP TAKLIF"},
      {"title":"Samsung uslubidagi smartfon","price":"1 699 000","old":"3 999 000","discount":"58%","rating":"4.8","reviews":"22","image":"https://images.unsplash.com/photo-1598327105666-5b89351aff97?auto=format&fit=crop&w=700&q=85","tag":"ORIGINAL NAMUNA"},
      {"title":"Sport uslubidagi krossovka","price":"559 000","old":"1 675 800","discount":"67%","rating":"5.0","reviews":"5","image":"https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=700&q=85","tag":"MASHHUR"},
      {"title":"Simsiz quloqchin","price":"89 000","old":"149 000","discount":"40%","rating":"4.6","reviews":"136","image":"https://images.unsplash.com/photo-150 conectar?auto=format&fit=crop&w=700&q=85","tag":"AKSIYA"},
      {"title":"Zamonaviy ayollar sumkasi","price":"249 000","old":"399 000","discount":"38%","rating":"4.9","reviews":"41","image":"https://images.unsplash.com/photo-158 handbags?auto=format&fit=crop&w=700&q=85","tag":"YANGI"},
    ]
    # Noto'g'ri yoki vaqtincha mavjud bo'lmagan demo rasm manzillarini xavfsiz almashtirish.
    demo_products[4]["image"] = "https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?auto=format&fit=crop&w=700&q=85"
    demo_products[5]["image"] = "https://images.unsplash.com/photo-1584917865442-de89df76afd3?auto=format&fit=crop&w=700&q=85"

    body = r'''<style>
    .shop-home{max-width:1180px;margin:-26px auto 0;padding:0 0 90px}
    .shop-hero{background:radial-gradient(circle at 85% 15%,#9b55ff 0,#6410bd 42%,#35006f 100%);color:#fff;padding:18px max(16px,calc((100% - 1148px)/2)) 28px;border-radius:0 0 28px 28px;overflow:hidden;position:relative}
    .delivery{font-size:13px;color:#ead8ff;margin:0 0 14px}.shop-top{display:flex;gap:10px;align-items:center}
    .shop-search{flex:1;background:#fff;border-radius:28px;display:flex;align-items:center;padding:0 16px;color:#777;min-width:0}
    .shop-search input{border:0!important;outline:0!important;margin:0!important;padding:14px 8px!important;font-size:16px;min-width:0;box-shadow:none!important}
    .heart-link{width:48px;height:48px;border-radius:50%;background:#fff;color:#292039;display:grid;place-items:center;font-size:25px;flex-shrink:0}
    .hero-copy{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:25px 6px 8px}
    .hero-copy h1{color:white;font-size:clamp(23px,4vw,36px);line-height:1.15;margin:0 0 8px}.hero-copy p{color:#ead8ff;margin:0}
    .hero-mark{font-size:clamp(48px,10vw,92px);filter:drop-shadow(0 8px 12px #18002f88)}
    .promo-strip{margin:16px 0 22px;background:linear-gradient(110deg,#f5dfd0,#fff4e9);border-radius:22px;padding:20px;color:#251b28;display:flex;justify-content:space-between;align-items:center;gap:12px;min-height:130px}
    .promo-strip h2{font-size:22px;margin:0 0 7px;color:#241b28}.promo-strip p{margin:0;color:#65545d}.promo-icon{font-size:52px}
    .category-row{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin:18px 0 25px;text-align:center}
    .category{color:#282334;font-size:12px;font-weight:700}.category span{display:grid;place-items:center;background:#eee8ff;border-radius:18px;height:68px;font-size:29px;margin-bottom:7px}
    .section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:20px 0 13px}.section-head h2{font-size:23px;margin:0;color:#21172c}.section-head a{font-weight:700}
    .demo-panel{background:linear-gradient(145deg,#f0e2ff,#e5d2ff);padding:18px;border-radius:26px;margin:0 0 22px}
    .product-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
    .shop-product{background:#fff;border-radius:19px;padding:9px;min-width:0;box-shadow:0 5px 18px #35105a12;position:relative;overflow:hidden}
    .shop-product .photo{width:100%;height:clamp(145px,34vw,245px);object-fit:cover;border-radius:13px;background:#f2eff6;display:block}
    .demo-tag{display:inline-block;background:#ec3e9b;color:#fff;font-size:10px;font-weight:800;padding:5px 9px;border-radius:8px;margin-top:-13px;position:relative;letter-spacing:.3px}
    .product-price{font-size:21px;font-weight:800;margin:9px 0 2px;color:#211b28}.old-price{font-size:12px;color:#888;text-decoration:line-through;margin-left:5px}.discount{display:inline-block;background:#ffeb00;color:#292400;padding:4px 7px;border-radius:7px;font-size:12px;margin:5px 0}
    .product-name{font-size:13px;line-height:1.35;height:35px;overflow:hidden;margin:5px 0 9px;color:#393440}.product-meta{font-size:12px;color:#888;margin:7px 0}.product-meta b{color:#f3a72f}
    .demo-disabled{display:block;text-align:center;background:#eee9ff;color:#8c5be2;border-radius:11px;padding:10px;font-weight:700;font-size:13px}
    .real-products{margin-top:25px}.real-products .shop-product{border:1px solid #eee9f4}
    .real-products .photo{height:190px}.real-products .buy-link{display:block;text-align:center;background:#eee8ff;color:#7040bd;border-radius:10px;padding:10px;font-weight:700}
    .bottom-tabs{position:fixed;z-index:50;bottom:0;left:0;right:0;background:#fff;border-top:1px solid #eee;display:flex;justify-content:space-around;padding:8px 3px max(8px,env(safe-area-inset-bottom));box-shadow:0 -4px 18px #21152a12}
    .bottom-tabs a{color:#777;text-align:center;font-size:11px;display:flex;flex-direction:column;gap:3px;align-items:center;min-width:0}.bottom-tabs .ico{font-size:22px}.bottom-tabs a:first-child{color:#8850e8;font-weight:800}
    @media(min-width:760px){.shop-home{padding-left:18px;padding-right:18px}.product-grid{grid-template-columns:repeat(4,minmax(0,1fr))}.shop-product .photo{height:210px}.shop-hero{border-radius:0 0 28px 28px}}
    @media(max-width:420px){.shop-home{margin-top:-16px}.shop-hero{padding-top:14px}.promo-strip{min-height:108px;padding:14px}.promo-strip h2{font-size:19px}.category-row{gap:5px}.category span{height:58px;font-size:24px}.shop-product{padding:7px}.product-price{font-size:19px}}
    </style>
    <div class="shop-home">
      <section class="shop-hero">
        <p class="delivery">Yetkazib berish manzili · <b>Toshkent</b>⌄</p>
        <div class="shop-top">
          <form class="shop-search" action="/" method="get"><span style="font-size:23px">⌕</span><input name="q" value="{{search_query}}" placeholder="Mahsulotlar qidirish" aria-label="Mahsulotlar qidirish"></form>
          <a class="heart-link" href="/login" aria-label="Sevimlilar">♡</a>
        </div>
        <div class="hero-copy"><div><h1>IBROHIM ONLINE SHOP</h1><p>Har kuni yangi takliflar va qulay xaridlar</p></div><div class="hero-mark">👑</div></div>
      </section>
      <div class="promo-strip"><div><h2>Uy va kundalik hayot uchun</h2><p>Yangi mahsulotlar • Qulay narxlar • Ajoyib takliflar</p></div><div class="promo-icon">🛍️</div></div>
      <div class="category-row">
        <div class="category"><span>👗</span>Moda</div><div class="category"><span>🎧</span>Elektronika</div><div class="category"><span>🧴</span>Har kuni</div><div class="category"><span>🏠</span>Uy-ro‘zg‘or</div><div class="category"><span>🚗</span>Avto</div>
      </div>
      <section class="demo-panel">
        <div class="section-head"><h2>Ommabop takliflar</h2><span style="font-size:13px;color:#7952b5">Namoyish katalogi</span></div>
        <div class="product-grid">
        {% for p in demo_products %}<article class="shop-product">
          <img class="photo" src="{{p.image}}" alt="{{p.title}}" loading="lazy" onerror="this.style.visibility='hidden'">
          <span class="demo-tag">DEMO · {{p.tag}}</span>
          <div class="product-price">{{p.price}} so‘m <span class="old-price">{{p.old}}</span></div>
          <span class="discount">{{p.discount}} chegirma</span>
          <p class="product-name">{{p.title}}</p>
          <div class="product-meta"><b>★</b> {{p.rating}}　● {{p.reviews}} ta fikr</div>
          <span class="demo-disabled">Faqat namoyish uchun</span>
        </article>{% endfor %}
        </div>
      </section>
      <section class="real-products" id="products">
        <div class="section-head"><h2>Haqiqiy sotuvchilar mahsulotlari</h2><a href="/plans">Sotish →</a></div>
        <div class="product-grid">
        {% for p in products %}<article class="shop-product">
          {% if p.image %}<img class="photo" src="/uploads/{{p.image}}" alt="{{p.title}}">{% else %}<div class="photo"></div>{% endif %}
          <div class="product-price">{{'%.0f'|format(p.price)}} USD</div><p class="product-name">{{p.title}}</p>
          <div class="product-meta">{{p.seller}} · <b>★</b> {{p.rating or '—'}} ({{p.review_count}})</div>
          <a class="buy-link" href="/product/{{p.id}}">Ko‘rish / Buyurtma</a>
        </article>{% else %}<div class="shop-product" style="grid-column:1/-1;padding:22px;text-align:center">Hozircha haqiqiy sotuvchi mahsuloti yo‘q. Demo mahsulotlar esa yuqorida namoyish etilmoqda.</div>{% endfor %}
        </div>
      </section>
    </div>
    <nav class="bottom-tabs"><a href="/"><span class="ico">⌂</span>Asosiy</a><a href="/#products"><span class="ico">⌕</span>Katalog</a><a href="/login"><span class="ico">🛍</span>Savat</a><a href="/#products"><span class="ico">％</span>Tezkor</a><a href="/plans"><span class="ico">💜</span>Karta</a><a href="/login"><span class="ico">♙</span>Profil</a></nav>'''
    search_query = request.args.get("q", "").strip()
    if search_query:
        products = [p for p in products if search_query.casefold() in (p["title"] or "").casefold() or search_query.casefold() in (p["description"] or "").casefold()]
        demo_products = [p for p in demo_products if search_query.casefold() in p["title"].casefold()]
    return page(body, products=products, demo_products=demo_products, search_query=search_query)

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
