# ==========================================================
#  Digital Wallet v2 — Demo App (Python / Flask)
#  Add Money (JazzCash/Easypaisa/SadaPay) + Withdraw + Admin Panel
#  سیکھنے کے لیے، فرضی رقم
# ==========================================================
import os, re, time, random, sqlite3, smtplib
from email.mime.text import MIMEText
from functools import wraps

import bcrypt
import jwt
from flask import Flask, request, jsonify, send_from_directory, g

app = Flask(__name__, static_folder="public", static_url_path="")

# ==================== آپ کی سیٹنگز (یہ ضرور بدلیں) ====================

# مالک (admin) کا موبائل نمبر — اس نمبر سے لاگ ان کرنے پر Admin Panel نظر آئے گا
ADMIN_MOBILE = os.environ.get("ADMIN_MOBILE", "03001234567")

# آپ کے اصلی اکاؤنٹ — یہی صارفین کو دکھائے جائیں گے کہ رقم یہاں بھیجیں
PAYMENT_METHODS = {
    "jazzcash": {"name": "JazzCash", "account_name": "Ali Khan", "account_number": "0300-1234567"},
    "easypaisa": {"name": "Easypaisa", "account_name": "Ali Khan", "account_number": "0345-1234567"},
    "sadapay": {"name": "SadaPay", "account_name": "Ali Khan", "account_number": "0331-1234567"},
}

# ======================================================================

JWT_SECRET = os.environ.get("JWT_SECRET", "change-this-secret-in-production")
PORT = int(os.environ.get("PORT", 3000))

# EMAIL_MODE = "console" → کوڈ terminal پر | "smtp" → اصلی ای میل
EMAIL_MODE = os.environ.get("EMAIL_MODE", "console")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_USER = os.environ.get("SMTP_USER", "your-email@gmail.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "your-app-password")

DB_PATH = os.path.join(os.path.dirname(__file__), "wallet.db")

# -------------------- DATABASE --------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        mobile TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        verified INTEGER DEFAULT 0,
        verify_code TEXT,
        verify_expires INTEGER,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS wallets (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        balance REAL NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,              -- 'deposit' | 'withdraw' | 'transfer'
        from_user INTEGER,
        to_user INTEGER,
        amount REAL NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        kind TEXT NOT NULL,              -- 'deposit' | 'withdraw'
        method TEXT NOT NULL,            -- 'jazzcash' | 'easypaisa' | 'sadapay'
        amount REAL NOT NULL,
        detail TEXT,                     -- deposit: بھیجنے والا نمبر/TxID | withdraw: وصولی کا اکاؤنٹ نمبر
        status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
        created_at TEXT DEFAULT (datetime('now')),
        decided_at TEXT
      );
    """)
    db.close()

init_db()

# -------------------- HELPERS --------------------
def send_email(to, subject, body):
    if EMAIL_MODE == "smtp":
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = SMTP_USER
            msg["To"] = to
            with smtplib.SMTP(SMTP_HOST, 587) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        except Exception as e:
            print(f"[EMAIL ERROR] {e}", flush=True)
    else:
        print("=" * 48)
        print(f"  📧 EMAIL to {to}: {subject}")
        print(f"     {body}")
        print("=" * 48, flush=True)

def send_code(email, code):
    send_email(email, "آپ کا تصدیقی کوڈ | Your verification code",
               f"Your verification code is: {code} (valid for 10 minutes)")

def notify_admin(text):
    # نئی درخواست پر مالک کو اطلاع: terminal پر ہمیشہ، smtp mode میں ای میل بھی
    print("*" * 48)
    print(f"  🔔 ADMIN ALERT: {text}")
    print("*" * 48, flush=True)
    if EMAIL_MODE == "smtp":
        send_email(SMTP_USER, "🔔 نئی درخواست | New wallet request", text)

def gen_code():
    return str(random.randint(100000, 999999))

_hits = {}
@app.before_request
def rate_limit():
    if not request.path.startswith("/api/"):
        return
    now = time.time()
    ip = request.remote_addr or "?"
    count, start = _hits.get(ip, (0, now))
    if now - start > 60:
        count, start = 0, now
    count += 1
    _hits[ip] = (count, start)
    if count > 40:
        return jsonify(error="بہت زیادہ درخواستیں، تھوڑا انتظار کریں"), 429

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        h = request.headers.get("Authorization", "")
        token = h[7:] if h.startswith("Bearer ") else None
        if not token:
            return jsonify(error="لاگ ان درکار ہے"), 401
        try:
            request.user = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify(error="سیشن ختم ہو گیا، دوبارہ لاگ ان کریں"), 401
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.user.get("isAdmin"):
            return jsonify(error="صرف admin کے لیے"), 403
        return f(*args, **kwargs)
    return wrapper

# -------------------- BASIC ROUTES --------------------

@app.get("/")
def home():
    return send_from_directory("public", "index.html")

@app.post("/api/signup")
def signup():
    d = request.get_json(silent=True) or {}
    name, mobile = (d.get("name") or "").strip(), (d.get("mobile") or "").strip()
    email, password = (d.get("email") or "").strip(), d.get("password") or ""

    if not all([name, mobile, email, password]):
        return jsonify(error="تمام خانے پُر کریں"), 400
    if not re.fullmatch(r"\+?\d{10,15}", mobile):
        return jsonify(error="موبائل نمبر درست نہیں (10–15 ہندسے)"), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify(error="ای میل درست نہیں"), 400
    if len(password) < 6:
        return jsonify(error="پاس ورڈ کم از کم 6 حروف کا ہو"), 400

    db = get_db()
    if db.execute("SELECT id FROM users WHERE mobile=? OR email=?", (mobile, email)).fetchone():
        return jsonify(error="یہ موبائل نمبر یا ای میل پہلے سے موجود ہے"), 409

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    code = gen_code()
    expires = int(time.time() * 1000) + 10 * 60 * 1000

    cur = db.execute(
        "INSERT INTO users (name, mobile, email, password_hash, verify_code, verify_expires) VALUES (?,?,?,?,?,?)",
        (name, mobile, email, pw_hash, code, expires),
    )
    db.execute("INSERT INTO wallets (user_id, balance) VALUES (?, 0)", (cur.lastrowid,))
    db.commit()

    send_code(email, code)
    return jsonify(message="اکاؤنٹ بن گیا! ای میل پر بھیجا گیا کوڈ داخل کریں")

@app.post("/api/verify")
def verify():
    d = request.get_json(silent=True) or {}
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", ((d.get("email") or "").strip(),)).fetchone()
    if not user:
        return jsonify(error="اکاؤنٹ نہیں ملا"), 404
    if user["verified"]:
        return jsonify(message="اکاؤنٹ پہلے سے تصدیق شدہ ہے")
    if int(time.time() * 1000) > user["verify_expires"]:
        return jsonify(error="کوڈ کی میعاد ختم، دوبارہ سائن اپ کریں"), 400
    if user["verify_code"] != str(d.get("code") or "").strip():
        return jsonify(error="غلط کوڈ"), 400

    db.execute("UPDATE users SET verified=1, verify_code=NULL WHERE id=?", (user["id"],))
    db.commit()
    return jsonify(message="✅ اکاؤنٹ کی تصدیق ہو گئی! اب لاگ ان کریں")

@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE mobile=?", ((d.get("mobile") or "").strip(),)).fetchone()
    if not user or not bcrypt.checkpw((d.get("password") or "").encode(), user["password_hash"].encode()):
        return jsonify(error="موبائل نمبر یا پاس ورڈ غلط ہے"), 401
    if not user["verified"]:
        return jsonify(error="پہلے ای میل کوڈ سے تصدیق کریں"), 403

    is_admin = user["mobile"] == ADMIN_MOBILE
    token = jwt.encode(
        {"id": user["id"], "name": user["name"], "isAdmin": is_admin,
         "exp": int(time.time()) + 2 * 3600},
        JWT_SECRET, algorithm="HS256",
    )
    return jsonify(token=token, name=user["name"], isAdmin=is_admin)

@app.get("/api/me")
@auth_required
def me():
    uid = request.user["id"]
    db = get_db()
    wallet = db.execute("SELECT balance FROM wallets WHERE user_id=?", (uid,)).fetchone()
    txns = db.execute("""
        SELECT t.*, uf.name AS from_name, ut.name AS to_name
        FROM transactions t
        LEFT JOIN users uf ON uf.id = t.from_user
        LEFT JOIN users ut ON ut.id = t.to_user
        WHERE t.from_user = ? OR t.to_user = ?
        ORDER BY t.id DESC LIMIT 20
    """, (uid, uid)).fetchall()
    reqs = db.execute(
        "SELECT * FROM requests WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)
    ).fetchall()
    return jsonify(
        name=request.user["name"],
        isAdmin=bool(request.user.get("isAdmin")),
        balance=wallet["balance"],
        transactions=[dict(t) for t in txns],
        requests=[dict(r) for r in reqs],
        myId=uid,
    )

# -------------------- ADD MONEY / WITHDRAW --------------------

@app.get("/api/payment-methods")
def payment_methods():
    return jsonify(methods=PAYMENT_METHODS)

@app.post("/api/deposit-request")
@auth_required
def deposit_request():
    d = request.get_json(silent=True) or {}
    method = d.get("method")
    detail = (d.get("detail") or "").strip()
    try:
        amount = float(d.get("amount"))
    except (TypeError, ValueError):
        return jsonify(error="درست رقم داخل کریں"), 400
    if method not in PAYMENT_METHODS:
        return jsonify(error="طریقہ منتخب کریں"), 400
    if amount <= 0 or amount > 1_000_000:
        return jsonify(error="درست رقم داخل کریں"), 400
    if not detail:
        return jsonify(error="جس نمبر سے رقم بھیجی اس کا نمبر یا Transaction ID لکھیں"), 400

    db = get_db()
    db.execute(
        "INSERT INTO requests (user_id, kind, method, amount, detail) VALUES (?,?,?,?,?)",
        (request.user["id"], "deposit", method, amount, detail),
    )
    db.commit()
    notify_admin(f"DEPOSIT request: {request.user['name']} | ₨{amount:g} | "
                 f"{PAYMENT_METHODS[method]['name']} | detail: {detail}")
    return jsonify(message="درخواست بھیج دی گئی ✅ منظوری کے بعد بیلنس شامل ہو جائے گا")

@app.post("/api/withdraw-request")
@auth_required
def withdraw_request():
    d = request.get_json(silent=True) or {}
    method = d.get("method")
    detail = (d.get("detail") or "").strip()
    try:
        amount = float(d.get("amount"))
    except (TypeError, ValueError):
        return jsonify(error="درست رقم داخل کریں"), 400
    if method not in PAYMENT_METHODS:
        return jsonify(error="طریقہ منتخب کریں"), 400
    if amount <= 0:
        return jsonify(error="درست رقم داخل کریں"), 400
    if not detail:
        return jsonify(error="اپنا اکاؤنٹ نمبر لکھیں جس پر رقم وصول کرنی ہے"), 400

    uid = request.user["id"]
    db = get_db()
    w = db.execute("SELECT balance FROM wallets WHERE user_id=?", (uid,)).fetchone()
    # pending withdraw بھی شمار کریں تاکہ دوہری درخواست سے بیلنس منفی نہ ہو
    pending = db.execute(
        "SELECT COALESCE(SUM(amount),0) s FROM requests WHERE user_id=? AND kind='withdraw' AND status='pending'",
        (uid,),
    ).fetchone()["s"]
    if w["balance"] - pending < amount:
        return jsonify(error="بیلنس ناکافی ہے (pending درخواستیں شامل کر کے)"), 400

    db.execute(
        "INSERT INTO requests (user_id, kind, method, amount, detail) VALUES (?,?,?,?,?)",
        (uid, "withdraw", method, amount, detail),
    )
    db.commit()
    notify_admin(f"WITHDRAW request: {request.user['name']} | ₨{amount:g} | "
                 f"{PAYMENT_METHODS[method]['name']} | account: {detail}")
    return jsonify(message="درخواست بھیج دی گئی ✅ منظوری کے بعد رقم آپ کے اکاؤنٹ میں بھیج دی جائے گی")

# -------------------- TRANSFER (پہلے جیسا) --------------------

@app.post("/api/transfer")
@auth_required
def transfer():
    d = request.get_json(silent=True) or {}
    to_mobile = (d.get("toMobile") or "").strip()
    try:
        amount = float(d.get("amount"))
    except (TypeError, ValueError):
        return jsonify(error="وصول کنندہ کا موبائل نمبر اور درست رقم داخل کریں"), 400
    if not to_mobile or amount <= 0:
        return jsonify(error="وصول کنندہ کا موبائل نمبر اور درست رقم داخل کریں"), 400

    uid = request.user["id"]
    db = get_db()
    receiver = db.execute("SELECT id, name FROM users WHERE mobile=? AND verified=1", (to_mobile,)).fetchone()
    if not receiver:
        return jsonify(error="اس نمبر پر کوئی تصدیق شدہ اکاؤنٹ نہیں"), 404
    if receiver["id"] == uid:
        return jsonify(error="اپنے آپ کو رقم نہیں بھیج سکتے"), 400

    try:
        db.execute("BEGIN")
        w = db.execute("SELECT balance FROM wallets WHERE user_id=?", (uid,)).fetchone()
        if w["balance"] < amount:
            db.execute("ROLLBACK")
            return jsonify(error="بیلنس ناکافی ہے"), 400
        db.execute("UPDATE wallets SET balance = balance - ? WHERE user_id=?", (amount, uid))
        db.execute("UPDATE wallets SET balance = balance + ? WHERE user_id=?", (amount, receiver["id"]))
        db.execute(
            "INSERT INTO transactions (type, from_user, to_user, amount) VALUES ('transfer', ?, ?, ?)",
            (uid, receiver["id"], amount),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        return jsonify(error="ٹرانسفر ناکام، دوبارہ کوشش کریں"), 500

    return jsonify(message=f"₨ {amount:g} کامیابی سے {receiver['name']} کو بھیج دیے گئے")

# -------------------- ADMIN PANEL --------------------

@app.get("/api/admin/requests")
@auth_required
@admin_required
def admin_requests():
    db = get_db()
    rows = db.execute("""
        SELECT r.*, u.name AS user_name, u.mobile AS user_mobile
        FROM requests r JOIN users u ON u.id = r.user_id
        WHERE r.status = 'pending'
        ORDER BY r.id ASC
    """).fetchall()
    return jsonify(requests=[dict(r) for r in rows])

@app.post("/api/admin/requests/<int:req_id>/decide")
@auth_required
@admin_required
def admin_decide(req_id):
    d = request.get_json(silent=True) or {}
    decision = d.get("decision")  # 'approve' | 'reject'
    if decision not in ("approve", "reject"):
        return jsonify(error="غلط فیصلہ"), 400

    db = get_db()
    r = db.execute("SELECT * FROM requests WHERE id=? AND status='pending'", (req_id,)).fetchone()
    if not r:
        return jsonify(error="درخواست نہیں ملی یا پہلے نمٹ چکی"), 404

    if decision == "reject":
        db.execute("UPDATE requests SET status='rejected', decided_at=datetime('now') WHERE id=?", (req_id,))
        db.commit()
        return jsonify(message="درخواست مسترد کر دی گئی")

    # approve
    try:
        db.execute("BEGIN")
        if r["kind"] == "deposit":
            db.execute("UPDATE wallets SET balance = balance + ? WHERE user_id=?", (r["amount"], r["user_id"]))
            db.execute("INSERT INTO transactions (type, to_user, amount) VALUES ('deposit', ?, ?)",
                       (r["user_id"], r["amount"]))
        else:  # withdraw
            w = db.execute("SELECT balance FROM wallets WHERE user_id=?", (r["user_id"],)).fetchone()
            if w["balance"] < r["amount"]:
                db.execute("ROLLBACK")
                return jsonify(error="صارف کا بیلنس ناکافی ہے، منظور نہیں ہو سکتی"), 400
            db.execute("UPDATE wallets SET balance = balance - ? WHERE user_id=?", (r["amount"], r["user_id"]))
            db.execute("INSERT INTO transactions (type, from_user, amount) VALUES ('withdraw', ?, ?)",
                       (r["user_id"], r["amount"]))
        db.execute("UPDATE requests SET status='approved', decided_at=datetime('now') WHERE id=?", (req_id,))
        db.commit()
    except sqlite3.Error:
        db.rollback()
        return jsonify(error="ناکام، دوبارہ کوشش کریں"), 500

    return jsonify(message="منظور ہو گئی ✅ بیلنس اپڈیٹ کر دیا گیا")


if __name__ == "__main__":
    print(f"\n💳 Wallet app v2 چل رہی ہے:  http://localhost:{PORT}")
    print(f"   Admin موبائل نمبر: {ADMIN_MOBILE} (app.py میں بدل سکتے ہیں)")
    print(f"   Email mode: {EMAIL_MODE}\n")
    app.run(host="0.0.0.0", port=PORT)
