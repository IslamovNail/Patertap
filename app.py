import os, re, sqlite3, secrets, hashlib, hmac, json, time
from datetime import date, datetime, timezone
from functools import wraps
from flask import Flask, jsonify, request, render_template, g
from werkzeug.exceptions import HTTPException

APP_DIR=os.path.dirname(os.path.abspath(__file__))
DB_PATH=os.environ.get("PATERTAP_DB",os.path.join(APP_DIR,"patertap.sqlite3"))
SECRET=os.environ.get("PATERTAP_SECRET")
if not SECRET:
    # Local-development convenience only; set a strong secret in production.
    SECRET="local-dev-only-change-me"
app=Flask(__name__,template_folder="templates",static_folder="static")
app.config["MAX_CONTENT_LENGTH"]=2*1024*1024
app.config["JSON_SORT_KEYS"]=False

def db():
    if "db" not in g:
        g.db=sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory=sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def close_db(exc):
    conn=g.pop("db",None)
    if conn: conn.close()

SCHEMA="""
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, name TEXT NOT NULL, birth_date TEXT NOT NULL,
 city TEXT NOT NULL DEFAULT 'Алматы', status TEXT DEFAULT '', budget INTEGER,
 sleep TEXT DEFAULT '', cleanliness TEXT DEFAULT '', guests TEXT DEFAULT '',
 smoking TEXT DEFAULT '', noise TEXT DEFAULT '', privacy TEXT DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS listings(
 id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL, description TEXT NOT NULL, district TEXT NOT NULL,
 price INTEGER NOT NULL CHECK(price>0), type TEXT NOT NULL, available_from TEXT NOT NULL,
 amenities TEXT DEFAULT '', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS listings_search_idx ON listings(district,type,price);
CREATE INDEX IF NOT EXISTS listings_owner_idx ON listings(owner_id);
CREATE TABLE IF NOT EXISTS favorites(
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL, PRIMARY KEY(user_id,listing_id)
);
CREATE TABLE IF NOT EXISTS conversations(
 id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, UNIQUE(id)
);
CREATE TABLE IF NOT EXISTS participants(
 conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(conversation_id,user_id)
);
CREATE INDEX IF NOT EXISTS participant_user_idx ON participants(user_id);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body TEXT NOT NULL CHECK(length(body)<=2000), created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id,id);
CREATE TABLE IF NOT EXISTS blocks(
 blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL, PRIMARY KEY(blocker_id,blocked_id), CHECK(blocker_id<>blocked_id)
);
CREATE TABLE IF NOT EXISTS reports(
 id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 listing_id INTEGER REFERENCES listings(id) ON DELETE SET NULL,
 reason TEXT NOT NULL, details TEXT DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL, expires_at INTEGER NOT NULL
);
"""
def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def init_db():
    conn=sqlite3.connect(DB_PATH); conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA); conn.commit(); conn.close()
init_db()

def error(message,status=400): return jsonify(error=message),status
def clean(s,limit=2000):
    if not isinstance(s,str): return ""
    return s.strip()[:limit]
def valid_email(s):
    return isinstance(s,str) and len(s)<=254 and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",s) is not None
def hash_password(password):
    salt=secrets.token_bytes(16)
    derived=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000)
    return salt.hex()+":"+derived.hex()
def verify_password(password,stored):
    try:
        salt,expected=stored.split(":")
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),310000).hex()
        return hmac.compare_digest(actual,expected)
    except Exception: return False
def user_public(row):
    return {k:row[k] for k in ("id","name","city","status","budget","sleep","cleanliness","guests","smoking","noise","privacy")}
def current_user():
    auth=request.headers.get("Authorization","")
    token=auth[7:] if auth.startswith("Bearer ") else request.cookies.get("pt_session","")
    if not token: return None
    digest=hashlib.sha256(token.encode()).hexdigest()
    row=db().execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",(digest,int(time.time()))).fetchone()
    return row
def login_required(fn):
    @wraps(fn)
    def wrapped(*args,**kwargs):
        g.user=current_user()
        if not g.user: return error("Требуется войти в аккаунт",401)
        return fn(*args,**kwargs)
    return wrapped
def create_session(user_id):
    token=secrets.token_urlsafe(32); digest=hashlib.sha256(token.encode()).hexdigest()
    db().execute("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",(digest,user_id,now(),int(time.time())+60*60*24*14))
    db().commit()
    return token
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"]="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    return response
@app.errorhandler(413)
def too_large(e): return error("Файл или запрос слишком большой",413)
@app.errorhandler(Exception)
def unexpected(e):
    if isinstance(e,HTTPException): return e
    app.logger.exception("Unhandled server error")
    return error("Внутренняя ошибка сервера",500)

@app.get("/")
def home(): return render_template("index.html")

@app.post("/api/auth/register")
def register():
    d=request.get_json(silent=True) or {}
    email=clean(d.get("email"),254).lower(); password=d.get("password","")
    name=clean(d.get("name"),80); born=clean(d.get("birth_date"),10)
    if not valid_email(email): return error("Введите корректный email")
    if not isinstance(password,str) or len(password)<10 or len(password)>128: return error("Пароль должен содержать от 10 до 128 символов")
    if not name: return error("Укажите имя")
    try: born_date=date.fromisoformat(born)
    except Exception: return error("Укажите корректную дату рождения")
    age=(date.today()-born_date).days/365.2425
    if age<17: return error("Регистрация доступна с 17 лет",403)
    if age>120: return error("Проверьте дату рождения")
    try:
        cur=db().execute("INSERT INTO users(email,password_hash,name,birth_date,created_at) VALUES(?,?,?,?,?)",(email,hash_password(password),name,born,now()))
        db().commit()
    except sqlite3.IntegrityError: return error("Аккаунт с таким email уже существует",409)
    row=db().execute("SELECT * FROM users WHERE id=?",(cur.lastrowid,)).fetchone()
    return jsonify(token=create_session(row["id"]),user=user_public(row)),201

@app.post("/api/auth/login")
def login():
    d=request.get_json(silent=True) or {}; email=clean(d.get("email"),254).lower(); password=d.get("password","")
    row=db().execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    if not row or not verify_password(password,row["password_hash"]): return error("Неверный email или пароль",401)
    return jsonify(token=create_session(row["id"]),user=user_public(row))
@app.post("/api/auth/logout")
@login_required
def logout():
    token=request.headers.get("Authorization","")[7:]
    if token: db().execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(token.encode()).hexdigest(),))
    db().commit(); return jsonify(ok=True)
@app.get("/api/me")
@login_required
def me(): return jsonify(user=user_public(g.user))

@app.put("/api/profile")
@login_required
def update_profile():
    d=request.get_json(silent=True) or {}
    name=clean(d.get("name"),80)
    if not name: return error("Имя обязательно")
    fields={"city":clean(d.get("city") or "Алматы",80),"status":clean(d.get("status"),40),
            "sleep":clean(d.get("sleep"),50),"cleanliness":clean(d.get("cleanliness"),50),
            "guests":clean(d.get("guests"),50),"smoking":clean(d.get("smoking"),80),
            "noise":clean(d.get("noise"),50),"privacy":clean(d.get("privacy"),50)}
    budget=d.get("budget")
    if budget in ("",None): budget=None
    try: budget=int(budget) if budget is not None else None
    except: return error("Бюджет должен быть числом")
    if budget is not None and not 0<=budget<=5000000: return error("Проверьте бюджет")
    fields["name"]=name; fields["budget"]=budget
    db().execute("UPDATE users SET "+",".join(k+"=?" for k in fields)+" WHERE id=?",(*fields.values(),g.user["id"]));db().commit()
    row=db().execute("SELECT * FROM users WHERE id=?",(g.user["id"],)).fetchone()
    return jsonify(user=user_public(row))

@app.get("/api/listings")
def listings():
    q=clean(request.args.get("q",""),100); district=clean(request.args.get("district",""),80); typ=clean(request.args.get("type",""),40)
    sql="SELECT l.*,u.name AS owner_name FROM listings l JOIN users u ON u.id=l.owner_id WHERE 1=1"; args=[]
    if q: sql+=" AND (l.title LIKE ? OR l.description LIKE ? OR l.district LIKE ?)";args += [f"%{q}%"]*3
    if district: sql+=" AND l.district=?";args.append(district)
    if typ: sql+=" AND l.type=?";args.append(typ)
    try:
        maxp=request.args.get("max_price")
        if maxp: sql+=" AND l.price<=?";args.append(max(0,min(5000000,int(maxp))))
    except: return error("Некорректный максимальный бюджет")
    sql+=" ORDER BY l.created_at DESC LIMIT 100"
    items=[]
    for r in db().execute(sql,args).fetchall():
        x=dict(r);x["demo"]=False;x["visual"]=["","orange","blue"][x["id"]%3];items.append(x)
    # Clearly labelled fixtures for first-time visitors; never represented as actual user posts.
    if not q and not district and not typ and not request.args.get("max_price"):
        items += [
          {"id":-1,"title":"Светлая комната рядом с метро","description":"Демонстрационный пример","district":"Бостандыкский","price":85000,"type":"Комната","available_from":"2026-11-01","amenities":"Мебель · Wi-Fi","owner_id":0,"owner_name":"Демо","demo":True,"visual":"orange"},
          {"id":-2,"title":"Подселение в уютную квартиру","description":"Демонстрационный пример","district":"Алмалинский","price":70000,"type":"Подселение","available_from":"2026-11-10","amenities":"Кухня · стиральная машина","owner_id":0,"owner_name":"Демо","demo":True,"visual":"blue"},
          {"id":-3,"title":"Студия для одного человека","description":"Демонстрационный пример","district":"Медеуский","price":145000,"type":"Студия","available_from":"2026-11-15","amenities":"Мебель · коммунальные отдельно","owner_id":0,"owner_name":"Демо","demo":True,"visual":""}
        ]
    return jsonify(items=items)
@app.post("/api/listings")
@login_required
def create_listing():
    d=request.get_json(silent=True) or {}
    title=clean(d.get("title"),120); description=clean(d.get("description"),3000); district=clean(d.get("district"),80)
    typ=clean(d.get("type"),40); amenities=clean(d.get("amenities"),400); available=clean(d.get("available_from"),10)
    try: price=int(d.get("price"))
    except: return error("Укажите цену числом")
    if not title or not description or not district: return error("Заполните обязательные поля")
    if not 1000<=price<=5000000:return error("Цена должна быть от 1 000 до 5 000 000 ₸")
    if typ not in ("Комната","Квартира","Подселение","Студия"):return error("Выберите тип жилья")
    try: date.fromisoformat(available)
    except: return error("Укажите дату доступности")
    cur=db().execute("INSERT INTO listings(owner_id,title,description,district,price,type,available_from,amenities,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(g.user["id"],title,description,district,price,typ,available,amenities,now()));db().commit()
    return jsonify(id=cur.lastrowid),201
@app.put("/api/listings/<int:lid>")
@login_required
def edit_listing(lid):
    r=db().execute("SELECT * FROM listings WHERE id=?",(lid,)).fetchone()
    if not r:return error("Объявление не найдено",404)
    if r["owner_id"]!=g.user["id"]:return error("Можно редактировать только свои объявления",403)
    d=request.get_json(silent=True) or {}
    title=clean(d.get("title",r["title"]),120);desc=clean(d.get("description",r["description"]),3000);district=clean(d.get("district",r["district"]),80)
    try: price=int(d.get("price",r["price"]))
    except: return error("Некорректная цена")
    if not title or not desc or not district or not 1000<=price<=5000000:return error("Проверьте обязательные поля и цену")
    db().execute("UPDATE listings SET title=?,description=?,district=?,price=?,type=?,available_from=?,amenities=? WHERE id=?",(title,desc,district,price,clean(d.get("type",r["type"]),40),clean(d.get("available_from",r["available_from"]),10),clean(d.get("amenities",r["amenities"]),400),lid));db().commit()
    return jsonify(ok=True)
@app.delete("/api/listings/<int:lid>")
@login_required
def delete_listing(lid):
    r=db().execute("SELECT owner_id FROM listings WHERE id=?",(lid,)).fetchone()
    if not r:return error("Объявление не найдено",404)
    if r["owner_id"]!=g.user["id"]:return error("Можно удалить только своё объявление",403)
    db().execute("DELETE FROM listings WHERE id=?",(lid,));db().commit();return jsonify(ok=True)

@app.post("/api/favorites/<int:lid>")
@login_required
def add_favorite(lid):
    if lid<1 or not db().execute("SELECT 1 FROM listings WHERE id=?",(lid,)).fetchone():return error("Это демо-объявление нельзя сохранить или объявление не найдено",404)
    db().execute("INSERT OR IGNORE INTO favorites(user_id,listing_id,created_at) VALUES(?,?,?)",(g.user["id"],lid,now()));db().commit();return jsonify(ok=True)
@app.delete("/api/favorites/<int:lid>")
@login_required
def remove_favorite(lid):
    db().execute("DELETE FROM favorites WHERE user_id=? AND listing_id=?",(g.user["id"],lid));db().commit();return jsonify(ok=True)
@app.get("/api/favorites")
@login_required
def get_favorites():
    rows=db().execute("SELECT l.*,u.name AS owner_name FROM favorites f JOIN listings l ON l.id=f.listing_id JOIN users u ON u.id=l.owner_id WHERE f.user_id=? ORDER BY f.created_at DESC",(g.user["id"],)).fetchall()
    return jsonify(items=[dict(r, demo=False,visual="") for r in rows])

def compatibility(a,b):
    weights={"budget":25,"sleep":15,"cleanliness":15,"guests":10,"smoking":10,"noise":10,"privacy":5,"district":5,"available_from":5}
    labels={"budget":"Бюджет","sleep":"Режим сна","cleanliness":"Чистота","guests":"Гости","smoking":"Курение","noise":"Шум","privacy":"Личное пространство","district":"Район","available_from":"Дата заселения"}
    vals={"budget":(a["budget"],b["budget"]),"sleep":(a["sleep"],b["sleep"]),"cleanliness":(a["cleanliness"],b["cleanliness"]),"guests":(a["guests"],b["guests"]),"smoking":(a["smoking"],b["smoking"]),"noise":(a["noise"],b["noise"]),"privacy":(a["privacy"],b["privacy"]),"district":(a["city"],b["city"]),"available_from":(None,None)}
    matches=[];diff=[];earned=possible=0
    for k,w in weights.items():
        x,y=vals[k]
        if x is None or y is None or x=="" or y=="":continue
        possible+=w
        ok=(abs(int(x)-int(y))<=25000 if k=="budget" else x==y)
        if ok:earned+=w;matches.append(labels[k])
        else:diff.append(labels[k])
    # Score only when at least 50% of configured weight has known values.
    score=round(earned/possible*100) if possible>=50 else None
    return score,matches,diff
@app.get("/api/roommates")
@login_required
def roommates():
    others=db().execute("SELECT * FROM users WHERE id<>? ORDER BY created_at DESC LIMIT 50",(g.user["id"],)).fetchall()
    blocked={r["blocked_id"] for r in db().execute("SELECT blocked_id FROM blocks WHERE blocker_id=? UNION SELECT blocker_id AS blocked_id FROM blocks WHERE blocked_id=?",(g.user["id"],g.user["id"])).fetchall()}
    items=[]
    for u in others:
        if u["id"] in blocked:continue
        score,matches,diffs=compatibility(g.user,u)
        items.append({"id":u["id"],"name":u["name"],"city":u["city"],"status":u["status"],"compatibility":score if score is not None else "—","matches":matches,"differences":diffs})
    return jsonify(items=items)

def conversation_access(cid,uid):
    return db().execute("SELECT 1 FROM participants WHERE conversation_id=? AND user_id=?",(cid,uid)).fetchone() is not None
def is_blocked(a,b):
    return db().execute("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",(a,b,b,a)).fetchone() is not None
@app.post("/api/conversations")
@login_required
def create_conversation():
    d=request.get_json(silent=True) or {}
    try: other=int(d.get("other_user_id"))
    except: return error("Некорректный пользователь")
    if other==g.user["id"] or not db().execute("SELECT 1 FROM users WHERE id=?",(other,)).fetchone():return error("Пользователь не найден")
    if is_blocked(g.user["id"],other):return error("Общение недоступно из-за блокировки",403)
    existing=db().execute("""SELECT p1.conversation_id FROM participants p1 JOIN participants p2 ON p1.conversation_id=p2.conversation_id
       WHERE p1.user_id=? AND p2.user_id=? LIMIT 1""",(g.user["id"],other)).fetchone()
    if existing:return jsonify(id=existing["conversation_id"])
    cur=db().execute("INSERT INTO conversations(created_at) VALUES(?)",(now(),));cid=cur.lastrowid
    db().executemany("INSERT INTO participants(conversation_id,user_id) VALUES(?,?)",[(cid,g.user["id"]),(cid,other)]);db().commit()
    return jsonify(id=cid),201
@app.get("/api/conversations")
@login_required
def list_conversations():
    rows=db().execute("""SELECT c.id, u.id other_id,u.name other_name,
      (SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) last_message
      FROM conversations c JOIN participants mine ON mine.conversation_id=c.id AND mine.user_id=?
      JOIN participants other ON other.conversation_id=c.id AND other.user_id<>?
      JOIN users u ON u.id=other.user_id ORDER BY c.id DESC""",(g.user["id"],g.user["id"])).fetchall()
    return jsonify(items=[dict(r) for r in rows])
@app.get("/api/conversations/<int:cid>/messages")
@login_required
def get_messages(cid):
    if not conversation_access(cid,g.user["id"]):return error("Диалог не найден или нет доступа",403)
    rows=db().execute("SELECT id,sender_id,body,created_at FROM messages WHERE conversation_id=? ORDER BY id ASC LIMIT 300",(cid,)).fetchall()
    return jsonify(items=[dict(r) for r in rows])
@app.post("/api/conversations/<int:cid>/messages")
@login_required
def send_message(cid):
    if not conversation_access(cid,g.user["id"]):return error("Диалог не найден или нет доступа",403)
    other=db().execute("SELECT user_id FROM participants WHERE conversation_id=? AND user_id<>?",(cid,g.user["id"])).fetchone()
    if not other:return error("Участник диалога не найден",404)
    if is_blocked(g.user["id"],other["user_id"]):return error("Сообщение не отправлено: пользователь заблокирован",403)
    d=request.get_json(silent=True) or {};body=clean(d.get("body"),2000)
    if not body:return error("Сообщение не может быть пустым")
    # Small per-user throttle: max 12 messages in a rolling minute.
    n=db().execute("SELECT COUNT(*) n FROM messages WHERE sender_id=? AND created_at>=?",(g.user["id"],datetime.fromtimestamp(time.time()-60,timezone.utc).isoformat(timespec="seconds"))).fetchone()["n"]
    if n>=12:return error("Слишком много сообщений. Попробуйте через минуту.",429)
    db().execute("INSERT INTO messages(conversation_id,sender_id,body,created_at) VALUES(?,?,?,?)",(cid,g.user["id"],body,now()));db().commit();return jsonify(ok=True),201

@app.post("/api/blocks/<int:uid>")
@login_required
def block_user(uid):
    if uid==g.user["id"] or not db().execute("SELECT 1 FROM users WHERE id=?",(uid,)).fetchone():return error("Нельзя заблокировать этого пользователя")
    db().execute("INSERT OR IGNORE INTO blocks(blocker_id,blocked_id,created_at) VALUES(?,?,?)",(g.user["id"],uid,now()));db().commit();return jsonify(ok=True)
@app.delete("/api/blocks/<int:uid>")
@login_required
def unblock_user(uid):
    db().execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?",(g.user["id"],uid));db().commit();return jsonify(ok=True)
@app.post("/api/reports")
@login_required
def report():
    d=request.get_json(silent=True) or {};reason=clean(d.get("reason"),100);details=clean(d.get("details"),2000)
    if not reason:return error("Укажите причину жалобы")
    try: target=int(d["target_user_id"]) if d.get("target_user_id") else None
    except: return error("Некорректный пользователь")
    try: listing_id=int(d["listing_id"]) if d.get("listing_id") else None
    except: return error("Некорректное объявление")
    if target==g.user["id"]:return error("Нельзя пожаловаться на себя")
    if target and not db().execute("SELECT 1 FROM users WHERE id=?",(target,)).fetchone():return error("Пользователь не найден")
    if listing_id and not db().execute("SELECT 1 FROM listings WHERE id=?",(listing_id,)).fetchone():return error("Объявление не найдено")
    db().execute("INSERT INTO reports(reporter_id,target_user_id,listing_id,reason,details,created_at) VALUES(?,?,?,?,?,?)",(g.user["id"],target,listing_id,reason,details,now()));db().commit();return jsonify(ok=True),201

if __name__=="__main__":
    app.run(host=os.environ.get("HOST","127.0.0.1"),port=int(os.environ.get("PORT","5000")),debug=False)
