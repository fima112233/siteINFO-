"""siteINFO+ — Flask-приложение: чат-интерфейс + SSE-стрим + история + логин/регистр.

Фичи:
  • много пробивов в одном чате (каждый — свой SSE-канал);
  • кнопка «Пробить↔Стоп»: отменяет текущий прогон;
  • история пробивов и чат-сообщений для каждого пользователя (SQLite);
  • регистрация / вход (сессии, пароли хэшируются).
"""
import os
import re
import json
import sqlite3
import hashlib
import secrets
import queue
import threading
import time
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, Response, render_template, session, g, redirect, url_for

from recon.engine import Reconsuite

HERE = os.path.dirname(__file__)


def _load_env(path=os.path.join(HERE, ".env")):
    """Мини-загрузчик .env (без внешних зависимостей)."""
    try:
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip(); v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)
    except Exception:
        pass


_load_env()

DB_PATH = os.path.join(HERE, "siteinfo.db")
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

suite = Reconsuite(max_workers=12, timeout=90)
jobs = {}            # jid -> Job
jobs_lock = threading.Lock()


# ---------------------------------------------------------------- БД ----
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pass_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conv_id INTEGER NOT NULL,
        kind TEXT NOT NULL,          -- user | stage | ok | err | block | final | note
        content TEXT NOT NULL,
        ts INTEGER NOT NULL,
        FOREIGN KEY (conv_id) REFERENCES conversations(id)
    );
    """)
    db.commit()
    # ---- миграции для существующих БД ----
    cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
    for col, ddl in (("is_admin", "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"),
                     ("is_active", "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"),
                     ("last_login", "ALTER TABLE users ADD COLUMN last_login TEXT")):
        if col not in cols:
            try:
                db.execute(ddl)
                db.commit()
            except Exception:
                pass
    db.close()


def sha256(pw: str, salt: str) -> str:
    return hashlib.sha256((salt + pw + salt).encode()).hexdigest()


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=? AND is_active=1", (uid,)).fetchone()
    if not row:
        session.clear()
        return None
    return row


# ------------------------------------------------------------- класс Job --
class Job:
    def __init__(self, jid, raw_url):
        self.id = jid
        self.raw_url = raw_url
        self.q = queue.Queue()
        self.done = False
        self.report = None
        self.results = {}
        self.started = datetime.utcnow().isoformat() + "Z"
        self.cancel = threading.Event()

    def put(self, evt):
        try:
            self.q.put_nowait(evt)
        except Exception:
            pass


# ------------------------------------------------------------- страницы --
@app.route("/")
def index():
    if not current_user():
        return redirect(url_for("auth_page"))
    db = get_db()
    convs = db.execute(
        "SELECT * FROM conversations WHERE user_id=? ORDER BY id DESC", (session["uid"],)
    ).fetchall()
    current_id = convs[0]["id"] if convs else None
    # админ может открыть любой чат по /?view=<cid> — в обычном чат-интерфейсе
    view_cid = request.args.get("view", type=int)
    if view_cid:
        conv = db.execute("SELECT id, user_id FROM conversations WHERE id=?", (view_cid,)).fetchone()
        if not conv:
            view_cid = None
        elif conv["user_id"] != session["uid"] and not is_admin_user():
            view_cid = None  # не админ и не владелец — игнорируем
    else:
        view_cid = None
    return render_template("index.html", conversations=convs,
                           user=session.get("username", ""), current_id=current_id,
                           view_cid=view_cid)


@app.route("/auth")
def auth_page():
    return render_template("auth.html")


# ------------------------------------------------------------- API: auth --
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not re.match(r"^[A-Za-z0-9_]{3,24}$", username):
        return jsonify({"error": "ник: 3–24 символа, латиница/цифры/_"}), 400
    if len(password) < 6:
        return jsonify({"error": "пароль минимум 6 символов"}), 400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return jsonify({"error": "такой ник уже занят"}), 409
    salt = secrets.token_hex(8)
    h = sha256(password, salt)
    db.execute("INSERT INTO users(username, pass_hash, created_at) VALUES(?,?,?)",
               (username, f"{salt}:{h}", datetime.utcnow().isoformat() + "Z"))
    db.commit()
    uid = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
    db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat() + "Z", uid))
    db.commit()
    session.permanent = True
    session["uid"] = uid
    session["username"] = username
    return jsonify({"ok": True, "username": username})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "неверный ник или пароль"}), 401
    if not row["is_active"]:
        return jsonify({"error": "аккаунт заблокирован"}), 403
    stored = row["pass_hash"]
    salt = stored.split(":")[0]
    if sha256(password, salt) != stored.split(":")[1]:
        return jsonify({"error": "неверный ник или пароль"}), 401
    db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat() + "Z", row["id"]))
    db.commit()
    session.permanent = True
    session["uid"] = row["id"]
    session["username"] = username
    return jsonify({"ok": True, "username": username})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    u = current_user()
    if not u:
        return jsonify({"user": None}), 401
    return jsonify({"user": {"id": u["id"], "username": u["username"]}})


def require_user():
    if not current_user():
        return jsonify({"error": "нужен вход"}), 401
    return None


def require_admin():
    u = current_user()
    if not u:
        return jsonify({"error": "нужен вход"}), 401
    if not u["is_admin"]:
        return jsonify({"error": "нужны права администратора"}), 403
    return None


def is_admin_user():
    u = current_user()
    return bool(u and u["is_admin"])


ADMIN_USERS = set(x.strip() for x in os.environ.get("ADMIN_USERS", "").split(",") if x.strip())


def promote_admins():
    """Назначает админами всех из ADMIN_USERS (по ENV) + первого зарегистрированного юзера."""
    db = sqlite3.connect(DB_PATH)
    try:
        for uname in ADMIN_USERS:
            db.execute("UPDATE users SET is_admin=1 WHERE username=?", (uname,))
        db.commit()
    finally:
        db.close()


# ------------------------------------------------------------- API: chat --
@app.route("/api/conversation/new", methods=["POST"])
def new_conversation():
    if (err := require_user()):
        return err
    db = get_db()
    cur = db.execute("INSERT INTO conversations(user_id, created_at) VALUES(?,?)",
                     (session["uid"], datetime.utcnow().isoformat() + "Z"))
    db.commit()
    return jsonify({"conv_id": cur.lastrowid})


@app.route("/api/conversation/<int:cid>/messages")
def conv_messages(cid):
    if (err := require_user()):
        return err
    db = get_db()
    conv = db.execute("SELECT * FROM conversations WHERE id=?", (cid,)).fetchone()
    if not conv:
        return jsonify({"error": "not found"}), 404
    # обычно чат видит только владелец; админ может читать любой (просмотр от имени админа)
    if conv["user_id"] != session["uid"] and not is_admin_user():
        return jsonify({"error": "not found"}), 404
    msgs = db.execute("SELECT * FROM messages WHERE conv_id=? ORDER BY id ASC", (cid,)).fetchall()
    return jsonify([dict(m) for m in msgs])


@app.route("/api/conversation/<int:cid>", methods=["DELETE"])
def delete_conversation(cid):
    if (err := require_user()):
        return err
    db = get_db()
    db.execute("DELETE FROM messages WHERE conv_id=?", (cid,))
    db.execute("DELETE FROM conversations WHERE id=? AND user_id=?", (cid, session["uid"]))
    db.commit()
    return jsonify({"ok": True})


def save_message(cid, kind, content):
    try:
        # Отдельное соединение: вызывается и из request-контекста, и из фонового
        # потока прогона (где нет Flask g), поэтому всегда свой connect.
        db = sqlite3.connect(DB_PATH)
        try:
            db.execute("INSERT INTO messages(conv_id, kind, content, ts) VALUES(?,?,?,?)",
                       (cid, kind, content, int(time.time() * 1000)))
            db.commit()
        finally:
            db.close()
    except Exception:
        pass


# ------------------------------------------------------------- API: scan --
@app.route("/api/scan", methods=["POST"])
def scan():
    if (err := require_user()):
        return err
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    cid = data.get("conv_id")
    if not url:
        return jsonify({"error": "url обязателен"}), 400
    if not re_ok(url):
        return jsonify({"error": "непохоже на URL/host"}), 400

    # контекст прогона
    if cid:
        db = get_db()
        conv = db.execute("SELECT * FROM conversations WHERE id=? AND user_id=?",
                          (cid, session["uid"])).fetchone()
        if not conv:
            return jsonify({"error": "нет такого чата"}), 400
    else:
        db = get_db()
        cur = db.execute("INSERT INTO conversations(user_id, created_at) VALUES(?,?)",
                         (session["uid"], datetime.utcnow().isoformat() + "Z"))
        db.commit()
        cid = cur.lastrowid

    jid = f"job-{int(time.time() * 1000)}"
    job = Job(jid, url)
    job.conv_id = cid
    with jobs_lock:
        jobs[jid] = job

    save_message(cid, "user", url)

    def _run():
        try:
            ctx, results, report = suite.run(url, job_id=jid, out_events=job.q,
                                             cancel_event=job.cancel)
            job.results = results
            job.report = report
            if not job.cancel.is_set():
                save_message(cid, "final", report)
        except Exception as e:
            job.put({"kind": "terminal", "text": f"Сбой прогона: {e}"})
            save_message(cid, "note", f"Сбой прогона: {e}")
        finally:
            job.done = True
            job.put({"kind": "done"})

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"job_id": jid, "url": url, "conv_id": cid,
                    "stream": f"/api/stream/{jid}"})


def re_ok(url):
    u = url.lower().strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    if not u:
        return False
    bad = any(x in u for x in (" ", "<", ">", '"', "'", "\\"))
    return not bad and "." in u


@app.route("/api/stream/<jid>")
def stream(jid):
    with jobs_lock:
        job = jobs.get(jid)
    if not job:
        return jsonify({"error": "job not found"}), 404

    def gen():
        yield "event: open\ndata: {}\n\n"
        while True:
            try:
                evt = job.q.get(timeout=1.0)
            except queue.Empty:
                if job.done:
                    break
                yield ": keepalive\n\n"
                continue
            if evt.get("kind") in ("stage", "ok", "err", "block", "final", "done", "terminal"):
                yield f"event: {evt['kind']}\ndata: {json.dumps(evt, ensure_ascii=False)}\n\n"
                if evt.get("kind") == "done":
                    break
        yield "event: __end__\ndata: {}\n\n"

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/<jid>/cancel", methods=["POST"])
def cancel_scan(jid):
    if (err := require_user()):
        return err
    with jobs_lock:
        job = jobs.get(jid)
    if not job:
        return jsonify({"error": "job not found"}), 404
    job.cancel.set()
    job.put({"kind": "stage", "text": "Прогон остановлен…", "ts": datetime.utcnow().isoformat() + "Z"})
    return jsonify({"ok": True})


@app.route("/api/report/<path:host>")
def report_json(host):
    j = None
    with jobs_lock:
        for _j in reversed(list(jobs.values())):
            if _j.raw_url.lower().strip().rstrip("/").endswith(host.lower().strip()):
                j = _j
                break
    if not j:
        return jsonify({"error": "no run for this host"}), 404
    return jsonify({
        "job_id": j.id, "target": j.raw_url, "started": j.started,
        "finished": j.done, "results": j.results, "report": j.report,
    })


@app.route("/healthz")
def health():
    return jsonify({"ok": True, "service": "siteINFO+", "checks": len(suite._plan())})


# =============================================================== АДМИНКА ==
@app.route("/admin")
def admin_page():
    if not current_user():
        return redirect(url_for("auth_page"))
    if not is_admin_user():
        return redirect(url_for("index"))
    return render_template("admin.html", user=session.get("username", ""))


@app.route("/api/admin/stats")
def admin_stats():
    if (err := require_admin()):
        return err
    db = get_db()
    def one(q):
        return db.execute(q).fetchone()[0]
    return jsonify({
        "users": one("SELECT COUNT(*) FROM users"),
        "admins": one("SELECT COUNT(*) FROM users WHERE is_admin=1"),
        "active_users": one("SELECT COUNT(*) FROM users WHERE is_active=1"),
        "conversations": one("SELECT COUNT(*) FROM conversations"),
        "messages": one("SELECT COUNT(*) FROM messages"),
        "scans": one("SELECT COUNT(*) FROM messages WHERE kind='user'"),
        "reports": one("SELECT COUNT(*) FROM messages WHERE kind='final'"),
        "running_jobs": len(jobs),
    })


@app.route("/api/admin/users")
def admin_users():
    if (err := require_admin()):
        return err
    db = get_db()
    rows = db.execute("""
        SELECT u.*,
          (SELECT COUNT(*) FROM conversations c WHERE c.user_id=u.id) AS conv_count,
          (SELECT COUNT(*) FROM messages m JOIN conversations c ON m.conv_id=c.id
             WHERE c.user_id=u.id AND m.kind='user') AS scan_count
        FROM users u ORDER BY u.id DESC
    """).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d.pop("pass_hash", None)
        out.append(d)
    return jsonify(out)


@app.route("/api/admin/users/<int:uid>", methods=["PATCH"])
def admin_update_user(uid):
    if (err := require_admin()):
        return err
    data = request.get_json(silent=True) or {}
    db = get_db()
    me = current_user()
    target = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        return jsonify({"error": "нет такого юзера"}), 404
    # защита: нельзя себя убрать из админов или заблокировать себя
    if uid == me["id"] and (data.get("is_admin") == 0 or data.get("is_active") == 0):
        return jsonify({"error": "нельзя менять свои права"}), 400
    if "is_admin" in data:
        db.execute("UPDATE users SET is_admin=? WHERE id=?", (1 if data["is_admin"] else 0, uid))
    if "is_active" in data:
        db.execute("UPDATE users SET is_active=? WHERE id=?", (1 if data["is_active"] else 0, uid))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
def admin_delete_user(uid):
    if (err := require_admin()):
        return err
    db = get_db()
    me = current_user()
    if uid == me["id"]:
        return jsonify({"error": "нельзя удалить себя"}), 400
    # удаляем юзера с его чатами и сообщениями
    db.execute("DELETE FROM messages WHERE conv_id IN (SELECT id FROM conversations WHERE user_id=?)", (uid,))
    db.execute("DELETE FROM conversations WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/admin/conversations")
def admin_conversations():
    if (err := require_admin()):
        return err
    db = get_db()
    rows = db.execute("""
        SELECT c.id, c.user_id, u.username, c.created_at,
          (SELECT COUNT(*) FROM messages m WHERE m.conv_id=c.id) AS msg_count,
          (SELECT COUNT(*) FROM messages m WHERE m.conv_id=c.id AND m.kind='user') AS scan_count
        FROM conversations c JOIN users u ON u.id=c.user_id
        ORDER BY c.id DESC LIMIT 500
    """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/conversations/<int:cid>")
def admin_conv_detail(cid):
    if (err := require_admin()):
        return err
    db = get_db()
    conv = db.execute("""
        SELECT c.*, u.username FROM conversations c JOIN users u ON u.id=c.user_id WHERE c.id=?
    """, (cid,)).fetchone()
    if not conv:
        return jsonify({"error": "not found"}), 404
    msgs = db.execute("SELECT * FROM messages WHERE conv_id=? ORDER BY id ASC", (cid,)).fetchall()
    return jsonify({"conversation": dict(conv), "messages": [dict(m) for m in msgs]})


@app.route("/api/admin/conversations/<int:cid>", methods=["DELETE"])
def admin_delete_conv(cid):
    if (err := require_admin()):
        return err
    db = get_db()
    db.execute("DELETE FROM messages WHERE conv_id=?", (cid,))
    db.execute("DELETE FROM conversations WHERE id=?", (cid,))
    db.commit()
    return jsonify({"ok": True})


init_db()
promote_admins()

if __name__ == "__main__":
    import sys
    port = int(os.environ.get("PORT", 5005))
    host = os.environ.get("HOST", "0.0.0.0" if os.environ.get("PROD") else "127.0.0.1")
    mode = os.environ.get("WSGI", "")
    try:
        print("\n  siteINFO+ %s | http://%s:%d | checks=%d\n"
              % ("prod (waitress)" if mode.strip().lower() == "waitress" else "dev", host, port,
                 len(suite._plan())))
    except Exception:
        pass
    if mode.strip().lower() == "waitress" or os.environ.get("PROD"):
        # production: waitress (надёжный WSGI для Windows)
        try:
            from waitress import serve
            print("  словарь: waitress (threads=16)")
            serve(app, host=host, port=port, threads=16)
        except ImportError:
            print("  waitress не установлен, падаем на dev-сервер")
            app.run(host=host, port=port, threaded=True, debug=False)
    else:
        app.run(host=host, port=port, threaded=True, debug=False)