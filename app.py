import os, re, json, time, sqlite3, secrets, urllib.request, urllib.error
from functools import wraps
from flask import Flask, g, request, session, redirect, render_template, abort, flash, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", BASE)
DB = os.path.join(DATA, "shjowme.db")
UP = os.path.join(DATA, "uploads")
KEY = os.path.join(DATA, ".secret")
OWNER = os.environ.get("OWNER_USERNAME", "").strip().lower()
os.makedirs(UP, exist_ok=True)
if not os.path.exists(KEY):
    with open(KEY, "w") as f:
        f.write(secrets.token_hex(32))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or open(KEY).read().strip()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(SESSION_COOKIE_SECURE=bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("RAILWAY_ENVIRONMENT_NAME") or os.environ.get("HTTPS")), MAX_CONTENT_LENGTH=60 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30)

THEMES = {
    "dusk": ("#15131f", "#e8e4f0", "#1f1c2e"), "paper": ("#e9e6df", "#1c1b19", "#f7f5f0"),
    "moss": ("#101612", "#dde6da", "#18211b"), "ember": ("#1a1210", "#f2e3da", "#251a16"),
    "sea": ("#0c141c", "#d9e8f2", "#12202c"), "rose": ("#1b1016", "#f5e1ea", "#27161f"),
    "mono": ("#000000", "#ffffff", "#0c0c0c"), "sand": ("#d8cfbf", "#26211a", "#e8e1d3"),
}
FONTS = {
    "sans": "'Avenir Next','Segoe UI',Helvetica,Arial,sans-serif", "serif": "Georgia,'Times New Roman',serif",
    "mono": "ui-monospace,Menlo,Consolas,monospace", "round": "'Trebuchet MS',Verdana,sans-serif",
    "classic": "'Palatino Linotype',Palatino,'Book Antiqua',serif", "wide": "'Gill Sans','Century Gothic',sans-serif",
}
SOC = {
    "discord": "Discord", "github": "GitHub", "x": "X", "instagram": "Instagram", "youtube": "YouTube", "spotify": "Spotify",
    "twitch": "Twitch", "tiktok": "TikTok", "telegram": "Telegram", "reddit": "Reddit", "steam": "Steam", "website": "Website",
}
IMG = {"png", "jpg", "jpeg", "gif", "webp"}
EXT = {"avatar": IMG, "banner": IMG, "bg": IMG | {"mp4", "webm"}, "music": {"mp3", "ogg", "wav", "m4a"}}
CAP = {"avatar": 8, "banner": 10, "bg": 30, "music": 12}
RESERVED = {"admin", "login", "register", "logout", "dash", "inv", "usr", "static", "api", "owner", "root", "staff", "me"}
SCHEMA = """
create table if not exists users(id integer primary key autoincrement, username text unique not null collate nocase, pw text not null,
role text default 'user', created integer, display text default '', tagline text default '', bio text default '', location text default '',
theme text default 'dusk', accent text default '#b79cff', font text default 'sans', layout text default 'left', effect text default 'none',
card text default 'glass', blur integer default 14, opacity integer default 55, radius integer default 18, shape text default 'round',
typewriter integer default 0, show_views integer default 1, avatar text default '', banner text default '', bg text default '',
music text default '', music_title text default '', views integer default 0, banned integer default 0);
create table if not exists socials(id integer primary key autoincrement, user_id integer, kind text, url text);
create table if not exists invites(id integer primary key autoincrement, user_id integer, slug text unique not null collate nocase, code text,
title text default '', guild text default '', members integer default 0, online integer default 0, status text default 'active',
checked integer default 0, clicks integer default 0, created integer);
create table if not exists clicks(invite_id integer, ts integer);
create index if not exists ck on clicks(invite_id, ts);
create table if not exists views(user_id integer, ts integer, ref text default '', dev text default '');
create index if not exists vw on views(user_id, ts);
create table if not exists sclicks(social_id integer, user_id integer, ts integer);
create index if not exists sc on sclicks(user_id, ts);
"""
with sqlite3.connect(DB) as c:
    c.execute("pragma journal_mode=wal")
    c.executescript(SCHEMA)
    have = [r[1] for r in c.execute("pragma table_info(clicks)")]
    for col in ("ref", "dev"):
        if col not in have:
            c.execute("alter table clicks add column %s text default ''" % col)

attempts = {}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("pragma busy_timeout=5000")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    d = g.pop("db", None)
    if d:
        d.close()


def throttle(key, n=8, win=300):
    now = time.time()
    a = [x for x in attempts.get(key, []) if now - x < win]
    attempts[key] = a
    if len(a) >= n:
        return True
    a.append(now)
    return False


@app.before_request
def load():
    g.user = None
    uid = session.get("uid")
    if uid:
        u = db().execute("select * from users where id=?", (uid,)).fetchone()
        if u and not u["banned"]:
            g.user = u
        else:
            session.clear()
    if request.method == "POST":
        t = session.get("t")
        if not t or t != request.form.get("t"):
            abort(400)


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return r


@app.context_processor
def ctx():
    if "t" not in session:
        session["t"] = secrets.token_hex(16)
    return dict(me=g.user, T=Markup('<input type="hidden" name="t" value="%s">' % session["t"]), themes=THEMES, fonts=FONTS, soc=SOC)


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect("/login")
        return f(*a, **k)
    return w


def staff_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user or g.user["role"] not in ("owner", "staff"):
            abort(403)
        return f(*a, **k)
    return w


def owner_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user or g.user["role"] != "owner":
            abort(403)
        return f(*a, **k)
    return w


def num(v, lo, hi, d):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return d


def parse_code(s):
    s = (s or "").strip().split("?")[0].rstrip("/")
    m = re.match(r"^(?:https?://)?(?:www\.)?(?:discord\.gg/|discord(?:app)?\.com/invite/)?([A-Za-z0-9-]{2,32})$", s)
    return m.group(1) if m else None


def probe(code):
    req = urllib.request.Request("https://discord.com/api/v10/invites/%s?with_counts=true" % code, headers={"User-Agent": "ShjowMe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=4) as r:
            d = json.load(r)
        return "active", (d.get("guild") or {}).get("name", ""), d.get("approximate_member_count") or 0, d.get("approximate_presence_count") or 0
    except urllib.error.HTTPError as e:
        return ("expired" if e.code == 404 else "unknown"), "", 0, 0
    except Exception:
        return "unknown", "", 0, 0


def refresh(i, force=False):
    if not force and time.time() - i["checked"] < 600:
        return i
    s, n, m, o = probe(i["code"])
    if s != "unknown":
        db().execute("update invites set status=?, guild=?, members=?, online=?, checked=? where id=?", (s, n or i["guild"], m, o, int(time.time()), i["id"]))
        db().commit()
        i = db().execute("select * from invites where id=?", (i["id"],)).fetchone()
    return i


def is_bot():
    ua = request.headers.get("User-Agent", "").lower()
    return not ua or any(b in ua for b in ("bot", "crawl", "spider", "preview", "embed", "facebookexternalhit"))


def device():
    ua = request.headers.get("User-Agent", "").lower()
    return "mobile" if any(x in ua for x in ("mobi", "android", "iphone")) else "desktop"


def ref_host():
    m = re.match(r"^https?://([^/:]+)", request.referrer or "")
    h = m.group(1).lower() if m else ""
    h = h[4:] if h.startswith("www.") else h
    return "" if h == request.host.split(":")[0].lower() else h


def series(iid, days=14):
    return bars("clicks", "invite_id", iid, days)


def bars(table, col, val, days=14):
    start = int(time.time()) // 86400 - days + 1
    rows = db().execute("select ts/86400 d, count(*) c from %s where %s=? and ts>=? group by d" % (table, col), (val, start * 86400)).fetchall()
    m = {r["d"]: r["c"] for r in rows}
    out = [m.get(start + k, 0) for k in range(days)]
    top = max(out) or 1
    return [(v, round(v * 100 / top)) for v in out]


def music_ok(p):
    try:
        from mutagen import File
        m = File(p)
        return m is not None and m.info.length <= 240
    except ImportError:
        return os.path.getsize(p) <= 8 * 1024 * 1024
    except Exception:
        return False


def unlink(name):
    if name:
        try:
            os.remove(os.path.join(UP, name))
        except OSError:
            pass


@app.route("/")
def home():
    n = db().execute("select (select count(*) from users) u, (select count(*) from invites) i, (select coalesce(sum(clicks),0) from invites) c").fetchone()
    return render_template("home.html", n=n)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect("/dash")
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if throttle("r" + request.remote_addr, 6, 3600):
            flash("Too many sign-ups from here. Try again later.")
        elif not re.match(r"^[a-z0-9_.-]{3,24}$", u, re.I) or u.lower() in RESERVED:
            flash("Usernames are 3 to 24 characters: letters, numbers, dot, dash, underscore.")
        elif len(p) < 8:
            flash("Pick a password with at least 8 characters.")
        elif db().execute("select 1 from users where username=?", (u,)).fetchone():
            flash("That username is taken.")
        else:
            first = (u.lower() == OWNER) if OWNER else db().execute("select count(*) from users").fetchone()[0] == 0
            cur = db().execute("insert into users(username, pw, role, created, display) values(?,?,?,?,?)", (u, generate_password_hash(p), "owner" if first else "user", int(time.time()), u))
            db().commit()
            session.clear()
            session["uid"] = cur.lastrowid
            session.permanent = True
            return redirect("/dash")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect("/dash")
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        if throttle("l" + request.remote_addr + u.lower()):
            flash("Too many attempts. Wait a few minutes.")
        else:
            r = db().execute("select * from users where username=?", (u,)).fetchone()
            if r and not r["banned"] and check_password_hash(r["pw"], request.form.get("password", "")):
                session.clear()
                session["uid"] = r["id"]
                session.permanent = True
                return redirect("/dash")
            flash("Wrong username or password.")
    return render_template("auth.html", mode="login")


@app.post("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/dash")
@login_required
def dash():
    inv = [dict(i, bars=series(i["id"])) for i in db().execute("select * from invites where user_id=? order by id desc", (g.user["id"],)).fetchall()]
    soc = db().execute("select * from socials where user_id=? order by id", (g.user["id"],)).fetchall()
    uid = g.user["id"]
    since = int(time.time()) - 30 * 86400
    q = lambda sql, *a: db().execute(sql, a).fetchall()
    ids = "(select id from invites where user_id=?)"
    an = dict(
        vbars=bars("views", "user_id", uid),
        v30=q("select count(*) c from views where user_id=? and ts>=?", uid, since)[0]["c"],
        j30=q("select count(*) c from clicks where invite_id in %s and ts>=?" % ids, uid, since)[0]["c"],
        vrefs=q("select ref k, count(*) c from views where user_id=? and ts>=? group by k order by c desc limit 5", uid, since),
        jrefs=q("select ref k, count(*) c from clicks where invite_id in %s and ts>=? group by k order by c desc limit 5" % ids, uid, since),
        devs=q("select dev k, count(*) c from views where user_id=? and ts>=? group by k order by c desc", uid, since),
        links=q("select s.kind k, count(c.ts) c from socials s left join sclicks c on c.social_id=s.id and c.ts>=? where s.user_id=? group by s.id order by c desc", since, uid),
    )
    return render_template("dash.html", inv=inv, socials=soc, an=an)


@app.post("/dash/profile")
@login_required
def save_profile():
    f = request.form
    th = f.get("theme") if f.get("theme") in THEMES else "dusk"
    ft = f.get("font") if f.get("font") in FONTS else "sans"
    ac = f.get("accent", "")
    ac = ac if re.match(r"^#[0-9a-fA-F]{6}$", ac) else "#b79cff"
    lay = f.get("layout") if f.get("layout") in ("left", "center", "split") else "left"
    fx = f.get("effect") if f.get("effect") in ("none", "grain", "scan", "glow", "aurora") else "none"
    cd = f.get("card") if f.get("card") in ("glass", "solid", "outline", "bare") else "glass"
    sh = f.get("shape") if f.get("shape") in ("round", "soft", "square") else "round"
    db().execute(
        "update users set display=?, tagline=?, bio=?, location=?, theme=?, accent=?, font=?, layout=?, effect=?, card=?, blur=?, opacity=?, radius=?, shape=?, typewriter=?, show_views=?, music_title=? where id=?",
        (f.get("display", "")[:40], f.get("tagline", "")[:80], f.get("bio", "")[:500], f.get("location", "")[:40], th, ac, ft, lay, fx, cd,
         num(f.get("blur"), 0, 40, 14), num(f.get("opacity"), 0, 100, 55), num(f.get("radius"), 0, 48, 18), sh,
         1 if f.get("typewriter") else 0, 1 if f.get("show_views") else 0, f.get("music_title", "")[:60], g.user["id"]))
    db().commit()
    flash("Saved.")
    return redirect("/dash#look")


@app.post("/dash/media")
@login_required
def media():
    for kind in EXT:
        if kind in request.form.getlist("clear"):
            unlink(g.user[kind])
            db().execute("update users set %s='' where id=?" % kind, (g.user["id"],))
            continue
        f = request.files.get(kind)
        if not f or not f.filename:
            continue
        ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
        if ext not in EXT[kind]:
            flash("%s: unsupported file type." % kind)
            continue
        name = "%s.%s" % (secrets.token_hex(10), ext)
        path = os.path.join(UP, name)
        f.save(path)
        if os.path.getsize(path) > CAP[kind] * 1024 * 1024:
            os.remove(path)
            flash("%s is over %d MB." % (kind, CAP[kind]))
            continue
        if kind == "music" and not music_ok(path):
            os.remove(path)
            flash("Music has to be 4 minutes or shorter.")
            continue
        unlink(g.user[kind])
        db().execute("update users set %s=? where id=?" % kind, (name, g.user["id"]))
        g.user = db().execute("select * from users where id=?", (g.user["id"],)).fetchone()
    db().commit()
    flash("Media updated.")
    return redirect("/dash#media")


@app.post("/dash/social")
@login_required
def add_social():
    k = request.form.get("kind")
    u = request.form.get("url", "").strip()
    if k not in SOC or not u:
        flash("Choose a platform and paste a link.")
    elif db().execute("select count(*) from socials where user_id=?", (g.user["id"],)).fetchone()[0] >= 12:
        flash("You can add up to 12 links.")
    else:
        if not re.match(r"^https?://", u, re.I):
            u = "https://" + u
        db().execute("insert into socials(user_id, kind, url) values(?,?,?)", (g.user["id"], k, u[:300]))
        db().commit()
    return redirect("/dash#links")


@app.post("/dash/social/<int:sid>/delete")
@login_required
def del_social(sid):
    db().execute("delete from socials where id=? and user_id=?", (sid, g.user["id"]))
    db().commit()
    return redirect("/dash#links")


@app.post("/dash/invite")
@login_required
def add_invite():
    slug = request.form.get("slug", "").strip().lower()
    code = parse_code(request.form.get("link"))
    if not re.match(r"^[a-z0-9_-]{2,32}$", slug):
        flash("Custom names are 2 to 32 characters: letters, numbers, dash, underscore.")
    elif not code:
        flash("That doesn't look like a Discord invite.")
    elif db().execute("select 1 from invites where slug=?", (slug,)).fetchone():
        flash("That custom name is taken.")
    elif db().execute("select count(*) from invites where user_id=?", (g.user["id"],)).fetchone()[0] >= 25:
        flash("You've reached 25 invites.")
    else:
        s, n, m, o = probe(code)
        if s == "expired":
            flash("Discord says that invite is expired or invalid.")
        else:
            db().execute("insert into invites(user_id, slug, code, title, guild, members, online, status, checked, created) values(?,?,?,?,?,?,?,?,?,?)",
                         (g.user["id"], slug, code, request.form.get("title", "")[:60], n, m, o, s, int(time.time()), int(time.time())))
            db().commit()
    return redirect("/dash#invites")


@app.post("/dash/invite/<int:iid>/<act>")
@login_required
def invite_act(iid, act):
    i = db().execute("select * from invites where id=? and user_id=?", (iid, g.user["id"])).fetchone()
    if not i:
        abort(404)
    if act == "delete":
        db().execute("delete from clicks where invite_id=?", (iid,))
        db().execute("delete from invites where id=?", (iid,))
        db().commit()
    elif act == "check":
        refresh(i, True)
    elif act == "replace":
        code = parse_code(request.form.get("link"))
        if code:
            s, n, m, o = probe(code)
            db().execute("update invites set code=?, status=?, guild=?, members=?, online=?, checked=? where id=?", (code, "active" if s != "expired" else s, n, m, o, int(time.time()), iid))
            db().commit()
        else:
            flash("That doesn't look like a Discord invite.")
    return redirect("/dash#invites")


@app.post("/dash/password")
@login_required
def password():
    if not check_password_hash(g.user["pw"], request.form.get("old", "")):
        flash("Current password is wrong.")
    elif len(request.form.get("new", "")) < 8:
        flash("New password needs at least 8 characters.")
    else:
        db().execute("update users set pw=? where id=?", (generate_password_hash(request.form["new"]), g.user["id"]))
        db().commit()
        flash("Password changed.")
    return redirect("/dash#account")


@app.route("/usr/<name>")
def usr(name):
    u = db().execute("select * from users where username=?", (name,)).fetchone()
    if not u or u["banned"]:
        abort(404)
    seen = session.get("seen", [])
    if u["id"] not in seen and not (g.user and g.user["id"] == u["id"]) and not is_bot():
        db().execute("update users set views=views+1 where id=?", (u["id"],))
        db().execute("insert into views(user_id, ts, ref, dev) values(?,?,?,?)", (u["id"], int(time.time()), ref_host(), device()))
        db().commit()
        session["seen"] = (seen + [u["id"]])[-200:]
    s = db().execute("select * from socials where user_id=? order by id", (u["id"],)).fetchall()
    return render_template("profile.html", u=u, th=THEMES[u["theme"]], socials=s)


def o_ok(i):
    r = db().execute("select banned from users where id=?", (i["user_id"],)).fetchone()
    return bool(r) and not r["banned"]


@app.route("/u/<name>")
def uploaded(name):
    return send_from_directory(UP, name, max_age=604800)


@app.route("/go/<int:sid>")
def go(sid):
    s = db().execute("select * from socials where id=?", (sid,)).fetchone()
    if not s:
        abort(404)
    if not is_bot():
        db().execute("insert into sclicks(social_id, user_id, ts) values(?,?,?)", (sid, s["user_id"], int(time.time())))
        db().commit()
    return redirect(s["url"])


@app.route("/inv/<slug>")
def inv(slug):
    i = db().execute("select * from invites where slug=?", (slug,)).fetchone()
    if not i:
        abort(404)
    if not o_ok(i):
        abort(404)
    i = refresh(i)
    o = db().execute("select username, display, role, banned from users where id=?", (i["user_id"],)).fetchone()
    if i["status"] == "expired":
        return render_template("msg.html", title="This invite has expired", text="The server owner needs to share a fresh link.", i=i, o=o), 410
    if not is_bot():
        db().execute("insert into clicks(invite_id, ts, ref, dev) values(?,?,?,?)", (i["id"], int(time.time()), ref_host(), device()))
        db().execute("update invites set clicks=clicks+1 where id=?", (i["id"],))
        db().commit()
    return render_template("invite.html", i=i, o=o)


@app.route("/admin")
@staff_required
def admin():
    q = request.args.get("q", "").strip()
    rows = db().execute("select u.*, (select count(*) from invites where user_id=u.id) ic from users u where username like ? order by id", ("%" + q + "%",)).fetchall()
    inv = db().execute("select i.*, u.username from invites i join users u on u.id=i.user_id order by i.id desc limit 30").fetchall()
    tot = db().execute("select (select count(*) from users) u, (select count(*) from invites) i, (select coalesce(sum(clicks),0) from invites) c, (select count(*) from views) v").fetchone()
    return render_template("admin.html", rows=rows, inv=inv, tot=tot, q=q)


@app.post("/admin/<int:uid>/<act>")
@staff_required
def admin_act(uid, act):
    u = db().execute("select * from users where id=?", (uid,)).fetchone()
    top = g.user["role"] == "owner"
    if not u or u["role"] == "owner" or u["id"] == g.user["id"]:
        abort(400)
    if u["role"] == "staff" and not top:
        abort(403)
    if act == "ban":
        db().execute("update users set banned=1-banned where id=?", (uid,))
    elif act in ("promote", "demote", "reset", "delete") and not top:
        abort(403)
    elif act == "promote":
        db().execute("update users set role='staff' where id=?", (uid,))
    elif act == "demote":
        db().execute("update users set role='user' where id=?", (uid,))
    elif act == "reset":
        pw = secrets.token_urlsafe(9)
        db().execute("update users set pw=? where id=?", (generate_password_hash(pw), uid))
        flash("Temporary password for %s: %s" % (u["username"], pw))
    elif act == "delete":
        for k in EXT:
            unlink(u[k])
        db().execute("delete from clicks where invite_id in (select id from invites where user_id=?)", (uid,))
        for t in ("invites", "socials", "views", "sclicks"):
            db().execute("delete from %s where user_id=?" % t, (uid,))
        db().execute("delete from users where id=?", (uid,))
    else:
        abort(400)
    db().commit()
    return redirect("/admin")


@app.post("/admin/invite/<int:iid>/delete")
@staff_required
def admin_inv(iid):
    db().execute("delete from clicks where invite_id=?", (iid,))
    db().execute("delete from invites where id=?", (iid,))
    db().commit()
    return redirect("/admin")


@app.errorhandler(404)
def e404(e):
    return render_template("msg.html", title="Nothing here", text="That page or name doesn't exist (yet)."), 404


@app.errorhandler(403)
def e403(e):
    return render_template("msg.html", title="Not for you", text="You don't have access to this."), 403


@app.errorhandler(400)
def e400(e):
    return render_template("msg.html", title="That didn't go through", text="Go back, refresh the page and try once more."), 400


@app.errorhandler(413)
def e413(e):
    return render_template("msg.html", title="File too large", text="Uploads are capped at 60 MB in total."), 413


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
