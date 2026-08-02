from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import cgi, hashlib, json, secrets, sqlite3, time, uuid

ROOT = Path(__file__).resolve().parent
DB = ROOT / "chat.db"
UPLOADS = ROOT / "uploads"
PORT = 4200

def conn():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

def setup():
    UPLOADS.mkdir(exist_ok=True)
    with conn() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, password TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, body TEXT NOT NULL, attachment_path TEXT NOT NULL DEFAULT '', attachment_name TEXT NOT NULL DEFAULT '', attachment_type TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
        """)
        columns = [row[1] for row in db.execute("PRAGMA table_info(messages)")]
        for name in ("attachment_path", "attachment_name", "attachment_type"):
            if name not in columns: db.execute(f"ALTER TABLE messages ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")

def digest(value, salt=None):
    salt = salt or secrets.token_bytes(16)
    raw = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 310000)
    return f"{salt.hex()}:{raw.hex()}"

def matches(value, saved):
    salt, expected = saved.split(":", 1)
    return secrets.compare_digest(digest(value, bytes.fromhex(salt)).split(":", 1)[1], expected)

class App(SimpleHTTPRequestHandler):
    def json(self, data, status=200, cookie=None):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body)))
        if cookie: self.send_header("Set-Cookie", cookie)
        self.end_headers(); self.wfile.write(body)

    def data(self): return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))

    def user(self):
        token = next((part.split("=",1)[1] for part in self.headers.get("Cookie","").split("; ") if part.startswith("ccs_chat=")), None)
        if not token: return None
        with conn() as db:
            return db.execute("SELECT users.id,users.name,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires_at>?", (token, int(time.time()))).fetchone()

    def require(self):
        user = self.user()
        if not user: self.json({"error":"Connexion requise."}, 401)
        return user

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/me": self.json(dict(self.user()) if self.user() else None)
        elif path == "/api/messages":
            if self.require():
                with conn() as db:
                    rows = db.execute("SELECT messages.id,messages.body,messages.attachment_path,messages.attachment_name,messages.attachment_type,messages.created_at,users.name,users.role,users.id user_id FROM messages JOIN users ON users.id=messages.user_id ORDER BY messages.id DESC LIMIT 200").fetchall()
                self.json(list(reversed([dict(row) for row in rows])))
        else: super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/enter":
                data=self.data(); name=data.get("name","").strip(); role=data.get("role","technicien")
                if len(name)<2 or role not in ("technicien","ccs"): raise ValueError("Indiquez votre prénom et votre rôle.")
                with conn() as db:
                    cur=db.execute("INSERT INTO users(name,role,password,created_at) VALUES(?,?,?,?)",(name,role,digest(secrets.token_urlsafe(24)),int(time.time()))); user_id=cur.lastrowid
                    token=secrets.token_urlsafe(32); db.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)",(token,user_id,int(time.time())+43200)); user=db.execute("SELECT id,name,role FROM users WHERE id=?",(user_id,)).fetchone()
                self.json(dict(user),cookie=f"ccs_chat={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200")
            elif path in ("/api/register", "/api/login"):
                data=self.data(); name=data.get("name","").strip(); password=data.get("password",""); role=data.get("role","technicien")
                if len(password)<8 or (path.endswith("register") and (len(name)<2 or role not in ("technicien","ccs"))): raise ValueError("Complétez les informations demandées. Le mot de passe doit avoir 8 caractères.")
                with conn() as db:
                    if path.endswith("register"):
                        cur=db.execute("INSERT INTO users(name,role,password,created_at) VALUES(?,?,?,?)",(name,role,digest(password),int(time.time()))); user_id=cur.lastrowid
                    else:
                        found=db.execute("SELECT id,password FROM users WHERE name=?",(name,)).fetchone()
                        if not found or not matches(password,found["password"]): raise ValueError("Identifiant ou mot de passe incorrect.")
                        user_id=found["id"]
                    token=secrets.token_urlsafe(32); db.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)",(token,user_id,int(time.time())+2592000)); user=db.execute("SELECT id,name,role FROM users WHERE id=?",(user_id,)).fetchone()
                self.json(dict(user),cookie=f"ccs_chat={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000")
            elif path == "/api/logout": self.json({"ok":True},cookie="ccs_chat=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            elif path == "/api/messages":
                user=self.require()
                if user:
                    data=self.data(); body=data.get("body","").strip(); attachment=data.get("attachment") or {}
                    if len(body)>2000 or (not body and not attachment.get("path")): raise ValueError("Ajoutez un message ou un fichier (message limité à 2 000 caractères).")
                    with conn() as db: db.execute("INSERT INTO messages(user_id,body,attachment_path,attachment_name,attachment_type,created_at) VALUES(?,?,?,?,?,?)",(user["id"],body,attachment.get("path",""),attachment.get("name",""),attachment.get("type",""),int(time.time())))
                    self.json({"ok":True},201)
            elif path == "/api/upload":
                user=self.require()
                if user:
                    form=cgi.FieldStorage(fp=self.rfile,headers=self.headers,environ={"REQUEST_METHOD":"POST","CONTENT_TYPE":self.headers.get("Content-Type","")})
                    item=form["file"]; content=item.file.read(10*1024*1024+1)
                    if len(content)>10*1024*1024: raise ValueError("Le fichier ne doit pas dépasser 10 Mo.")
                    name=Path(item.filename or "fichier").name
                    stored=f"{uuid.uuid4().hex}_{name}"; (UPLOADS/stored).write_bytes(content)
                    self.json({"path":f"/uploads/{stored}","name":name,"type":item.type or "application/octet-stream"},201)
            else: self.send_error(404)
        except sqlite3.IntegrityError: self.json({"error":"Cet identifiant est déjà utilisé."},400)
        except Exception as error: self.json({"error":str(error)},400)

if __name__ == "__main__":
    setup(); print(f"Chat local : http://127.0.0.1:{PORT}"); ThreadingHTTPServer(("0.0.0.0",PORT),App).serve_forever()
