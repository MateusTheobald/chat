#!/usr/bin/env python3
import time, sqlite3, hashlib, json
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

# --- Config ---
DB_FILE = "auth.db"
OFFENSIVE_WORDS = {"palavrão1", "palavrão2", "burro", "idiota"}

# --- Flask App ---
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "replace-with-secure-key"
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Database setup ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nick TEXT UNIQUE,
            password_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def verify_user(nick, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE nick=?", (nick,))
    row = c.fetchone()
    conn.close()
    return row and row[0] == hash_password(password)

def create_user(nick, password):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (nick, password_hash) VALUES (?, ?)", (nick, hash_password(password)))
        conn.commit()
        conn.close()
        return True, "Usuário criado"
    except Exception as e:
        return False, str(e)

# --- Flask routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json or {}
    nick, pw = data.get("nick","").strip(), data.get("password","")
    if not nick or not pw:
        return jsonify(success=False, message="nick e password obrigatórios"), 400
    ok, msg = create_user(nick, pw)
    return jsonify(success=ok, message=msg), (200 if ok else 400)

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    nick, pw = data.get("nick","").strip(), data.get("password","")
    if verify_user(nick, pw):
        return jsonify(success=True, message="autenticado")
    return jsonify(success=False, message="credenciais inválidas"), 401

# --- Socket.IO ---
web_users = {}  # sid -> nick

@socketio.on("connect")
def on_connect():
    print("Novo cliente conectado")

@socketio.on("chat_event")
def handle_chat(data):
    sid = request.sid
    t = data.get("type")

    if t == "register":
        nick = data.get("nick","").strip()
        if not nick:
            emit("server_event", {"type":"error","message":"nick obrigatório"}, room=sid)
            return
        web_users[sid] = nick
        socketio.emit("server_event", {"type":"system","message":f"{nick} entrou no chat."})
        return

    if t == "message":
        nick = web_users.get(sid)
        if not nick:
            emit("server_event", {"type":"error","message":"autentique-se primeiro"}, room=sid)
            return
        text = data.get("message","")
        payload = {"type":"message","from":nick,"message":text,"timestamp":time.time()}
        socketio.emit("server_event", payload)
        return

@socketio.on("disconnect")
def on_disconnect():
    nick = web_users.pop(request.sid, None)
    if nick:
        socketio.emit("server_event", {"type":"system","message":f"{nick} saiu do chat."})

# --- Run ---
if __name__ == "__main__":
    init_db()
    import os
    port = int(os.getenv("PORT", 5000))  # Render define PORT automaticamente
    socketio.run(app, host="0.0.0.0", port=port)
