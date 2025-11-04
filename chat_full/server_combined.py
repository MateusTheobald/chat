#!/usr/bin/env python3
"""Combined Chat Server:
- Web interface (Flask + Flask-SocketIO) with authentication (SQLite)
- TCP JSON newline-delimited server compatible with original server.py protocol
- Broadcasts messages between web and TCP clients
"""
import socket, threading, json, time, sqlite3, hashlib, os
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from typing import Dict, Tuple

# --- Config ---
HOST = "0.0.0.0"
TCP_PORT = 6000      # TCP server port for raw clients
WEB_PORT = 5000      # Flask port for web clients
MSG_LOG_FILE = "messages.log"
DB_FILE = "auth.db"
OFFENSIVE_WORDS = {"palavrão1", "palavrão2", "burro", "idiota"}

# --- Shared state ---
tcp_clients_lock = threading.Lock()
tcp_clients: Dict[socket.socket, dict] = {}  # sock -> {'nick':..., 'addr':(...)}

web_users_lock = threading.Lock()
web_nick_to_sid: Dict[str, str] = {}  # nick -> socketio sid
sid_to_nick: Dict[str, str] = {}      # sid -> nick

# --- Flask app and SocketIO ---
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'replace-with-secure-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Database helpers ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nick TEXT UNIQUE,
        password_hash TEXT
    )''')
    conn.commit()
    conn.close()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def create_user(nick: str, password: str):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (nick, password_hash) VALUES (?, ?)", (nick, hash_password(password)))
        conn.commit()
        conn.close()
        return True, "Usuário criado"
    except Exception as e:
        return False, str(e)

def verify_user(nick: str, password: str) -> bool:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE nick = ?", (nick,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    return row[0] == hash_password(password)

# --- Message utilities ---
def sanitize_text(text: str):
    words = text.split()
    had = False
    for i,w in enumerate(words):
        lw = w.lower().strip(".,!?;:")
        if lw in OFFENSIVE_WORDS:
            words[i] = "***"
            had = True
    return " ".join(words), had

def persist_message(payload: dict):
    try:
        with open(MSG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as e:
        print("Erro gravando log:", e)

# --- Broadcast to all clients (web + tcp) ---
def broadcast(payload: dict):
    # send to web clients via socketio
    try:
        socketio.emit('server_event', payload)
    except Exception as e:
        print("Erro broadcasting to web:", e)
    # send to tcp clients
    text = json.dumps(payload, ensure_ascii=False) + "\n"
    with tcp_clients_lock:
        dead = []
        for s, info in list(tcp_clients.items()):
            try:
                s.sendall(text.encode())
            except Exception as e:
                print("Erro enviando para TCP client:", e)
                dead.append(s)
        for s in dead:
            remove_tcp_client(s)

# --- TCP server (legacy clients) ---
def remove_tcp_client(sock: socket.socket):
    with tcp_clients_lock:
        info = tcp_clients.pop(sock, None)
    if info and info.get('nick'):
        broadcast({'type':'system','message':f"{info['nick']} saiu do chat.", 'timestamp': time.time()})
    try:
        sock.close()
    except: pass

def handle_tcp_client(sock: socket.socket, addr: Tuple[str,int]):
    print("TCP conexão de", addr)
    with tcp_clients_lock:
        tcp_clients[sock] = {'nick': None, 'addr': addr}
    buffer = ""
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            buffer += data.decode(errors='ignore')
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip(): continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    sock.sendall((json.dumps({'type':'error','message':'JSON inválido'}) + "\n").encode())
                    continue
                t = obj.get('type')
                if t == 'register':
                    nick = obj.get('nick','').strip()
                    if not nick:
                        sock.sendall((json.dumps({'type':'error','message':'Nick obrigatório'}) + "\n").encode())
                        continue
                    tcp_clients[sock]['nick'] = nick
                    sock.sendall((json.dumps({'type':'system','message':f'Bem-vindo, {nick}!'}) + "\n").encode())
                    broadcast({'type':'system','message':f"{nick} entrou no chat.", 'timestamp': time.time()})
                    continue
                if t == 'auth':
                    nick = obj.get('nick','').strip()
                    pw = obj.get('password','')
                    if verify_user(nick, pw):
                        tcp_clients[sock]['nick'] = nick
                        sock.sendall((json.dumps({'type':'system','message':f'Authenticado como {nick}'}) + "\n").encode())
                        broadcast({'type':'system','message':f"{nick} entrou no chat.", 'timestamp': time.time()})
                    else:
                        sock.sendall((json.dumps({'type':'error','message':'Credenciais inválidas'}) + "\n").encode())
                    continue
                if t == 'message':
                    nick = tcp_clients[sock].get('nick')
                    if not nick:
                        sock.sendall((json.dumps({'type':'error','message':'Registre-se primeiro'}) + "\n").encode())
                        continue
                    text = obj.get('message','')
                    sanitized, had = sanitize_text(text)
                    payload = {'type':'message','from':nick,'message':sanitized,'original_had_offensive':had,'timestamp': time.time()}
                    persist_message(payload)
                    broadcast(payload)
                    continue
                if t == 'private':
                    nick = tcp_clients[sock].get('nick')
                    if not nick:
                        sock.sendall((json.dumps({'type':'error','message':'Registre-se primeiro'}) + "\n").encode())
                        continue
                    to = obj.get('to')
                    text = obj.get('message','')
                    sanitized, had = sanitize_text(text)
                    payload = {'type':'private','from':nick,'to':to,'message':sanitized,'original_had_offensive':had,'timestamp': time.time()}
                    # send to web if exists
                    with web_users_lock:
                        sid = web_nick_to_sid.get(to)
                    if sid:
                        socketio.emit('server_event', payload, room=sid)
                        sock.sendall((json.dumps({'type':'system','message':f'Mensagem privada enviada para {to}.'}) + "\n").encode())
                        persist_message(payload)
                    else:
                        # try to find TCP recipient
                        sent = False
                        with tcp_clients_lock:
                            for s, info in tcp_clients.items():
                                if info.get('nick') == to:
                                    try:
                                        s.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode())
                                        sent = True
                                    except: pass
                        if sent:
                            sock.sendall((json.dumps({'type':'system','message':f'Mensagem privada enviada para {to}.'}) + "\n").encode())
                            persist_message(payload)
                        else:
                            sock.sendall((json.dumps({'type':'error','message':f'Usuário {to} não encontrado.'}) + "\n").encode())
                    continue
                if t == 'list':
                    with tcp_clients_lock:
                        nicks = [info.get('nick') for info in tcp_clients.values() if info.get('nick')]
                    sock.sendall((json.dumps({'type':'list','users':nicks}) + "\n").encode())
                    continue
                sock.sendall((json.dumps({'type':'error','message':'Tipo desconhecido'}) + "\n").encode())
    except Exception as e:
        print("Exceção TCP handler:", e)
    finally:
        remove_tcp_client(sock)
        print("TCP conexão encerrada", addr)

def start_tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, TCP_PORT))
    s.listen(100)
    print("TCP server rodando em", HOST, TCP_PORT)
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()
    except Exception as e:
        print("TCP server encerrado:", e)
    finally:
        s.close()

# --- Flask routes (signup/login pages) ---
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'replace-with-secure-key'
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json or {}
    nick = data.get('nick','').strip()
    pw = data.get('password','')
    if not nick or not pw:
        return jsonify({'success':False,'message':'nick e password obrigatórios'}), 400
    ok, msg = create_user(nick, pw)
    if ok:
        return jsonify({'success':True,'message':msg})
    return jsonify({'success':False,'message':msg}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    nick = data.get('nick','').strip()
    pw = data.get('password','')
    if verify_user(nick, pw):
        return jsonify({'success':True,'message':'autenticado'})
    return jsonify({'success':False,'message':'credenciais inválidas'}), 401

# --- SocketIO events for web clients ---
@socketio.on('chat_event')
def on_chat_event(data):
    sid = request.sid
    t = data.get('type')
    if t == 'register':
        nick = data.get('nick','').strip()
        if not nick:
            emit('server_event', {'type':'error','message':'nick obrigatório'}, room=sid)
            return
        with web_users_lock:
            web_nick_to_sid[nick] = sid
            sid_to_nick[sid] = nick
        emit('server_event', {'type':'system','message':f'Bem-vindo, {nick}!'}, room=sid)
        socketio.emit('server_event', {'type':'system','message':f'{nick} entrou no chat.'})
        return
    if t == 'auth':
        nick = data.get('nick','').strip()
        pw = data.get('password','')
        if verify_user(nick, pw):
            with web_users_lock:
                web_nick_to_sid[nick] = sid
                sid_to_nick[sid] = nick
            emit('server_event', {'type':'system','message':f'Autenticado como {nick}.'}, room=sid)
            socketio.emit('server_event', {'type':'system','message':f'{nick} entrou no chat.'})
        else:
            emit('server_event', {'type':'error','message':'credenciais inválidas'}, room=sid)
        return
    if t == 'message':
        nick = sid_to_nick.get(sid)
        if not nick:
            emit('server_event', {'type':'error','message':'autentique-se primeiro'}, room=sid); return
        text = data.get('message','')
        sanitized, had = sanitize_text(text)
        payload = {'type':'message','from':nick,'message':sanitized,'original_had_offensive':had,'timestamp': time.time()}
        persist_message(payload); broadcast(payload); return
    if t == 'private':
        nick = sid_to_nick.get(sid)
        if not nick:
            emit('server_event', {'type':'error','message':'autentique-se primeiro'}, room=sid); return
        to = data.get('to')
        text = data.get('message','')
        sanitized, had = sanitize_text(text)
        payload = {'type':'private','from':nick,'to':to,'message':sanitized,'original_had_offensive':had,'timestamp': time.time()}
        # send to web if exists
        with web_users_lock:
            to_sid = web_nick_to_sid.get(to)
        if to_sid:
            emit('server_event', payload, room=to_sid)
            emit('server_event', {'type':'system','message':f'Mensagem privada enviada para {to}.'}, room=sid)
            persist_message(payload)
        else:
            # try tcp clients
            sent = False
            with tcp_clients_lock:
                for s, info in tcp_clients.items():
                    if info.get('nick') == to:
                        try:
                            s.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode()); sent = True
                        except: pass
            if sent:
                emit('server_event', {'type':'system','message':f'Mensagem privada enviada para {to}.'}, room=sid)
                persist_message(payload)
            else:
                emit('server_event', {'type':'error','message':f'Usuário {to} não encontrado.'}, room=sid)
        return
    if t == 'list':
        with web_users_lock, tcp_clients_lock:
            nicks = list(web_nick_to_sid.keys()) + [info.get('nick') for info in tcp_clients.values() if info.get('nick')]
        emit('server_event', {'type':'list','users':nicks}, room=sid); return
    emit('server_event', {'type':'error','message':'tipo desconhecido'}, room=sid)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    nick = sid_to_nick.pop(sid, None)
    if nick:
        with web_users_lock:
            web_nick_to_sid.pop(nick, None)
        socketio.emit('server_event', {'type':'system','message':f'{nick} saiu do chat.'})

# --- main ---
if __name__ == '__main__':
    init_db()
    threading.Thread(target=start_tcp_server, daemon=True).start()
    print(f"Servidor combinado rodando: WEB port={WEB_PORT}, TCP port={TCP_PORT}")
    socketio.run(app, host=HOST, port=WEB_PORT)
