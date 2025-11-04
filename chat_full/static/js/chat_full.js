const socket = io();

const loginDiv = document.getElementById('login');
const chatDiv = document.getElementById('chat');
const btnConnect = document.getElementById('btnConnect');
const btnAuth = document.getElementById('btnAuth');
const btnSignup = document.getElementById('btnSignup');
const btnDisconnect = document.getElementById('btnDisconnect');
const btnSend = document.getElementById('btnSend');
const inputMsg = document.getElementById('inputMsg');
const nickInput = document.getElementById('nick');
const passInput = document.getElementById('password');
const messagesDiv = document.getElementById('messages');
const usersList = document.getElementById('usersList');
const myNickSpan = document.getElementById('myNick');
const emojiBtn = document.getElementById('emojiBtn');

let myNick = null;

function appendMessage(text, cls='') {
  const p = document.createElement('div');
  p.className = 'msg ' + cls;
  p.textContent = text;
  messagesDiv.appendChild(p);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

btnSignup.onclick = async () => {
  const nick = nickInput.value.trim();
  const pw = passInput.value;
  if(!nick || !pw){ alert('nick e senha necessários para registrar'); return; }
  const res = await fetch('/signup', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({nick: nick, password: pw})});
  const data = await res.json();
  if(res.ok){ alert('registrado com sucesso'); } else { alert('erro: '+data.message); }
};

btnAuth.onclick = () => {
  const nick = nickInput.value.trim();
  const pw = passInput.value;
  if(!nick || !pw){ alert('nick e senha necessários para autenticar'); return; }
  socket.emit('chat_event', {type:'auth', nick: nick, password: pw});
  myNick = nick; myNickSpan.textContent = nick;
  loginDiv.classList.add('hidden'); chatDiv.classList.remove('hidden');
  socket.emit('chat_event', {type:'list'});
};

btnConnect.onclick = () => {
  const nick = nickInput.value.trim();
  if(!nick){ alert('Digite um nick'); return; }
  myNick = nick; myNickSpan.textContent = nick;
  socket.emit('chat_event', {type:'register', nick: nick});
  loginDiv.classList.add('hidden'); chatDiv.classList.remove('hidden');
  socket.emit('chat_event', {type:'list'});
};

btnDisconnect.onclick = () => { socket.disconnect(); location.reload(); };

btnSend.onclick = () => sendMessage();
inputMsg.addEventListener('keydown', (e) => { if(e.key==='Enter') sendMessage(); });

emojiBtn.onclick = () => {
  const emoji = '😄';
  inputMsg.value = (inputMsg.value + ' ' + emoji).trim();
  inputMsg.focus();
};

function sendMessage(){
  const txt = inputMsg.value.trim();
  if(!txt) return;
  if(txt.startsWith('/msg ')){
    const parts = txt.split(' '); const to = parts[1]; const msg = parts.slice(2).join(' ');
    socket.emit('chat_event', {type:'private', to: to, message: msg});
    appendMessage(`[privado para ${to}] ${msg}`, 'private');
  } else if(txt === '/list'){
    socket.emit('chat_event', {type:'list'});
  } else {
    socket.emit('chat_event', {type:'message', message: txt});
  }
  inputMsg.value='';
}

socket.on('server_event', (obj) => {
  const t = obj.type;
  if(t==='system'){ appendMessage(`(sistema) ${obj.message}`, 'system'); }
  else if(t==='message'){ const dt=new Date(obj.timestamp*1000); appendMessage(`[${dt.toLocaleTimeString()}] ${obj.from}: ${obj.message}`, 'message'); }
  else if(t==='private'){ const dt=new Date(obj.timestamp*1000); appendMessage(`[${dt.toLocaleTimeString()}] 🔒 ${obj.from} → ${obj.to}: ${obj.message}`, 'private'); }
  else if(t==='list'){ usersList.innerHTML=''; (obj.users||[]).forEach(u=>{ const li=document.createElement('li'); li.textContent=u; usersList.appendChild(li); }); }
  else if(t==='error'){ appendMessage(`(erro) ${obj.message}`, 'error'); }
  else { appendMessage(JSON.stringify(obj), 'debug'); }
});
