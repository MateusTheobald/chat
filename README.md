Chat Full (Web + TCP) - Combined Server

Funcionalidades adicionadas:
- Autenticação (signup/login) com SQLite (arquivo auth.db)
- Web UI (responsive, emoji button)
- TCP JSON server compatível com clientes antigos (porta TCP 6000)
- Mensagens persistidas em messages.log
- Mensagens privadas entre web and tcp clients
- Lista de usuários combinada (web + tcp)

Como rodar:
1. Descompacte o projeto.
2. (recomendado) crie venv:
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate   # Windows cmd
3. Instale dependências:
   pip install -r requirements.txt
4. Execute o servidor combinado:
   python server_combined.py
5. Abra no navegador (PC): http://127.0.0.1:5000
   No celular (mesma rede): http://SEU_IP_LOCAL:5000

Uso TCP (clientes legados):
- Conectar TCP ao porto 6000 e enviar JSON newline-delimited.
- Tipos: register, auth, message, private, list (igual ao protocolo anterior).

Observações:
- Senhas são armazenadas como SHA-256 no banco SQLite.
- O banco (auth.db) será criado automaticamente.
