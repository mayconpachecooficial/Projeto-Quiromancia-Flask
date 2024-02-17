from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # Chave secreta para sessão

# Função para conectar ao banco de dados
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Função para criar a tabela 'users' no banco de dados
def create_users_table():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

# Rota para a página inicial
@app.route('/')
def index():
    return render_template('index.html')

# Rota para a página de cadastro
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['name']
        email = request.form['email']
        telefone = request.form['phone']
        senha = request.form['password']
        confirmar_senha = request.form['confirm_password']

        # Verifica se as senhas correspondem
        if senha != confirmar_senha:
            return "As senhas não correspondem. Por favor, tente novamente."

        # Criptografa a senha
        hashed_password = hashlib.sha256(senha.encode()).hexdigest()

        # Conectar ao banco de dados e inserir os dados do usuário
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
                       (nome, email, telefone, hashed_password))
        conn.commit()
        conn.close()

        # Redirecionar para a página de login após o cadastro
        return redirect(url_for('login'))

    # Caso o método seja GET, renderiza o template de cadastro
    return render_template('cadastro.html')

# Rota para a página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Lógica para autenticar o usuário
        if autenticacao_bem_sucedida(username, password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error_message = 'Usuário ou senha incorretos. Por favor, tente novamente.'
            return render_template('login.html', error_message=error_message)

    return render_template('login.html')

# Rota para a página de logout
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

# Função para autenticar o usuário (substitua isso com sua própria lógica de autenticação)
def autenticacao_bem_sucedida(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if user['password'] == hashed_password:
            return True
    return False

if __name__ == '__main__':
    create_users_table()  # Garante que a tabela de usuários exista antes de iniciar o aplicativo
    app.run(debug=True)
