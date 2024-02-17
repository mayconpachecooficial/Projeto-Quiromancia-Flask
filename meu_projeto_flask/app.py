from flask import Flask, render_template, request, redirect, url_for, session, jsonify
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

# Rota para a página de cadastro
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    error_message = None

    if request.method == 'POST':
        nome = request.form['name']
        email = request.form['email']
        telefone = request.form['phone']
        senha = request.form['password']
        confirmar_senha = request.form['confirm_password']

        # Verifica se as senhas correspondem
        if senha != confirmar_senha:
            error_message = "As senhas não correspondem. Por favor, tente novamente."
        else:
            # Criptografa a senha
            hashed_password = hashlib.sha256(senha.encode()).hexdigest()

            # Verifica se o e-mail já está cadastrado
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                error_message = "O e-mail já está cadastrado. Por favor, use outro e-mail."
            else:
                # Conectar ao banco de dados e inserir os dados do usuário
                cursor.execute('INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
                               (nome, email, telefone, hashed_password))
                conn.commit()
                conn.close()

                # Redirecionar para a página de login após o cadastro
                return redirect(url_for('login'))

    return render_template('cadastro.html', error_message=error_message)

# Rota para a página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None

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

# Rota para verificar se o e-mail já está cadastrado
@app.route('/verificar_email', methods=['POST'])
def verificar_email():
    email = request.json['email']

    # Verificar se o e-mail já está cadastrado
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    existing_user = cursor.fetchone()
    conn.close()

    if existing_user:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})

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

# Rota para a página inicial (exemplo)
@app.route('/')
@app.route('/home')
def index():
    return render_template('home.html')

# Função para formatar o número de telefone enquanto o usuário digita
@app.template_filter('format_phone')
def format_phone(s):
    s = ''.join(filter(str.isdigit, s))
    return '({}) {}-{}'.format(s[:2], s[2:7], s[7:])

# Restante do código...

if __name__ == '__main__':
    create_users_table()  # Garante que a tabela de usuários exista antes de iniciar o aplicativo
    app.run(debug=True)
